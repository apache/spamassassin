# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Handler::Archive - A MIME-part handler for archive files

=head1 SYNOPSIS

  loadhandler  Mail::SpamAssassin::Handler::Archive

=head1 DESCRIPTION

A MIME-part handler that opens C<zip> and C<rar> archive attachments, extracts a
bounded number of the files inside, and returns each as a child part.  The
handler framework then re-dispatches every extracted file by its
C<effective_type> (filename extension first), so an C<inner.js> reaches the
script handler, an C<inner.html> reaches the HTML handler, an C<inner.pdf>
the PDF handler, an image the image handler, and a nested archive comes back to
this handler -- all bounded by the framework's depth, part-count and byte
budgets.

The handler is intentionally thin: its main job is to make the archive's contents
visible to the other handlers and to ordinary body rules.  It also provides one
eval rule, C<check_archive_file_count>, for matching on the number of files an
archive holds (see L</EVAL RULES>).

=head1 REQUIREMENTS

=over 2

=item zip

Extraction uses L<Archive::Zip> 1.34 or later.  If it is not installed, the
handler still loads (with a warning at startup) and skips zip archives.

=item rar

Extraction shells out to the C<unrar> executable: RARLAB's, or unrar-free 0.2.0
or later.  Set C<archive_unrar_path> if it is not on the C<PATH>.  If it cannot
be found, rar extraction is disabled with a debug message, so C<--lint> never
fails merely because the binary is absent.  Any other unrar disables rar
extraction with a warning.

=back

=head1 CONFIGURATION

=over 4

=item archive_max_files N    (default: 2)

Extract at most N files from each archive.  Bounds the work done downstream and
is a countermeasure against archives that pack a very large number of entries.
A zip archive with more than 10,000 zip headers is not opened.  An archive has
two or three headers for each of its files.  The message then gets the
C<ZIP_ENTRY_LIMIT_EXCEEDED> rule.

=item archive_unrar_path /path/to/unrar

Full path to the C<unrar> executable.  If unset, the handler looks for C<unrar>
on the C<PATH>.

=back

=head1 EVAL RULES

=over 4

=item check_archive_file_count(min[, max])

Fires when any archive in the message has an entry count of at least C<min>
(and, if C<max> is given and non-zero, at most C<max>).  The count is of the
entries read from a zip archive's directory, or from C<unrar>'s member listing.
The number that a zip archive declares is not used, since it need not be true.
The count is independent of C<archive_max_files>: an archive that packs
thousands of files but from which only four are extracted still reports its
true size.  A zip archive that is not opened because it has too many headers
counts as having more than 10,000 entries.  Useful for flagging archives that
pack an implausible number of entries.

  body  ARC_MANY_FILES   eval:check_archive_file_count(100)
  body  ARC_FILES_RANGE  eval:check_archive_file_count(2,10)

=back

=cut

package Mail::SpamAssassin::Handler::Archive;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Constants qw(MAX_ZIP_HEADERS);
use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg would_log);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str
                                am_running_on_windows);
use Mail::SpamAssassin::Util::Zip;

our @ISA = qw(Mail::SpamAssassin::Handler);

# Default for archive_max_files; single source of truth for the registered
# default and the per-call-site fallback below.
use constant DEFAULT_MAX_FILES => 2;

# a rar member name with these characters (see
# Mail::SpamAssassin::Util::helper_app_pipe_open), or starting with @, which
# unrar reads as a list file, is not passed to unrar
use constant UNSAFE_MEMBER_NAME =>
  am_running_on_windows() ? qr/^\@|["&|<>^%!\x00-\x1f]/ : qr/^\@|"/;

sub log_dbg  { Mail::SpamAssassin::Logger::dbg ("archive: @_"); }
sub log_warn { Mail::SpamAssassin::Logger::log_message('warn', "archive: @_"); }

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # Register as the handler for zip and rar parts.  The modern IANA rar type is
  # application/vnd.rar; the legacy application/x-rar-compressed is aliased to it
  # by Message::Node::effective_type.  Mislabelled application/octet-stream parts
  # named *.zip / *.rar also dispatch here via the filename->type map.
  $self->register_handler('application/zip',     'handle_zip');
  $self->register_handler('application/vnd.rar', 'handle_rar');

  # check_archive_file_count(min[,max]) fires when any archive in the message
  # has an entry count in [min,max].  The count is of the entries read
  # (directory for zip, member list for rar), independent of how
  # many files archive_max_files actually extracts -- so it sees the true size of
  # an archive that packs far more entries than we open.
  $self->register_eval_rule('check_archive_file_count',
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # Warn once at startup if the zip backend is unavailable, so zip archives are
  # knowingly skipped rather than silently ignored.
  if (!Mail::SpamAssassin::Util::Zip::HAS_ARCHIVE_ZIP) {
    log_warn("zip archives not supported, required module Archive::Zip 1.34 or later not available");
  }
  # unrar is resolved lazily in handle_rar (like pdftotext in Handler::PDF).

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, (
    {
      # Extract at most this many files from each archive (bounds downstream work
      # and resists archives that pack a huge number of entries).
      setting => 'archive_max_files',
      is_admin => 1,
      default => DEFAULT_MAX_FILES,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # Full path to the unrar executable.  If unset, the handler looks for unrar
      # on the PATH.  If it cannot be found, rar extraction is disabled.
      setting => 'archive_unrar_path',
      is_admin => 1,
      default => '',
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    },
  ));

  $conf->{parser}->register_commands(\@cmds);
}

# basename of an archive member path, used as the synthetic part's filename so
# the framework's effective_type() can route it by extension.  Strips any
# directory components (forward or back slashes) and leading drive/dots.
sub _basename {
  my ($name) = @_;
  $name = '' unless defined $name;
  $name =~ s{\\}{/}g;        # normalise Windows separators
  $name =~ s{.*/}{}s;        # drop directory components
  return $name;
}

# Record an archive's entry count for check_archive_file_count.  One
# entry per archive part in the message (a message may carry several).
sub _record_file_count {
  my ($self, $pms, $count) = @_;
  return unless defined $count;
  push @{ $pms->{Handler}{Archive}{file_counts} }, $count;
  log_dbg("archive has $count entries");
}

# handle_zip($node, $pms): extract up to archive_max_files files from a zip
# attachment and return each as an application/octet-stream child part named with
# the member's basename.  The framework re-dispatches each by effective_type.
# Members are listed from the central directory and uncompressed within the
# message's byte budget; the framework already wraps this call in a timeout, so
# no timeout is set here.
sub handle_zip {
  my ($self, $node, $pms) = @_;
  return [] unless Mail::SpamAssassin::Util::Zip::HAS_ARCHIVE_ZIP;

  my $data = $node->decode();
  return [] unless defined $data && length $data;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $max  = $conf->{archive_max_files} // DEFAULT_MAX_FILES;

  if (Mail::SpamAssassin::Util::Zip::header_count(\$data, MAX_ZIP_HEADERS + 1)
        > MAX_ZIP_HEADERS) {
    log_dbg("zip has more than ".MAX_ZIP_HEADERS." headers, not opened");
    $pms->{msg}->{zip_entry_limit_exceeded} = 1;
    $self->_record_file_count($pms, MAX_ZIP_HEADERS + 1);
    return [];
  }

  my $zip = Mail::SpamAssassin::Util::Zip::open_zip(\$data, MAX_ZIP_HEADERS);
  if (!$zip) {
    log_dbg("failed to open zip");
    return [];
  }

  # Record the number of entries that were read, whatever number the archive
  # declares, so check_archive_file_count sees the true total even though we
  # only open the first archive_max_files members below.
  my @members = $zip->members();
  $self->_record_file_count($pms, scalar @members);

  my @parts;
  my $pending = 0;    # size of @parts, counted by the framework on return
  foreach my $member (@members) {
    last if @parts >= $max;

    # Skip directory entries (the framework would just see an empty part).
    next if $member->isDirectory();
    my $name = _basename($member->fileName());
    next if $name eq '';

    my $limit = $self->bytes_left($pms) - $pending;
    if ($limit <= 0) {
      log_dbg("byte budget used up, not extracting zip member $name");
      last;
    }
    my ($content, $produced) =
      Mail::SpamAssassin::Util::Zip::member_contents($member, $limit);
    if (!defined $content) {
      $self->spend_bytes($pms, $produced);
      log_dbg("zip member $name skipped: encrypted, unreadable or over budget");
    } elsif (length $content) {
      log_dbg("extracted zip member: $name (".length($content)." bytes)");
      push @parts, {
        type => 'application/octet-stream',
        data => $content,
        name => $name,
      };
      $pending += length $content;
    }
  }

  return \@parts;
}

# handle_rar($node, $pms): extract up to archive_max_files files from a rar
# attachment by shelling out to unrar, and return each as an
# application/octet-stream child part.  Mirrors how Handler::PDF runs pdftotext:
# the decoded archive is written to a temp file, unrar is run under a Timeout, and
# helper-run-mode is entered/left around the external calls.  Degrades to a no-op
# when unrar is unavailable.
sub handle_rar {
  my ($self, $node, $pms) = @_;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $bin  = $self->_unrar($conf);
  return [] unless defined $bin;

  my $data = $node->decode();
  return [] unless defined $data && length $data;
  return [] unless $self->_unrar_kind($pms, $bin);

  my $max = $conf->{archive_max_files} // DEFAULT_MAX_FILES;

  # Write the archive to a temp file once; unrar needs a seekable file.
  my ($arc_file, $arc_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
  if (!$arc_file) {
    log_dbg("failed to create a temporary file for rar");
    return [];
  }
  binmode $arc_fh;
  print $arc_fh $data;
  close($arc_fh);
  $arc_file = untaint_file_path($arc_file);

  my ($count, @members) = $self->_unrar_list($pms, $bin, $arc_file);

  # Record the full declared entry count before capping at archive_max_files, so
  # check_archive_file_count sees the true total of the archive.
  $self->_record_file_count($pms, $count);

  my @unsafe = grep { $_ =~ UNSAFE_MEMBER_NAME } @members;
  log_dbg("rar members skipped, unsafe for the command line: @unsafe") if @unsafe;
  @members = grep { $_ !~ UNSAFE_MEMBER_NAME } @members;
  # one unrar p prints every member with a name, matched regardless of case
  # on Windows, so ask for each name once
  my %seen;
  @members = grep { !$seen{am_running_on_windows() ? lc($_) : $_}++ } @members;
  splice(@members, $max) if @members > $max;

  my @parts;
  my $pending = 0;    # size of @parts, counted by the framework on return
  for my $member (@members) {
    my $name = _basename($member);
    next if $name eq '';
    my $limit = $self->bytes_left($pms) - $pending;
    if ($limit <= 0) {
      log_dbg("byte budget used up, not extracting rar member $name");
      last;
    }
    my ($bytes, $produced) =
      $self->_unrar_extract($pms, $bin, $arc_file, $member, $limit);
    if (!defined $bytes) {
      $self->spend_bytes($pms, $produced);
      log_dbg("rar member $name skipped: unreadable or over budget");
      next;
    }
    next unless length $bytes;
    log_dbg("extracted rar member: $name (".length($bytes)." bytes)");
    push @parts, {
      type => 'application/octet-stream',
      data => $bytes,
      name => $name,
    };
    $pending += length $bytes;
  }

  unlink($arc_file) if defined $arc_file;
  return \@parts;
}

# Resolve the unrar binary lazily, on first use, and cache the result.  Deferred
# out of new() because the handler is constructed during config parsing, possibly
# before archive_unrar_path has been seen.  Returns the path, or undef (rar
# extraction then no-ops) if unavailable.
sub _unrar {
  my ($self, $conf) = @_;
  return $self->{unrar} if exists $self->{unrar};
  my $path = $conf->{archive_unrar_path};
  if (!defined $path || $path eq '') {
    $path = Mail::SpamAssassin::Util::find_executable_in_env_path('unrar');
  }
  if (defined $path && -x $path) {
    $path = untaint_file_path($path);
    log_dbg("using unrar at $path");
    $self->{unrar} = $path;
  } else {
    log_dbg("unrar not found, rar extraction disabled (set archive_unrar_path)");
    $self->{unrar} = undef;
  }
  return $self->{unrar};
}

# Which unrar this is, asked once: 'rarlab', or 'free' for unrar-free 0.2.0 or
# later (the first with a print command).  Anything else gets '', and rar
# extraction is disabled.  Undef if unrar could not be run, to try again later.
sub _unrar_kind {
  my ($self, $pms, $bin) = @_;
  return $self->{unrar_kind} if defined $self->{unrar_kind};
  my ($out) = $self->_run_unrar($pms, undef, $bin, '-V');
  return unless defined $out;
  if ($out =~ /Alexander Roshal/) {
    $self->{unrar_kind} = 'rarlab';
  } elsif ($out =~ /^unrar-free (\d+)\.(\d+)/m && ($1 > 0 || $2 >= 2)) {
    $self->{unrar_kind} = 'free';
  } else {
    log_warn("$bin is neither RARLAB's unrar nor unrar-free 0.2.0 or later, ".
             "rar extraction disabled");
    $self->{unrar_kind} = '';
  }
  return $self->{unrar_kind};
}

# List the member names of a rar archive: `unrar lb -p- <archive>` prints one
# bare filename per line (CRLF on Windows) and never prompts for a password.
# unrar-free, which Fedora and Debian install as unrar, has no lb.  Its l
# listing has, between two lines of dashes, a line with a space and the name
# and then a line with size, date and attributes for each member.  Returns the
# number of members and the names to extract (in archive order); 0 on any
# failure.
sub _unrar_list {
  my ($self, $pms, $bin, $arc_file) = @_;
  my $free = $self->{unrar_kind} eq 'free';
  my ($out) = $self->_run_unrar($pms, undef, $bin,
                $free ? 'l' : 'lb', '-p-', '--', $arc_file);
  return 0 unless defined $out;
  my @lines = split(/\r?\n/, $out);
  if (!$free) {
    my @members = grep { length } @lines;
    return (scalar @members, @members);
  }

  shift @lines while @lines && $lines[0] !~ /^-+$/;
  shift @lines;
  my ($count, @members) = (0);
  while (@lines >= 2 && $lines[0] =~ /^ (.*)/s) {
    my $name = $1;
    $count++;
    # directories and empty files have nothing to scan
    push @members, $name if $lines[1] =~ /^\s*[1-9]/;
    splice(@lines, 0, 2);
  }
  return ($count, @members);
}

# Extract one member to stdout: `unrar p -inul -p- <archive> <member>` prints the
# file's bytes with no UI noise and never prompts for a password (so
# password-protected members simply fail and are skipped).  RARLAB's unrar
# prints only the first member with the name unless given a -r switch, and -r-
# lifts that without searching for other archives; unrar-free prints them all.
# Returns the bytes, or undef on failure or if they exceed $limit, and the
# number of bytes read.
sub _unrar_extract {
  my ($self, $pms, $bin, $arc_file, $member, $limit) = @_;
  my @all = $self->{unrar_kind} eq 'rarlab' ? ('-r-') : ();
  my ($out, $produced) = $self->_run_unrar($pms, $limit, $bin, 'p', '-inul',
                                           '-p-', @all, '--', $arc_file, $member);
  return (undef, $produced) if !defined $out || $produced > $limit;
  return ($out, $produced);
}

# Run unrar with the given args under a Timeout and return its stdout, or undef on
# failure, and the number of bytes read.  Reading stops once it exceeds $limit,
# if given.  Mirrors Handler::PDF::_extract_text: a pipe open in helper-run-mode,
# the whole thing wrapped in a Mail::SpamAssassin::Timeout, with the stale child
# reaped if the timer fires.
sub _run_unrar {
  my ($self, $pms, $limit, $bin, @args) = @_;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $secs = $conf->{handler_time_limit} || 10;

  my ($err_file, $pid, $resp, $errno);

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($pms);

  my $timer = Mail::SpamAssassin::Timeout->new(
    { secs => $secs, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($err_file, my $err_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $err_file or die "failed to create a temporary file\n";
    close($err_fh);
    $err_file = untaint_file_path($err_file);

    my @cmd = ($bin, map { untaint_var($_) } @args);

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
             *ARCHIVE_UNRAR, undef, ">$err_file", @cmd);
    $pid or die "$!\n";

    binmode ARCHIVE_UNRAR;
    my ($inbuf, $nread, $over);
    $resp = '';
    while ($nread = read(ARCHIVE_UNRAR, $inbuf, 8192)) {
      $resp .= $inbuf;
      # a flag, since kill in a statement that reads $resp dies under -T
      if (defined $limit && length($resp) > $limit) { $over = 1; last }
    }
    defined $nread or die "error reading from pipe: $!\n";

    $errno = 0;
    kill('TERM', $pid) if $over;
    close ARCHIVE_UNRAR or $errno = $!;

    if (proc_status_ok($?, $errno)) {
      log_dbg("unrar [$pid] finished successfully");
    } else {
      log_dbg("unrar [$pid] finished: " . exit_status_str($?, $errno));
    }
  });

  # Reap a stale child if the timer fired mid-run.
  if (defined(fileno(*ARCHIVE_UNRAR))) {
    if ($pid) {
      kill('TERM', $pid) and log_dbg("killed stale unrar [$pid]");
    }
    close ARCHIVE_UNRAR or 1;
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($pms);

  unlink($err_file) if defined $err_file;

  if ($err) {
    if ($err =~ /__brokenpipe__ignore__/) {
      log_dbg("unrar broken pipe, ignoring");
    } elsif ($timer->timed_out) {
      log_dbg("unrar timed out after ${secs}s");
    } else {
      chomp(my $e = $err);
      log_warn("unrar error: $e");
    }
    return (undef, length($resp // ''));
  }

  return ($resp, length $resp);
}

# check_archive_file_count($pms, $min, $max): fire when any archive in the message
# has an entry count of at least $min (and, if $max is given and non-zero, at
# most $max).  Reads the per-archive counts recorded by handle_zip / handle_rar.
#
# Registered as a body eval, so the harness calls it as
# ($self, $pms, $fulltext, @ruleargs): the body text is passed ahead of the
# rule's own arguments (mirroring stock body evals like check_blank_line_ratio).
# We don't use the body text -- the signal is the recorded archive counts -- so
# $fulltext is accepted and ignored.
#
#   body  ARC_MANY_FILES  eval:check_archive_file_count(100)
#   body  ARC_FILES_RANGE eval:check_archive_file_count(2,10)
sub check_archive_file_count {
  my ($self, $pms, $fulltext, $min, $max) = @_;
  my $counts = $pms->{Handler}{Archive}{file_counts};
  return 0 unless ref $counts eq 'ARRAY' && @$counts;

  $min = 0 unless defined $min;
  for my $n (@$counts) {
    next if $n < $min;
    next if defined $max && $max && $n > $max;
    return 1;
  }
  return 0;
}

1;
