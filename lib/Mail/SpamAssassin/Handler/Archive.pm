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
JavaScript handler, an C<inner.html> reaches the HTML handler, an C<inner.pdf>
the PDF handler, an image the image handler, and a nested archive comes back to
this handler -- all bounded by the framework's depth, part-count and byte
budgets.

The handler is intentionally thin: its main job is to make the archive's contents
visible to the other handlers and to ordinary body rules.  It also provides one
eval rule, C<check_archive_file_count>, for matching on the number of files an
archive declares (see L</EVAL RULES>).

=head1 REQUIREMENTS

=over 2

=item zip

Extraction uses L<IO::Uncompress::Unzip>, which is part of the core Perl
distribution.  It is loaded lazily; if it is somehow unavailable the handler
still loads (with a warning at startup) and simply skips zip archives.

=item rar

Extraction shells out to the C<unrar> executable.  Set C<archive_unrar_path> if
it is not on the C<PATH>.  If it cannot be found, rar extraction is disabled with
a debug message, so C<--lint> never fails merely because the binary is absent.

=back

=head1 CONFIGURATION

=over 4

=item archive_max_files N    (default: 2)

Extract at most N files from each archive.  Bounds the work done downstream and
is a countermeasure against archives that pack a very large number of entries.

=item archive_unrar_path /path/to/unrar

Full path to the C<unrar> executable.  If unset, the handler looks for C<unrar>
on the C<PATH>.

=back

=head1 EVAL RULES

=over 4

=item check_archive_file_count(min[, max])

Fires when any archive in the message declares an entry count of at least C<min>
(and, if C<max> is given and non-zero, at most C<max>).  The count is the
archive's full declared total -- read from the zip End Of Central Directory
record, or from C<unrar>'s member listing -- and is therefore independent of
C<archive_max_files>: an archive that packs thousands of files but from which only
four are extracted still reports its true size.  Useful for flagging archives that
pack an implausible number of entries.

  body  ARC_MANY_FILES   eval:check_archive_file_count(100)
  body  ARC_FILES_RANGE  eval:check_archive_file_count(2,10)

=back

=cut

package Mail::SpamAssassin::Handler::Archive;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg would_log);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str);

our @ISA = qw(Mail::SpamAssassin::Handler);

# Default for archive_max_files; single source of truth for the registered
# default and the per-call-site fallback below.
use constant DEFAULT_MAX_FILES => 2;

# zip extraction uses the core IO::Uncompress::Unzip.  Load it lazily and guard
# on the result, mirroring the optional-dependency idiom in Handler::PDF: the
# handler still loads if it is missing, only zip archives are skipped.
use constant HAS_UNZIP => eval { require IO::Uncompress::Unzip; 1 };
BEGIN { IO::Uncompress::Unzip->import('$UnzipError') if HAS_UNZIP; }

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
  # declares an entry count in [min,max].  The count is the archive's full
  # declared total (EOCD record for zip, member list for rar), independent of how
  # many files archive_max_files actually extracts -- so it sees the true size of
  # an archive that packs far more entries than we open.
  $self->register_eval_rule('check_archive_file_count',
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # Warn once at startup if the zip backend is unavailable, so zip archives are
  # knowingly skipped rather than silently ignored.
  if (!HAS_UNZIP) {
    log_warn("zip archives not supported, required module IO::Uncompress::Unzip missing");
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

# _zip_entry_count(\$data): return the number of files a zip declares, WITHOUT
# decompressing anything, by reading the End Of Central Directory (EOCD) record.
# The EOCD sits at the tail of the file: a 22-byte fixed record (signature
# PK\x05\x06) optionally followed by an archive comment of up to 65535 bytes, so
# it begins within the last 22+65535 bytes.  Its "total number of central
# directory records" is a 2-byte little-endian field at offset +10.
#
# When that field is 0xFFFF the real count lives in the ZIP64 EOCD record
# (signature PK\x06\x06), whose "total entries" is an 8-byte little-endian field
# at offset +32; we read that when present.  Returns undef if no EOCD is found
# (truncated or non-zip data).
sub _zip_entry_count {
  my ($dataref) = @_;
  my $len = defined $$dataref ? length $$dataref : 0;
  return if $len < 22;

  # Search backwards for the EOCD signature within the comment window.  Scanning
  # a bounded tail (not the whole file) keeps this cheap on large archives.
  my $window = $len < 22 + 0xFFFF ? $len : 22 + 0xFFFF;
  my $tail   = substr($$dataref, $len - $window);
  my $pos    = rindex($tail, "PK\x05\x06");
  return if $pos < 0;
  return if $pos + 12 > length $tail;   # not enough bytes for the count field

  my $count = unpack('v', substr($tail, $pos + 10, 2));

  # 0xFFFF in the classic EOCD means "see the ZIP64 EOCD for the real count".
  if ($count == 0xFFFF) {
    my $z64 = rindex($tail, "PK\x06\x06");
    if ($z64 >= 0 && $z64 + 40 <= length $tail) {
      # 8-byte total-entries field; we only trust the low 32 bits (any archive
      # with >4G entries is pathological and the value is signal enough as-is).
      my ($lo, $hi) = unpack('VV', substr($tail, $z64 + 32, 8));
      $count = $hi ? 0xFFFFFFFF : $lo;
    }
  }

  return $count;
}

# Record an archive's declared entry count for check_archive_file_count.  One
# entry per archive part in the message (a message may carry several).
sub _record_file_count {
  my ($self, $pms, $count) = @_;
  return unless defined $count;
  push @{ $pms->{Handler}{Archive}{file_counts} }, $count;
  log_dbg("archive declares $count entries");
}

# handle_zip($node, $pms): extract up to archive_max_files files from a zip
# attachment and return each as an application/octet-stream child part named with
# the member's basename.  The framework re-dispatches each by effective_type.
# Pure Perl (IO::Uncompress::Unzip); the framework already wraps this call in a
# timeout, so no timeout is set here.
sub handle_zip {
  my ($self, $node, $pms) = @_;
  return [] unless HAS_UNZIP;

  my $data = $node->decode();
  return [] unless defined $data && length $data;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $max  = $conf->{archive_max_files} // DEFAULT_MAX_FILES;

  # Record the archive's full declared entry count (from the EOCD record) before
  # extracting, so check_archive_file_count sees the true total even though we
  # only open the first archive_max_files members below.
  $self->_record_file_count($pms, _zip_entry_count(\$data));

  my $u = IO::Uncompress::Unzip->new(\$data, MultiStream => 0);
  if (!$u) {
    log_dbg("failed to open zip: ".(defined $UnzipError ? $UnzipError : 'unknown error'));
    return [];
  }

  my @parts;
  my $status = 1;
  while ($status > 0 && @parts < $max) {
    my $hdr  = $u->getHeaderInfo();
    my $name = _basename($hdr ? $hdr->{Name} : undef);

    # Skip directory entries (the framework would just see an empty part).
    if ($name eq '' || ($hdr && defined $hdr->{Name} && $hdr->{Name} =~ m{/\z})) {
      $status = $u->nextStream();
      next;
    }

    my $content = '';
    my ($buf, $n);
    while (($n = $u->read($buf, 65536)) > 0) { $content .= $buf; }
    if (!defined $n) {
      log_dbg("error reading zip member $name: ".(defined $UnzipError ? $UnzipError : '?'));
    } elsif (length $content) {
      log_dbg("extracted zip member: $name (".length($content)." bytes)");
      push @parts, {
        type => 'application/octet-stream',
        data => $content,
        name => $name,
      };
    }

    $status = $u->nextStream();
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

  my @members = $self->_unrar_list($pms, $bin, $arc_file);

  # Record the full declared entry count before capping at archive_max_files, so
  # check_archive_file_count sees the true total of the archive.
  $self->_record_file_count($pms, scalar @members);

  splice(@members, $max) if @members > $max;

  my @parts;
  for my $member (@members) {
    my $bytes = $self->_unrar_extract($pms, $bin, $arc_file, $member);
    next unless defined $bytes && length $bytes;
    my $name = _basename($member);
    next if $name eq '';
    log_dbg("extracted rar member: $name (".length($bytes)." bytes)");
    push @parts, {
      type => 'application/octet-stream',
      data => $bytes,
      name => $name,
    };
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

# List the member names of a rar archive: `unrar lb -p- <archive>` prints one
# bare filename per line and never prompts for a password.  Returns the list (in
# archive order); empty on any failure.
sub _unrar_list {
  my ($self, $pms, $bin, $arc_file) = @_;
  my $out = $self->_run_unrar($pms, $bin, 'lb', '-p-', '--', $arc_file);
  return () unless defined $out;
  my @members = grep { length } map { chomp; $_ } split(/\n/, $out);
  return @members;
}

# Extract one member to stdout: `unrar p -inul -p- <archive> <member>` prints the
# file's bytes with no UI noise and never prompts for a password (so
# password-protected members simply fail and are skipped).  Returns the bytes, or
# undef on failure.
sub _unrar_extract {
  my ($self, $pms, $bin, $arc_file, $member) = @_;
  return $self->_run_unrar($pms, $bin, 'p', '-inul', '-p-', '--',
                           $arc_file, $member);
}

# Run unrar with the given args under a Timeout and return its stdout, or undef on
# failure.  Mirrors Handler::PDF::_extract_text: a pipe open in helper-run-mode,
# the whole thing wrapped in a Mail::SpamAssassin::Timeout, with the stale child
# reaped if the timer fires.
sub _run_unrar {
  my ($self, $pms, $bin, @args) = @_;

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
    my ($inbuf, $nread);
    $resp = '';
    while ($nread = read(ARCHIVE_UNRAR, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread or die "error reading from pipe: $!\n";

    $errno = 0;
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
    return;
  }

  return $resp;
}

# check_archive_file_count($pms, $min, $max): fire when any archive in the message
# declares an entry count of at least $min (and, if $max is given and non-zero, at
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
