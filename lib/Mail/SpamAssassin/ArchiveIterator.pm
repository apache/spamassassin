# iterate over mail archives, calling a function on each message.
#
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

package Mail::SpamAssassin::ArchiveIterator;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Errno qw(ENOENT EACCES EBADF);
use Mail::SpamAssassin::Util qw(compile_regexp);
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::AICache;

# 500 KiB is a big email, unless stated otherwise
use constant BIG_BYTES => 500*1024;

our ( $MESSAGES, $AICache, %class_opts );

our @ISA = qw();

=head1 NAME

Mail::SpamAssassin::ArchiveIterator - find and process messages one at a time

=head1 SYNOPSIS

  my $iter = Mail::SpamAssassin::ArchiveIterator->new(
    { 
      'opt_max_size' => 500 * 1024,  # 0 implies no limit
      'opt_cache' => 1,
    }
  );

  $iter->set_functions( \&wanted, sub { } );

  eval { $iter->run(@ARGV); };

  sub wanted {
    my($class, $filename, $recv_date, $msg_array) = @_;


    ...
  }

=head1 DESCRIPTION

The Mail::SpamAssassin::ArchiveIterator module will go through a set
of mbox files, mbx files, and directories (with a single message per
file) and generate a list of messages.  It will then call the C<wanted_sub>
and C<result_sub> functions appropriately per message.

=head1 METHODS

=over 4

=cut


###########################################################################

=item $item = Mail::SpamAssassin::ArchiveIterator-E<gt>new( [ { opt =E<gt> val, ... } ] )

Constructs a new C<Mail::SpamAssassin::ArchiveIterator> object.  You may
pass the following attribute-value pairs to the constructor.  The pairs are
optional unless otherwise noted.

=over 4

=item opt_max_size

A value of option I<opt_max_size> determines a limit (number of bytes)
beyond which a message is considered large and is skipped by ArchiveIterator.

A value 0 implies no size limit, all messages are examined. An undefined
value implies a default limit of 500 KiB.

=item opt_all

Setting this option to true implicitly sets I<opt_max_size> to 0, i.e.
no limit of a message size, all messages are processes by ArchiveIterator.
For compatibility with SpamAssassin versions older than 3.4.0 which
lacked option I<opt_max_size>.

=item opt_scanprob

Randomly select messages to scan, with a probability of N, where N ranges
from 0.0 (no messages scanned) to 1.0 (all messages scanned).  Default
is 1.0.

This setting can be specified separately for each target.

=item opt_before

Only use messages which are received after the given time_t value.
Negative values are an offset from the current time, e.g. -86400 =
last 24 hours; or as parsed by Time::ParseDate (e.g. '-6 months')

This setting can be specified separately for each target.

=item opt_after

Same as opt_before, except the messages are only used if after the given
time_t value.

This setting can be specified separately for each target.

=item opt_want_date

Set to 1 (default) if you want the received date to be filled in
in the C<wanted_sub> callback below.  Set this to 0 to avoid this;
it's a good idea to set this to 0 if you can, as it imposes a performance
hit.

=item opt_skip_empty_messages

Set to 1 if you want to skip corrupt, 0-byte messages.  The default is 0.

=item opt_cache

Set to 0 (default) if you don't want to use cached information to help speed
up ArchiveIterator.  Set to 1 to enable.  This setting requires C<opt_cachedir>
also be set.

=item opt_cachedir

Set to the path of a directory where you wish to store cached information for
C<opt_cache>, if you don't want to mix them with the input files (as is the
default).  The directory must be both readable and writable.

=item wanted_sub

Reference to a subroutine which will process message data.  Usually
set via set_functions().  The routine will be passed 5 values: class
(scalar), filename (scalar), received date (scalar), message content
(array reference, one message line per element), and the message format
key ('f' for file, 'm' for mbox, 'b' for mbx).

Note that if C<opt_want_date> is set to 0, the received date scalar will be
undefined.

=item result_sub

Reference to a subroutine which will process the results of the wanted_sub
for each message processed.  Usually set via set_functions().
The routine will be passed 3 values: class (scalar), result (scalar, returned
from wanted_sub), and received date (scalar).

Note that if C<opt_want_date> is set to 0, the received date scalar will be
undefined.

=item scan_progress_sub

Reference to a subroutine which will be called intermittently during
the 'scan' phase of the mass-check.  No guarantees are made as to
how frequently this may happen, mind you.

=item opt_from_regex

This setting allows for flexibility in specifying the mbox format From separator.

It defaults to the regular expression:

/^From \S+  ?(\S\S\S \S\S\S .?\d .?\d:\d\d:\d\d \d{4}|.?\d-\d\d-\d{4}_\d\d:\d\d:\d\d_)/

Some SpamAssassin programs such as sa-learn will use the configuration option 
'mbox_format_from_regex' to override the default regular expression.

=back

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  # If any of these options are set, we need to figure out the message's
  # receive date at scan time.  opt_after, opt_before, or opt_want_date
  $self->{determine_receive_date} = 
  	defined $self->{opt_after} || defined $self->{opt_before} ||
        $self->{opt_want_date};

  $self->{s} = [ ];		# spam, of course
  $self->{h} = [ ];		# ham, as if you couldn't guess

  if ($self->{opt_all}) {
    $self->{opt_max_size} = 0;
  } elsif (!defined $self->{opt_max_size}) {
    $self->{opt_max_size} = BIG_BYTES;
  }

  $self;
}

###########################################################################

=item set_functions( \&wanted_sub, \&result_sub )

Sets the subroutines used for message processing (wanted_sub), and result
reporting.  For more information, see I<new()> above.

=cut

sub set_functions {
  my ($self, $wanted, $result) = @_;
  $self->{wanted_sub} = $wanted if defined $wanted;
  $self->{result_sub} = $result if defined $result;
}

###########################################################################

=item run ( @target_paths )

Generates the list of messages to process, then runs each message through
the configured wanted subroutine.

Compressed files are detected and uncompressed automatically regardless of
file extension.  Supported formats are C<gzip>, C<bzip2>, C<xz>, C<lz4>,
C<lzip>, C<lzo>.  Gzip is uncompressed via IO::Zlib module, others use their
specific command line tool (bzip2/xz/lz4/lzip/lzop).  Compressed
mailbox/mbox files are not supported.

The target_paths array is expected to be either one element per path in the
following format: C<class:format:raw_location>, or a hash reference containing
key-value option pairs and a 'target' key with a value in that format.

The key-value option pairs that can be used are: opt_scanprob, opt_after,
opt_before.  See the constructor method's documentation for more information
on their effects.

run() returns 0 if there was an error (can't open a file, etc,) and 1 if there
were no errors.

=over 4

=item class

Either 'h' for ham or 's' for spam.  If the class is longer than 1 character,
it will be truncated.  If blank, 'h' is default.

=item format

Specifies the format of the raw_location.  C<dir> is a directory whose
files are individual messages, C<file> a file with a single message,
C<mbox> an mbox formatted file, or C<mbx> for an mbx formatted directory.

C<detect> can also be used.  This assumes C<mbox> for any file whose path
contains the pattern C</\.mbox/i>, C<file> anything that is not a
directory, or C<directory> otherwise.

=item raw_location

Path to file or directory.  File globbing is allowed using the
standard csh-style globbing (see C<perldoc -f glob>).  C<~> at the
front of the value will be replaced by the C<HOME> environment
variable.  Escaped whitespace is protected as well.

B<NOTE:> C<~user> is not allowed.

B<NOTE 2:> C<-> is not allowed as a raw location.  To have
ArchiveIterator deal with STDIN, generate a temp file.

=back

=cut

sub run {
  my ($self, @targets) = @_;

  if (!defined $self->{wanted_sub}) {
    warn "archive-iterator: set_functions never called";
    return 0;
  }

  # Find some uncompressors (gzip is handled with IO::Zlib)
  foreach ('bzip2','xz','lz4','lzip','lzop') {
    $self->{$_.'_path'} = Mail::SpamAssassin::Util::find_executable_in_env_path($_);
  }

  # scan the targets and get the number and list of messages
  $self->_scan_targets(\@targets,
    sub {
      my($self, $date, $class, $format, $mail) = @_;
      push(@{$self->{$class}}, _index_pack($date, $class, $format, $mail));
    }
  );

  my $messages;
  # for ease of memory, we'll play with pointers
  $messages = $self->{s};
  undef $self->{s};
  push(@{$messages}, @{$self->{h}});
  undef $self->{h};

  $MESSAGES = scalar(@{$messages});

  # go ahead and run through all of the messages specified
  return $self->_run($messages);
}

sub _run {
  my ($self, $messages) = @_;

  my $messages_run = 0;
  while (my $message = shift @{$messages}) {
    my($class, undef, $date, undef, $result) = $self->_run_message($message);
    if ($result) {
      $messages_run++;
      &{$self->{result_sub}}($class, $result, $date);
    }
  }
  # Return success if atleast some files were processed through
  return $messages_run > 0;
}

############################################################################

## run_message and related functions to process a single message

sub _run_message {
  my ($self, $msg) = @_;

  my ($date, $class, $format, $mail) = _index_unpack($msg);

  if ($format eq 'f') {
    return $self->_run_file($class, $format, $mail, $date);
  }
  elsif ($format eq 'm') {
    return $self->_run_mailbox($class, $format, $mail, $date);
  }
  elsif ($format eq 'b') {
    return $self->_run_mbx($class, $format, $mail, $date);
  }
}

sub _run_file {
  my ($self, $class, $format, $where, $date) = @_;

  my $fh = $self->_mail_open($where, 1);
  return unless $fh;

  my $opt_max_size = $self->{opt_max_size};
  if (!$opt_max_size) {
    # process any size
  } elsif (!-f _) {
    # must check size while reading
  } elsif (-s _ > $opt_max_size) {
    # skip too-big mails
    # note that -s can only deal with files, it returns 0 on char.spec. STDIN
    info("archive-iterator: skipping large message: ".
         "file size %d, limit %d bytes", -s _, $opt_max_size);
    close $fh  or die "error closing input file: $!";
    return;
  }

  my @msg;
  my $header;
  my $len = 0;
  my $str = '';
  my($inbuf,$nread);
  while ( $nread=read($fh,$inbuf,16384) ) {
    $len += $nread;
    if ($opt_max_size && $len > $opt_max_size) {
      info("archive-iterator: skipping large message: read %d, limit %d bytes",
           $len, $opt_max_size);
      close $fh  or die "error closing input file: $!";
      return;
    }
    $str .= $inbuf;
  }
  defined $nread  or die "error reading: $!";
  undef $inbuf;
  @msg = split(/^/m, $str, -1);  undef $str;
  for my $j (0..$#msg) {
    if ($msg[$j] =~ /^\015?$/) { $header = $j; last }
  }
  close $fh  or die "error closing input file: $!";

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

sub _run_mailbox {
  my ($self, $class, $format, $where, $date) = @_;

  my ($file, $offset);
  { local($1,$2);  # Bug 7140 (avoids perl bug [perl #123880])
    ($file, $offset) = ($where =~ m/(.*)\.(\d+)$/);
  }
  my @msg;
  my $header;

  my $fh = $self->_mail_open($file, 1);
  return unless $fh;

  my $opt_max_size = $self->{opt_max_size};
  dbg("archive-iterator: _run_mailbox %s, ofs %d, limit %d",
      $file, $offset, $opt_max_size||0);

  seek($fh,$offset,0)  or die "cannot reposition file to $offset: $!";

  my $size = 0;
  for ($!=0; <$fh>; $!=0) {
    #Changed Regex to use option Per bug 6703
    last if (/^From / && @msg && $_ =~ $self->{opt_from_regex});
    $size += length($_);
    push (@msg, $_);

    # skip mails that are too big
    if ($opt_max_size && $size > $opt_max_size) {
      info("archive-iterator: skipping large message: ".
           "%d lines, %d bytes, limit %d bytes",
           scalar @msg, $size, $opt_max_size);
      close $fh  or die "error closing input file: $!";
      return;
    }

    if (!defined $header && /^\s*$/) {
      $header = $#msg;
    }
  }
  defined $_ || $!==0  or
    $!==EBADF ? dbg("archive-iterator: error reading: $!")
              : die "error reading: $!";
  close $fh  or die "error closing input file: $!";

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

sub _run_mbx {
  my ($self, $class, $format, $where, $date) = @_;

  my ($file, $offset);
  { local($1,$2);  # Bug 7140 (avoids perl bug [perl #123880])
    ($file, $offset) = ($where =~ m/(.*)\.(\d+)$/);
  }
  my @msg;
  my $header;

  my $fh = $self->_mail_open($file, 1);
  return unless $fh;

  my $opt_max_size = $self->{opt_max_size};
  dbg("archive-iterator: _run_mbx %s, ofs %d, limit %d",
      $file, $offset, $opt_max_size||0);

  seek($fh,$offset,0)  or die "cannot reposition file to $offset: $!";
    
  my $size = 0;
  for ($!=0; <$fh>; $!=0) {
    last if ($_ =~ MBX_SEPARATOR);
    $size += length($_);
    push (@msg, $_);

    # skip mails that are too big
    if ($opt_max_size && $size > $opt_max_size) {
      info("archive-iterator: skipping large message: ".
           "%d lines, %d bytes, limit %d bytes",
           scalar @msg, $size, $opt_max_size);
      close $fh  or die "error closing input file: $!";
      return;
    }

    if (!defined $header && /^\s*$/) {
      $header = $#msg;
    }
  }
  defined $_ || $!==0  or
    $!==EBADF ? dbg("archive-iterator: error reading: $!")
              : die "error reading: $!";
  close $fh  or die "error closing input file: $!";

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

############################################################################

## FUNCTIONS BELOW THIS POINT ARE FOR FINDING THE MESSAGES TO RUN AGAINST

############################################################################

sub _scan_targets {
  my ($self, $targets, $bkfunc) = @_;

  %class_opts = ();

  foreach my $target (@${targets}) {
    if (!defined $target) {
      warn "archive-iterator: invalid (undef) value in target list";
      next;
    }

    my %opts;
    if (ref $target eq 'HASH') {
      # e.g. { target => $target, opt_foo => 1, opt_bar => 0.4 ... }
      foreach my $k (keys %{$target}) {
        if ($k =~ /^opt_/) {
          $opts{$k} = $target->{$k};
        }
      }
      $target = $target->{target};
    }

    my ($class, $format, $rawloc) = split(/:/, $target, 3);

    # "class"
    if (!defined $format) {
      warn "archive-iterator: invalid (undef) format in target list, $target";
      next;
    }
    # "class:format"
    if (!defined $rawloc) {
      warn "archive-iterator: invalid (undef) raw location in target list, $target";
      next;
    }

    if ($rawloc eq '-') {
      warn 'archive-iterator: raw location "-" is not supported';
      next;
    }

    # use ham by default, things like "spamassassin" can't specify the type
    $class = substr($class, 0, 1) || 'h';

    # keep a copy of the most recent message-selection options for
    # each class
    $class_opts{$class} = \%opts;

    foreach my $k (keys %opts) {
      $self->{$k} = $opts{$k};
    }
    $self->_set_default_message_selection_opts();

    my @locations = $self->_fix_globs($rawloc);

    foreach my $location (@locations) {
      my $method;

      # for this location only; 'detect' means they can differ for each location
      my $thisformat = $format;

      if ($format eq 'detect') {
	# detect the format
        my $stat_errn = stat($location) ? 0 : 0+$!;
        if ($stat_errn != 0) {
          warn "archive-iterator: no access to $location: $!\n";
          next;
        }
        elsif (-d _) {
	  # it's a directory
	  $thisformat = 'dir';
        }
        elsif ($location =~ /\.mbox/i) {
          # filename indicates mbox
          $thisformat = 'mbox';
        } 
	else {
          $thisformat = 'file';
	}
      }

      if ($thisformat eq 'dir') {
        $method = \&_scan_directory;
      }
      elsif ($thisformat eq 'mbox') {
        $method = \&_scan_mailbox;
      }
      elsif ($thisformat eq 'file') {
        $method = \&_scan_file;
      }
      elsif ($thisformat eq 'mbx') {
        $method = \&_scan_mbx;
      }
      else {
	warn "archive-iterator: format $thisformat (from $format) unknown!";
        next;
      }

      # call the appropriate method
      &{$method}($self, $class, $location, $bkfunc);
    }
  }
}

sub _mail_open {
  my ($self, $file, $ignore_missing) = @_;
  my $fh;

  # Go ahead and try to open the file
  # bug 5288: the "magic" version of open will strip leading and trailing
  # whitespace from the expression.  switch to the three-argument version
  # of open which does not strip whitespace.  see "perldoc -f open" and
  # "perldoc perlipc" for more information.
  if (!open($fh, '<', $file)) {
    # Don't warn about disappeared files
    if ($ignore_missing && $! == ENOENT) {
      dbg("archive-iterator: no access to $file: $!");
    } else {
      warn "archive-iterator: no access to $file: $!\n"
    }
    return;
  }

  # bug 5249: mail could have 8-bit data, need this on some platforms
  binmode $fh  or die "cannot set input file to binmode: $!";

  # Detect compressed data (only from files, can't reopen pipe)
  if (-f $file && read($fh, my $magic, 6)) {
    # GZIP
    if ($magic =~ /^\x1F\x8B/) {
      dbg("archive-iterator: detected gzip file $file, reopening with IO::Zlib");
      close $fh  or die "error closing input file: $!";
      eval { require IO::Zlib; };
      if ($@) { warn "archive-iterator: IO::Zlib required for $file: $@\n"; return; }
      $fh = IO::Zlib->new($file, "rb");
      if (!$fh) {
        if ($ignore_missing && $! == ENOENT) {
          dbg("archive-iterator: no access to $file: $!");
        } else {
          warn "archive-iterator: no access to $file: $!\n";
        }
        return;
      }
    }
    # BZIP2
    elsif ($magic =~ /^\x42\x5A(?:\x68|\x30)/) {
      dbg("archive-iterator: detected bzip2 file $file, reopening with bzip2");
      close $fh  or die "error closing input file: $!";
      if (!$self->{bzip2_path}) {
        warn "archive-iterator: bzip2 executable required for $file\n";
        return;
      }
      if (!open($fh, '-|', $self->{bzip2_path}, '-cd', $file)) {
        warn "archive-iterator: no access to $file: $!\n";
        return;
      }
      binmode $fh  or die "cannot set input file to binmode: $!";
    }
    # XZ
    elsif ($magic =~ /^\xFD\x37\x7A\x58\x5A\x00/) {
      dbg("archive-iterator: detected xz file $file, reopening with xz");
      close $fh  or die "error closing input file: $!";
      if (!$self->{xz_path}) {
        warn "archive-iterator: xz executable required for $file\n";
        return;
      }
      if (!open($fh, '-|', $self->{xz_path}, '-cd', $file)) {
        warn "archive-iterator: no access to $file: $!\n";
        return;
      }
      binmode $fh  or die "cannot set input file to binmode: $!";
    }
    # LZ4
    elsif ($magic =~ /^\x04\x22\x4D\x18/) {
      dbg("archive-iterator: detected lz4 file $file, reopening with lz4");
      close $fh  or die "error closing input file: $!";
      if (!$self->{lz4_path}) {
        warn "archive-iterator: lz4 executable required for $file\n";
        return;
      }
      if (!open($fh, '-|', $self->{lz4_path}, '-cd', $file)) {
        warn "archive-iterator: no access to $file: $!\n";
        return;
      }
      binmode $fh  or die "cannot set input file to binmode: $!";
    }
    # LZIP
    elsif ($magic =~ /^\x4C\x5A\x49\x50/) {
      dbg("archive-iterator: detected lzip file $file, reopening with lzip");
      close $fh  or die "error closing input file: $!";
      if (!$self->{lzip_path}) {
        warn "archive-iterator: lzip executable required for $file\n";
        return;
      }
      if (!open($fh, '-|', $self->{lzip_path}, '-cd', $file)) {
        warn "archive-iterator: no access to $file: $!\n";
        return;
      }
      binmode $fh  or die "cannot set input file to binmode: $!";
    }
    # LZO
    elsif ($magic =~ /^\x89\x4C\x5A\x4F\x00\x0D/) {
      dbg("archive-iterator: detected lzo file $file, reopening with lzop");
      close $fh  or die "error closing input file: $!";
      if (!$self->{lzop_path}) {
        warn "archive-iterator: lzop executable required for $file\n";
        return;
      }
      if (!open($fh, '-|', $self->{lzop_path}, '-cd', $file)) {
        warn "archive-iterator: no access to $file: $!\n";
        return;
      }
      binmode $fh  or die "cannot set input file to binmode: $!";
    } else {
      # Reset position
      seek($fh,0,0);
    }
  }

  return $fh;
}

sub _set_default_message_selection_opts {
  my ($self) = @_;
 
  $self->{opt_scanprob} = 1.0 unless (defined $self->{opt_scanprob});
  $self->{opt_want_date} = 1 unless (defined $self->{opt_want_date});
  $self->{opt_cache} = 0 unless (defined $self->{opt_cache});
  #Changed Regex to include boundaries for Communigate Pro versions (5.2.x and later). per Bug 6413
  if (!defined $self->{opt_from_regex}) {
    $self->{opt_from_regex} = qr/^From \S+  ?(\S\S\S \S\S\S .?\d .?\d:\d\d:\d\d \d{4}|.?\d-\d\d-\d{4}_\d\d:\d\d:\d\d_)/;
  } elsif (ref($self->{opt_from_regex}) ne 'Regexp') {
    my ($rec, $err) = compile_regexp($self->{opt_from_regex}, 1);
    if (!$rec) {
      die "fatal: invalid mbox_format_from_regex '$self->{opt_from_regex}': $err\n";
    }
    $self->{opt_from_regex} = $rec;
  }

  dbg("archive-iterator: _set_default_message_selection_opts After: Scanprob[$self->{opt_scanprob}], want_date[$self->{opt_want_date}], cache[$self->{opt_cache}], from_regex[$self->{opt_from_regex}]");

}

############################################################################

sub _message_is_useful_by_date {
  my ($self, $date) = @_;

  if (!$self->{opt_after} && !$self->{opt_before}) {
    # Not using the feature
    return 1;
  }

  return 0 unless $date;	# undef or 0 date = unusable

  if (!$self->{opt_before}) {
    # Just care about after
    return $date > $self->{opt_after};
  }
  else {
    return (($date < $self->{opt_before}) && ($date > $self->{opt_after}));
  }
}

# additional check, based solely on a file's mod timestamp.  we cannot
# make assumptions about --before, since the file may have been "touch"ed
# since the last message was appended; but we can assume that too-old
# files cannot contain messages newer than their modtime.
sub _message_is_useful_by_file_modtime {
  my ($self, $date) = @_;

  # better safe than sorry, if date is undef; let other stuff catch errors
  return 1 unless $date;

  if ($self->{opt_after}) {
    return ($date > $self->{opt_after});
  }
  else {
    return 1;       # --after not in use
  }
}

sub _scanprob_says_scan {
  my ($self) = @_;
  if (defined $self->{opt_scanprob} && $self->{opt_scanprob} < 1.0) {
    if ( int( rand( 1 / $self->{opt_scanprob} ) ) != 0 ) {
      return 0;
    }
  }
  return 1;
}

############################################################################

# 0 850852128			atime
# 1 h				class
# 2 m				format
# 3 ./ham/goodmsgs.0		path

# put the date in first, big-endian packed format
# this format lets cmp easily sort by date, then class, format, and path.
sub _index_pack {
  return pack("NAAA*", @_);
}

sub _index_unpack {
  return unpack("NAAA*", $_[0]);
}

############################################################################

sub _scan_directory {
  my ($self, $class, $folder, $bkfunc) = @_;

  my(@files,@subdirs);

  if (-d "$folder/new" && -d "$folder/cur" && -d "$folder/tmp") {
    # Maildir format: bug 3003
    for my $sub ("new", "cur") {
      opendir (DIR, "$folder/$sub")
            or die "archive-iterator: can't open '$folder/$sub' dir: $!\n";
      # Don't learn from messages marked as deleted
      # Or files starting with a leading dot
      push @files, map { "$sub/$_" } grep { !/^\.|:2,.*T/ } readdir(DIR);
      closedir(DIR)  or die "error closing directory $folder: $!";
    } 
  }
  elsif (-f "$folder/cyrus.header") {
    opendir(DIR, $folder)
      or die "archive-iterator: can't open '$folder' dir: $!\n";

    # cyrus metadata: http://unix.lsa.umich.edu/docs/imap/imap-lsa-srv_3.html
    @files = grep { $_ ne '.' && $_ ne '..' &&
                    /^\S+$/ && !/^cyrus\.(?:index|header|cache|seen)/ }
		  readdir(DIR);
    closedir(DIR)  or die "error closing directory $folder: $!";
  }
  else {
    opendir(DIR, $folder)
      or die "archive-iterator: can't open '$folder' dir: $!\n";

    # ignore ,234 (deleted or refiled messages) and MH metadata dotfiles
    @files = grep { !/^[,.]/ } readdir(DIR);
    closedir(DIR)  or die "error closing directory $folder: $!";
  }

  $_ = "$folder/$_"  for @files;

  if (!@files) {
    # this is not a problem; no need to warn about it
    # warn "archive-iterator: readdir found no mail in '$folder' directory\n";
    return;
  }

  $self->_create_cache('dir', $folder);

  foreach my $file (@files) {
    my $stat_errn = stat($file) ? 0 : 0+$!;
    if ($stat_errn == ENOENT) {
      # no longer there?
      dbg("archive-iterator: no access to $file: $!");
    }
    elsif ($stat_errn != 0) {
      warn "archive-iterator: no access to $file: $!\n";
    }
    elsif (-f _ || -c _ || -p _) {
      $self->_scan_file($class, $file, $bkfunc);
    }
    elsif (-d _) {
      push(@subdirs, $file);
    }
    else {
      warn "archive-iterator: $file is not a plain file or directory\n";
    }
  }
  undef @files;  # release storage

  # recurse into directories
  foreach my $dir (@subdirs) {
    $self->_scan_directory($class, $dir, $bkfunc);
  }

  if (defined $AICache) {
    $AICache = $AICache->finish();
  }
}

sub _scan_file {
  my ($self, $class, $mail, $bkfunc) = @_;

  $self->_bump_scan_progress();

  # only perform these stat() operations if we're not using a cache;
  # it's faster to perform lookups in the cache, and more accurate
  if (!defined $AICache) {
    my @s = stat($mail);
    @s  or warn "archive-iterator: no access to $mail: $!";
    return unless $self->_message_is_useful_by_file_modtime($s[9]);
  }

  my $date = AI_TIME_UNKNOWN;
  if ($self->{determine_receive_date}) {
    unless (defined $AICache and $date = $AICache->check($mail)) {
      # silently skip directories/non-files; some folders may
      # contain extraneous dirs etc.
      my $stat_errn = stat($mail) ? 0 : 0+$!;
      if ($stat_errn != 0) {
        warn "archive-iterator: no access to $mail: $!";
        return;
      }
      elsif (!-f _) {
        return;
      }

      my $header = '';
      my $fh = $self->_mail_open($mail);
      return unless $fh;

      for ($!=0; <$fh>; $!=0) {
        last if /^\015?$/s;
        $header .= $_;
      }
      defined $_ || $!==0  or
        $!==EBADF ? dbg("archive-iterator: error reading: $!")
                  : die "error reading: $!";
      close $fh  or die "error closing input file: $!";

      return if ($self->{opt_skip_empty_messages} && $header eq '');

      $date = Mail::SpamAssassin::Util::receive_date($header);
      if (defined $AICache) {
        $AICache->update($mail, $date);
      }
    }

    return if !$self->_message_is_useful_by_date($date);
    return if !$self->_scanprob_says_scan();
  }
  else {
    return if ($self->{opt_skip_empty_messages} && (-z $mail));
  }

  &{$bkfunc}($self, $date, $class, 'f', $mail);

  return;
}

sub _scan_mailbox {
  my ($self, $class, $folder, $bkfunc) = @_;
  my @files;

  my $stat_errn = stat($folder) ? 0 : 0+$!;
  if ($stat_errn == ENOENT) {
    # no longer there?
  }
  elsif ($stat_errn != 0) {
    warn "archive-iterator: no access to $folder: $!";
  }
  elsif (-f _) {
    push(@files, $folder);
  }
  elsif (-d _) {
    # passed a directory of mboxes
    $folder =~ s/\/\s*$//; #Remove trailing slash, if there
    if (!opendir(DIR, $folder)) {
      warn "archive-iterator: can't open '$folder' dir: $!\n";
      return;
    }
    while ($_ = readdir(DIR)) {
      next if $_ eq '.' || $_ eq '..' || !/^[^\.]\S*$/;
      # hmmm, ignores folders with spaces in the name???
      $stat_errn = stat("$folder/$_") ? 0 : 0+$!;
      if ($stat_errn == ENOENT) {
        # no longer there?
      }
      elsif ($stat_errn != 0) {
        warn "archive-iterator: no access to $folder/$_: $!";
      }
      elsif (-f _) {
	push(@files, "$folder/$_");
      }
    }
    closedir(DIR)  or die "error closing directory $folder: $!";
  }
  else {
    warn "archive-iterator: $folder is not a plain file or directory: $!";
  }

  foreach my $file (@files) {
    $self->_bump_scan_progress();
    if ($file =~ /\.(?:gz|bz2|xz|lz[o4]?)$/i) {
      warn "archive-iterator: compressed mbox folders are not supported at this time\n";
      next;
    }

    my @s = stat($file);
    @s  or warn "archive-iterator: no access to $file: $!";
    next unless $self->_message_is_useful_by_file_modtime($s[9]);

    my $info = {};
    my $count;

    $self->_create_cache('mbox', $file);

    if ($self->{opt_cache}) {
      if ($count = $AICache->count()) {
        $info = $AICache->check();
      }
    }

    unless ($count) {
      my $fh = $self->_mail_open($file);
      next unless $fh;

      my $start = 0;		# start of a message
      my $where = 0;		# current byte offset
      my $first = '';		# first line of message
      my $header = '';		# header text
      my $in_header = 0;	# are in we a header?
      while (!eof $fh) {
        my $offset = $start;	# byte offset of this message
        my $header = $first;	# remember first line
        for ($!=0; <$fh>; $!=0) {
	  if ($in_header) {
            if (/^\015?$/s) {
	      $in_header = 0;
	    }
	    else {
	      $header .= $_;
	    }
	  }
          #Changed Regex to use option Per bug 6703
	  if (/^From / && $_ =~ $self->{opt_from_regex}) {
	    $in_header = 1;
	    $first = $_;
	    $start = $where;
	    $where = tell $fh;
            $where >= 0  or die "cannot obtain file position: $!";
	    last;
	  }
	  $where = tell $fh;
          $where >= 0  or die "cannot obtain file position: $!";
        }
        defined $_ || $!==0  or
          $!==EBADF ? dbg("archive-iterator: error reading: $!")
                    : die "error reading: $!";
        if ($header ne '') {
        # next if ($self->{opt_skip_empty_messages} && $header eq '');
          $self->_bump_scan_progress();
	  $info->{$offset} = Mail::SpamAssassin::Util::receive_date($header);
	}
      }
      close $fh  or die "error closing input file: $!";
    }

    while(my($k,$v) = each %{$info}) {
      if (defined $AICache && !$count) {
	$AICache->update($k, $v);
      }

      if ($self->{determine_receive_date}) {
        next if !$self->_message_is_useful_by_date($v);
      }
      next if !$self->_scanprob_says_scan();

      &{$bkfunc}($self, $v, $class, 'm', "$file.$k");
    }

    if (defined $AICache) {
      $AICache = $AICache->finish();
    }
  }
}

sub _scan_mbx {
  my ($self, $class, $folder, $bkfunc) = @_;
  my (@files, $fp);

  my $stat_errn = stat($folder) ? 0 : 0+$!;
  if ($stat_errn == ENOENT) {
    # no longer there?
  }
  elsif ($stat_errn != 0) {
    warn "archive-iterator: no access to $folder: $!";
  }
  elsif (-f _) {
    push(@files, $folder);
  }
  elsif (-d _) {
    # got passed a directory full of mbx folders.
    $folder =~ s/\/\s*$//; # remove trailing slash, if there is one
    if (!opendir(DIR, $folder)) {
      warn "archive-iterator: can't open '$folder' dir: $!\n";
      return;
    }
    while ($_ = readdir(DIR)) {
      next if $_ eq '.' || $_ eq '..' || !/^[^\.]\S*$/;
      # hmmm, ignores folders with spaces in the name???
      $stat_errn = stat("$folder/$_") ? 0 : 0+$!;
      if ($stat_errn == ENOENT) {
        # no longer there?
      }
      elsif ($stat_errn != 0) {
        warn "archive-iterator: no access to $folder/$_: $!";
      }
      elsif (-f _) {
	push(@files, "$folder/$_");
      }
    }
    closedir(DIR)  or die "error closing directory $folder: $!";
  }
  else {
    warn "archive-iterator: $folder is not a plain file or directory: $!";
  }

  foreach my $file (@files) {
    $self->_bump_scan_progress();

    if ($folder =~ /\.(?:gz|bz2|xz|lz[o4]?)$/i) {
      warn "archive-iterator: compressed mbx folders are not supported at this time\n";
      next;
    }

    my @s = stat($file);
    @s  or warn "archive-iterator: no access to $file: $!";
    next unless $self->_message_is_useful_by_file_modtime($s[9]);

    my $info = {};
    my $count;

    $self->_create_cache('mbx', $file);

    if ($self->{opt_cache}) {
      if ($count = $AICache->count()) {
        $info = $AICache->check();
      }
    }

    unless ($count) {
      my $fh = $self->_mail_open($file);
      next unless $fh;

      # check the mailbox is in mbx format
      $! = 0; $fp = <$fh>;
      defined $fp || $!==0  or
        $!==EBADF ? dbg("archive-iterator: error reading: $!")
                  : die "error reading: $!";
      if (!defined $fp) {
        die "archive-iterator: error: mailbox not in mbx format - empty!\n";
      } elsif ($fp !~ /\*mbx\*/) {
        die "archive-iterator: error: mailbox not in mbx format!\n";
      }

      # skip mbx headers to the first email...
      seek($fh,2048,0)  or die "cannot reposition file to 2048: $!";

      for ($!=0; <$fh>; $!=0) {
        if ($_ =~ MBX_SEPARATOR) {
	  my $offset = tell $fh;
          $offset >= 0  or die "cannot obtain file position: $!";
	  my $size = $2;

	  # gather up the headers...
	  my $header = '';
          for ($!=0; <$fh>; $!=0) {
            last if (/^\015?$/s);
	    $header .= $_;
	  }
          defined $_ || $!==0  or
            $!==EBADF ? dbg("archive-iterator: error reading: $!")
                      : die "error reading: $!";
          if (!($self->{opt_skip_empty_messages} && $header eq '')) {
            $self->_bump_scan_progress();
            $info->{$offset} = Mail::SpamAssassin::Util::receive_date($header);
          }

	  # go onto the next message
	  seek($fh, $offset + $size, 0)
            or die "cannot reposition file to $offset + $size: $!";
	}
        else {
	  die "archive-iterator: error: failure to read message body!\n";
        }
      }
      defined $_ || $!==0  or
        $!==EBADF ? dbg("archive-iterator: error reading: $!")
                  : die "error reading: $!";
      close $fh  or die "error closing input file: $!";
    }

    while(my($k,$v) = each %{$info}) {
      if (defined $AICache && !$count) {
	$AICache->update($k, $v);
      }

      if ($self->{determine_receive_date}) {
        next if !$self->_message_is_useful_by_date($v);
      }
      next if !$self->_scanprob_says_scan();

      &{$bkfunc}($self, $v, $class, 'b', "$file.$k");
    }

    if (defined $AICache) {
      $AICache = $AICache->finish();
    }
  }
}

############################################################################

sub _bump_scan_progress {
  my ($self) = @_;
  if (exists $self->{scan_progress_sub}) {
    return unless ($self->{scan_progress_counter}++ % 50 == 0);
    $self->{scan_progress_sub}->();
  }
}

############################################################################

{
  my $home;

  sub _fix_globs {
    my ($self, $path) = @_;

    unless (defined $home) {
      $home = $ENV{'HOME'};

      # No $HOME set?  Try to find it, portably.
      unless ($home) {
        if (!Mail::SpamAssassin::Util::am_running_on_windows()) {
          $home = (Mail::SpamAssassin::Util::portable_getpwuid($<))[7];
        } else {
          my $vol = $ENV{'HOMEDRIVE'} || 'C:';
          my $dir = $ENV{'HOMEPATH'} || '\\';
          $home = File::Spec->catpath($vol, $dir, '');
        }

        # Fall back to no replacement at all.
	$home ||= '~';
      }
    }
    $path =~ s,^~/,${home}/,;

    # protect/escape spaces: ./Mail/My Letters => ./Mail/My\ Letters
    $path =~ s/(?<!\\)(\s)/\\$1/g;

    # return csh-style globs: ./corpus/*.mbox => er, you know what it does ;)
    return glob($path);
  }
}

sub _create_cache {
  my ($self, $type, $path) = @_;

  if ($self->{opt_cache}) {
    $AICache = Mail::SpamAssassin::AICache->new({
                                    'type' => $type,
                                    'prefix' => $self->{opt_cachedir},
                                    'path' => $path,
                              });
  }
}

############################################################################

1;

__END__

=back

=head1 SEE ALSO

Mail::SpamAssassin(3)
spamassassin(1)
mass-check(1)

=cut

# vim: ts=8 sw=2 et
