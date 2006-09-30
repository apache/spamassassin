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
use bytes;

use IO::Select;
use IO::Socket;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::AICache;

use constant BIG_BYTES => 256*1024;	# 256k is a big email
use constant BIG_LINES => BIG_BYTES/65;	# 65 bytes/line is a good approximation

use vars qw {
  $MESSAGES
  $AICache
};

my @ISA = qw($MESSAGES);

=head1 NAME

Mail::SpamAssassin::ArchiveIterator - find and process messages one at a time

=head1 SYNOPSIS

  my $iter = new Mail::SpamAssassin::ArchiveIterator(
    { 
      'opt_j'     => 0,
      'opt_n'     => 1,
      'opt_all'   => 1,
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
file) and generate a list of messages.  It will then call the wanted
and results functions appropriately per message.

=head1 METHODS

=over 4

=cut


###########################################################################

=item $item = new Mail::SpamAssassin::ArchiveIterator( [ { opt => val, ... } ] )

Constructs a new C<Mail::SpamAssassin::ArchiveIterator> object.  You may
pass the following attribute-value pairs to the constructor.  The pairs are
optional unless otherwise noted.

=over 4

=item opt_all

Typically messages over 250k are skipped by ArchiveIterator.  Use this option
to keep from skipping messages based on size.

=item opt_j (required)

Specifies how many messages should be run at the same time, as well as the
method with which to scan for the messages.

If the value is 0, the list of messages to process will be kept in memory,
and only 1 message at a time will be processed by the wanted subroutine.
Restarting is not allowed.

If the value is 1, the list of messages to process will be kept in a
temporary file, and only 1 message at a time will be processed by the
wanted subroutine.  Restarting is not allowed.

If the value is 2 or higher, the list of messages to process will be kept
in a temporary file, and the process will split into a parent/child mode.
The option value number of children will be forked off and each child
will process messages via the wanted subroutine in parallel.  Restarting
is allowed.

B<NOTE:> For C<opt_j> >= 1, an extra child process will be created to
determine the list of messages, sort the list, everything as appropriate.
This will keep the list in memory (possibly multiple copies) before
writing the final list to a temporary file which will be used for
processing.  The list generation child will exit, freeing up the memory.

=item opt_n

ArchiveIterator is typically used to simulate ham and spam moving through
SpamAssassin.  By default, the list of messages is sorted by received date so
that the mails can be passed through in order.  If opt_n is true, the sorting
will not occur.  This is useful if you don't care about the order of the
messages.

=item opt_restart

If set to a positive integer value, children processes (see opt_j w/ value 2
or higher above) will restart after the option value number of messages, in
total, have been processed.

=item opt_head

Only use the first N ham and N spam (or if the value is -N, only use the first
N total messages regardless of class).

=item opt_tail

Only use the last N ham and N spam (or if the value is -N, only use the last
N total messages regardless of class).

If both C<opt_head> and C<opt_tail> are specified, then the C<opt_head> value
specifies a subset of the C<opt_tail> selection to use; in other words, the
C<opt_tail> splice is applied first.

=item opt_before

Only use messages which are received after the given time_t value.
Negative values are an offset from the current time, e.g. -86400 =
last 24 hours; or as parsed by Time::ParseDate (e.g. '-6 months')

=item opt_after

Same as opt_before, except the messages are only used if after the given
time_t value.

=item opt_want_date

Set to 1 (default) if you want the received date to be filled in
in the C<wanted_sub> callback below.  Set this to 0 to avoid this;
it's a good idea to set this to 0 if you can, as it imposes a performance
hit.

=item opt_cache

Set to 0 (default) if you don't want to use cached information to help speed
up ArchiveIterator.  Set to 1 to enable.

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

=back

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  $self->{opt_head} = 0 unless (defined $self->{opt_head});
  $self->{opt_tail} = 0 unless (defined $self->{opt_tail});
  $self->{opt_want_date} = 1 unless (defined $self->{opt_want_date});
  $self->{opt_cache} = 0 unless (defined $self->{opt_cache});

  # If any of these options are set, we need to figure out the message's
  # receive date at scan time.  opt_n == 0, opt_after, opt_before
  $self->{determine_receive_date} = !$self->{opt_n} ||
  	defined $self->{opt_after} || defined $self->{opt_before} ||
        $self->{opt_want_date};

  $self->{s} = [ ];		# spam, of course
  $self->{h} = [ ];		# ham, as if you couldn't guess

  $self->{access_problem} = 0;

  $self;
}

###########################################################################

=item set_functions( \&wanted_sub, \&result_sub )

Sets the subroutines used for message processing (wanted_sub), and result
reporting.  For more information, see I<new()> above.

=cut

sub set_functions {
  my ($self, $wanted, $result) = @_;
  $self->{wanted_sub} = $wanted;
  $self->{result_sub} = $result;
}

###########################################################################

=item run ( @target_paths )

Generates the list of messages to process, then runs each message through the
configured wanted subroutine.  Files which have a name ending in C<.gz> or
C<.bz2> will be properly uncompressed via call to C<gzip -dc> and C<bzip2 -dc>
respectively.

The target_paths array is expected to be one element per path in the following
format: class:format:raw_location

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
contains the pattern C</\.mbox/i>, C<file> for STDIN and anything that is
not a directory, or C<directory> otherwise.

=item raw_location

Path to file or directory.  Can be "-" for STDIN.  File globbing is allowed
using the standard csh-style globbing (see C<perldoc -f glob>).  C<~> at the
front of the value will be replaced by the C<HOME> environment variable.
Escaped whitespace is protected as well.

B<NOTE:> C<~user> is not allowed.

=back

=cut

sub run {
  my ($self, @targets) = @_;

  if (!defined $self->{wanted_sub}) {
    warn "archive-iterator: set_functions never called";
    return 0;
  }

  # non-forking model (generally sa-learn), everything in a single process
  if ($self->{opt_j} == 0) {
    my $messages;

    # message-array
    ($MESSAGES, $messages) = $self->message_array(\@targets);

    while (my $message = shift @{$messages}) {
      my($class, undef, $date, undef, $result) = $self->run_message($message);
      &{$self->{result_sub}}($class, $result, $date) if $result;
    }
  }
  # forking model (generally mass-check), avoid extended memory usage
  else {
    my $tmpf;
    ($tmpf, $self->{messageh}) = Mail::SpamAssassin::Util::secure_tmpfile()
      or die 'archive-iterator: failed to create temp file';
    unlink $tmpf or die "archive-iterator: unlink '$tmpf': $!";
    undef $tmpf;

    # forked child process scans messages
    if ($tmpf = fork()) {
      # parent
      waitpid($tmpf, 0);
    }
    elsif (defined $tmpf) {
      # child
      $self->message_array(\@targets, $self->{messageh});
      exit;
    }
    else {
      die "archive-iterator: cannot fork: $!";
    }

    # we now have a temporary file with the messages to process
    # in theory, our file pointer is at the start of the file, but make sure.
    # NOTE: do this here, not in message_array, since that will only affect
    # the child.
    seek($self->{messageh}, 0, 0);
    $MESSAGES = $self->next_message();

    if (!$MESSAGES) {
      die "archive-iterator: no messages to process\n";
    }
    # only do 1 process, message list in a temp file, no restarting
    if ($self->{opt_j} == 1 && !defined $self->{opt_restart}) {
      my $message;
      my $messages;
      my $total_count = 0;

      while (($MESSAGES > $total_count) && ($message = $self->next_message())) {
        my($class, undef, $date, undef, $result) = $self->run_message($message);
        &{$self->{result_sub}}($class, $result, $date) if $result;
	$total_count++;
      }
    }
    # more than one process or one process with restarts
    else {
      my $select = IO::Select->new();

      my $total_count = 0;
      my $needs_restart = 0;
      my @child = ();
      my @pid = ();
      my $messages;

      # start children processes
      $self->start_children($self->{opt_j}, \@child, \@pid, $select);

      # feed childen, make them work for it, repeat
      while ($select->count()) {
        foreach my $socket ($select->can_read()) {
	  my $line = $self->read_line($socket);

          # some error happened during the read!
          if (!defined $line) {
            $needs_restart = 1;
            warn "archive-iterator: readline failed, attempting to recover\n";
            $select->remove($socket);
          }
	  elsif ($line =~ /^([^\0]+)\0RESULT (.+)$/s) {
	    my $result = $1;
	    my ($date,$class,$type) = index_unpack($2);
	    #warn ">> RESULT: $class, $type, $date\n";

	    if (defined $self->{opt_restart} && ($total_count % $self->{opt_restart}) == 0) {
	      $needs_restart = 1;
	    }

	    # if messages remain, and we don't need to restart, send message
	    if (($MESSAGES > $total_count) && !$needs_restart) {
	      $self->send_line($socket, $self->next_message());
	      $total_count++;
	      #warn ">> recv: $MESSAGES $total_count\n";
	    }
	    else {
	      # stop listening on this child since we're done with it
	      #warn ">> removeresult: $needs_restart $MESSAGES $total_count\n";
	      $select->remove($socket);
	    }

	    # deal with the result we received
	    if ($result) {
	      &{$self->{result_sub}}($class, $result, $date);
	    }
	  }
	  elsif ($line eq "START") {
	    if ($MESSAGES > $total_count) {
	      # we still have messages, send one to child
	      $self->send_line($socket, $self->next_message());
	      $total_count++;
	      #warn ">> new: $MESSAGES $total_count\n";
	    }
	    else {
	      # no more messages, so stop listening on this child
	      #warn ">> removestart: $needs_restart $MESSAGES $total_count\n";
	      $select->remove($socket);
	    }
	  }
        }

        #warn ">> out of loop, $MESSAGES $total_count $needs_restart ".$select->count()."\n";

        # If there are still messages to process, and we need to restart
        # the children, and all of the children are idle, let's go ahead.
        if ($needs_restart && $select->count == 0 && $MESSAGES > $total_count)
	{
	  $needs_restart = 0;

	  #warn "debug: needs restart, $MESSAGES total, $total_count done\n";
	  $self->reap_children($self->{opt_j}, \@child, \@pid);
	  @child=();
	  @pid=();
	  $self->start_children($self->{opt_j}, \@child, \@pid, $select);
        }
      }

      # reap children
      $self->reap_children($self->{opt_j}, \@child, \@pid);
    }

    # close tempfile so it will be unlinked
    close($self->{messageh});
  }

  return ! $self->{access_problem};
}

############################################################################

## run_message and related functions to process a single message

sub run_message {
  my ($self, $msg) = @_;

  my ($date, $class, $format, $mail) = index_unpack($msg);

  if ($format eq 'f') {
    return $self->run_file($class, $format, $mail, $date);
  }
  elsif ($format eq 'm') {
    return $self->run_mailbox($class, $format, $mail, $date);
  }
  elsif ($format eq 'b') {
    return $self->run_mbx($class, $format, $mail, $date);
  }
}

sub run_file {
  my ($self, $class, $format, $where, $date) = @_;

  if (!mail_open($where)) {
    $self->{access_problem} = 1;
    return;
  }

  # skip too-big mails
  if (! $self->{opt_all} && -s INPUT > BIG_BYTES) {
    info("archive-iterator: skipping large message\n");
    close INPUT;
    return;
  }
  my @msg;
  my $header;
  while (<INPUT>) {
    push(@msg, $_);
    if (!defined $header && /^\s*$/) {
      $header = $#msg;
    }
  }
  close INPUT;

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

sub run_mailbox {
  my ($self, $class, $format, $where, $date) = @_;

  my ($file, $offset) = ($where =~ m/(.*)\.(\d+)$/);
  my @msg;
  my $header;
  if (!mail_open($file)) {
    $self->{access_problem} = 1;
    return;
  }
  seek(INPUT,$offset,0);
  while (<INPUT>) {
    last if (substr($_,0,5) eq "From " && @msg);
    push (@msg, $_);

    # skip too-big mails
    if (! $self->{opt_all} && @msg > BIG_LINES) {
      info("archive-iterator: skipping large message\n");
      close INPUT;
      return;
    }

    if (!defined $header && /^\s*$/) {
      $header = $#msg;
    }
  }
  close INPUT;

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

sub run_mbx {
  my ($self, $class, $format, $where, $date) = @_;

  my ($file, $offset) = ($where =~ m/(.*)\.(\d+)$/);
  my @msg;
  my $header;

  if (!mail_open($file)) {
    $self->{access_problem} = 1;
    return;
  }

  seek(INPUT, $offset, 0);
    
  while (<INPUT>) {
    last if ($_ =~ MBX_SEPARATOR);
    push (@msg, $_);

    # skip mails that are too big
    if (! $self->{opt_all} && @msg > BIG_LINES) {
      info("archive-iterator: skipping large message\n");
      close INPUT;
      return;
    }

    if (!defined $header && /^\s*$/) {
      $header = $#msg;
    }
  }
  close INPUT;

  if ($date == AI_TIME_UNKNOWN && $self->{determine_receive_date}) {
    $date = Mail::SpamAssassin::Util::receive_date(join('', splice(@msg, 0, $header)));
  }

  return($class, $format, $date, $where, &{$self->{wanted_sub}}($class, $where, $date, \@msg, $format));
}

############################################################################

## figure out the next message to process, used when opt_j >= 1

sub next_message {
  my ($self) = @_;
  my $line = $self->read_line($self->{messageh});
  return $line;
}

############################################################################

## children processors, start and process, used when opt_j > 1

sub start_children {
  my ($self, $count, $child, $pid, $socket) = @_;

  my $io = IO::Socket->new();
  my $parent;

  # create children
  for (my $i = 0; $i < $count; $i++) {
    ($child->[$i],$parent) = $io->socketpair(AF_UNIX,SOCK_STREAM,PF_UNSPEC)
	or die "archive-iterator: socketpair failed: $!";
    if ($pid->[$i] = fork) {
      close $parent;

      # disable caching for parent<->child relations
      my ($old) = select($child->[$i]);
      $|++;
      select($old);

      $socket->add($child->[$i]);
      #warn "debug: starting new child $i (pid ",$pid->[$i],")\n";
      next;
    }
    elsif (defined $pid->[$i]) {
      my $result;
      my $line;

      close $self->{messageh} if defined $self->{messageh};

      close $child->[$i];
      select($parent);
      $| = 1;	# print to parent by default, turn off buffering
      $self->send_line($parent,"START");
      while ($line = $self->read_line($parent)) {
	if ($line eq "exit") {
	  close $parent;
	  exit;
	}

	my($class, $format, $date, $where, $result) = $self->run_message($line);
	$result ||= '';

	# If determine_receive_date is not set, the original input date
	# wasn't calculated, but run_message would have done so, so reset
	# the packed version if possible ...  use defined for date since
	# it could == 0.
        if (!$self->{determine_receive_date} && $class && $format && defined $date && $where) {
	  $line = index_pack($date, $class, $format, $where);
        }

	$self->send_line($parent,"$result\0RESULT $line");
      }
      exit;
    }
    else {
      die "archive-iterator: cannot fork: $!";
    }
  }
}

## handling killing off the children

sub reap_children {
  my ($self, $count, $socket, $pid) = @_;

  # If the child died, sending it the exit will generate a SIGPIPE, but we
  # don't really care since the readline will go undef (which is fine),
  # then we do the waitpid which will finish it off.  So we end up in the
  # right state, in theory.
  local $SIG{'PIPE'} = 'IGNORE';

  for (my $i = 0; $i < $count; $i++) {
    #warn "debug: killing child $i (pid ",$pid->[$i],")\n";
    $self->send_line($socket->[$i],"exit"); # tell the child to die.
    close $socket->[$i];
    waitpid($pid->[$i], 0); # wait for the signal ...
  }
}

############################################################################

# four bytes in network/vax format (little endian) as length of message
# the rest is the actual message

sub read_line {
  my($self, $fd) = @_;
  my($length,$msg);

  # read in the 4 byte length and unpack
  sysread($fd, $length, 4);
  $length = unpack("V", $length);
#  warn "<< $$ $length\n";
  return unless $length;

  # read in the rest of the single message
  sysread($fd, $msg, $length);
#  warn "<< $$ $msg\n";
  return $msg;
}

sub send_line {
  my $self = shift;
  my $fd = shift;

  foreach ( @_ ) {
    my $length = pack("V", length $_);
#    warn ">> $$ ".length($_)." $_\n";
    syswrite($fd, $length . $_);
  }
}

############################################################################

## FUNCTIONS BELOW THIS POINT ARE FOR FINDING THE MESSAGES TO RUN AGAINST

############################################################################

sub message_array {
  my ($self, $targets, $fh) = @_;

  foreach my $target (@${targets}) {
    if (!defined $target) {
      warn "archive-iterator: invalid (undef) value in target list";
      next;
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

    # use ham by default, things like "spamassassin" can't specify the type
    $class = substr($class, 0, 1) || 'h';

    my @locations = $self->fix_globs($rawloc);

    foreach my $location (@locations) {
      my $method;

      if ($format eq 'detect') {
	# detect the format
        if (!-d $location && $location =~ /\.mbox/i) {
          # filename indicates mbox
          $method = \&scan_mailbox;
        } 
	elsif ($location eq '-' || !(-d $location)) {
	  # stdin is considered a file if not passed as mbox
          $method = \&scan_file;
	}
	else {
	  # it's a directory
	  $method = \&scan_directory;
	}
      }
      else {
	if ($format eq "dir") {
	  $method = \&scan_directory;
	}
	elsif ($format eq "file") {
	  $method = \&scan_file;
	}
	elsif ($format eq "mbox") {
	  $method = \&scan_mailbox;
        }
	elsif ($format eq "mbx") {
	  $method = \&scan_mbx;
	}
      }

      if(defined($method)) {
	&{$method}($self, $class, $location);
      }
      else {
	warn "archive-iterator: format $format unknown!";
      }
    }
  }

  my @messages;
  if ($self->{opt_n}) {
    # OPT_N == 1 means don't bother sorting on message receive date

    # head or tail > 0 means crop each list
    if ($self->{opt_tail} > 0) {
      splice(@{$self->{s}}, 0, -$self->{opt_tail});
      splice(@{$self->{h}}, 0, -$self->{opt_tail});
    }
    if ($self->{opt_head} > 0) {
      splice(@{$self->{s}}, min ($self->{opt_head}, scalar @{$self->{s}}));
      splice(@{$self->{h}}, min ($self->{opt_head}, scalar @{$self->{h}}));
    }

    @messages = ( @{$self->{s}}, @{$self->{h}} );
    undef $self->{s};
    undef $self->{h};
  }
  else {
    # OPT_N == 0 means sort on message receive date

    # Sort the spam and ham groups by date
    my @s = sort { $a cmp $b } @{$self->{s}};
    undef $self->{s};
    my @h = sort { $a cmp $b } @{$self->{h}};
    undef $self->{h};

    # head or tail > 0 means crop each list
    if ($self->{opt_tail} > 0) {
      splice(@s, 0, -$self->{opt_tail});
      splice(@h, 0, -$self->{opt_tail});
    }
    if ($self->{opt_head} > 0) {
      splice(@s, min ($self->{opt_head}, scalar @s));
      splice(@h, min ($self->{opt_head}, scalar @h));
    }

    # interleave ordered spam and ham
    if (@s && @h) {
      my $ratio = @s / @h;
      while (@s && @h) {
	push @messages, (@s / @h > $ratio) ? (shift @s) : (shift @h);
      }
    }
    # push the rest onto the end
    push @messages, @s, @h;
  }

  # head or tail < 0 means crop the total list, negate the value appropriately
  if ($self->{opt_tail} < 0) {
    splice(@messages, 0, $self->{opt_tail});
  }
  if ($self->{opt_head} < 0) {
    splice(@messages, -$self->{opt_head});
  }

  # Dump out the messages to the temp file if we're using one
  if (defined $fh) {
    $self->send_line($fh, scalar(@messages), @messages);
    return;
  }

  return scalar(@messages), \@messages;
}

sub mail_open {
  my ($file) = @_;

  my $expr;
  if ($file =~ /\.gz$/) {
    $expr = "gunzip -cd $file |";
  }
  elsif ($file =~ /\.bz2$/) {
    $expr = "bzip2 -cd $file |";
  }
  else {
    $expr = "$file";
  }
  if (!open (INPUT, $expr)) {
    warn "archive-iterator: unable to open $file: $!\n";
    return 0;
  }
  return 1;
}

############################################################################

sub message_is_useful_by_date  {
  my ($self, $date) = @_;

  return 0 unless $date;	# undef or 0 date = unusable

  if (!$self->{opt_after} && !$self->{opt_before}) {
    # Not using the feature
    return 1;
  }
  elsif (!$self->{opt_before}) {
    # Just case about after
    return $date > $self->{opt_after};
  }
  else {
    return (($date < $self->{opt_before}) && ($date > $self->{opt_after}));
  }
}

############################################################################

# 0 850852128			atime
# 1 h				class
# 2 m				format
# 3 ./ham/goodmsgs.0		path

# put the date in first, big-endian packed format
# this format lets cmp easily sort by date, then class, format, and path.
sub index_pack {
  return pack("NAAA*", @_);
}

sub index_unpack {
  return unpack("NAAA*", $_[0]);
}

############################################################################

sub scan_directory {
  my ($self, $class, $folder) = @_;

  my @files;

  opendir(DIR, $folder) || die "archive-iterator: can't open '$folder' dir: $!\n";
  if (-f "$folder/cyrus.header") {
    # cyrus metadata: http://unix.lsa.umich.edu/docs/imap/imap-lsa-srv_3.html
    @files = grep { /^\S+$/ && !/^cyrus\.(?:index|header|cache|seen)/ }
			readdir(DIR);
  }
  else {
    # ignore ,234 (deleted or refiled messages) and MH metadata dotfiles
    @files = grep { !/^[,.]/ } readdir(DIR);
  }
  closedir(DIR);

  @files = grep { -f } map { "$folder/$_" } @files;

  if (!@files) {
    # this is not a problem; no need to warn about it
    # warn "archive-iterator: readdir found no mail in '$folder' directory\n";
    return;
  }

  $self->create_cache('dir', $folder);

  foreach my $mail (@files) {
    $self->scan_file($class, $mail);
  }

  if (defined $AICache) {
    $AICache = $AICache->finish();
  }
}

sub scan_file {
  my ($self, $class, $mail) = @_;

  $self->bump_scan_progress();
  if (!$self->{determine_receive_date}) {
    push(@{$self->{$class}}, index_pack(AI_TIME_UNKNOWN, $class, "f", $mail));
    return;
  }

  my $date;

  unless (defined $AICache and $date = $AICache->check($mail)) {
    my $header;
    if (!mail_open($mail)) {
      $self->{access_problem} = 1;
      return;
    }
    while (<INPUT>) {
      last if /^\s*$/;
      $header .= $_;
    }
    close(INPUT);
    $date = Mail::SpamAssassin::Util::receive_date($header);
    if (defined $AICache) {
      $AICache->update($mail, $date);
    }
  }

  return if !$self->message_is_useful_by_date($date);
  push(@{$self->{$class}}, index_pack($date, $class, "f", $mail));
}

sub scan_mailbox {
  my ($self, $class, $folder) = @_;
  my @files;

  if ($folder ne '-' && -d $folder) {
    # passed a directory of mboxes
    $folder =~ s/\/\s*$//; #Remove trailing slash, if there
    if (!opendir(DIR, $folder)) {
      warn "archive-iterator: can't open '$folder' dir: $!\n";
      $self->{access_problem} = 1;
      return;
    }

    while ($_ = readdir(DIR)) {
      if(/^[^\.]\S*$/ && ! -d "$folder/$_") {
	push(@files, "$folder/$_");
      }
    }
    closedir(DIR);
  }
  else {
    push(@files, $folder);
  }

  foreach my $file (@files) {
    $self->bump_scan_progress();
    if ($file =~ /\.(?:gz|bz2)$/) {
      warn "archive-iterator: compressed mbox folders are not supported at this time\n";
      $self->{access_problem} = 1;
      next;
    }

    my $info = {};
    my $count;

    $self->create_cache('mbox', $file);

    if ($self->{opt_cache}) {
      if ($count = $AICache->count()) {
        $info = $AICache->check();
      }
    }

    unless ($count) {
      if (!mail_open($file)) {
        $self->{access_problem} = 1;
	next;
      }

      my $start = 0;		# start of a message
      my $where = 0;		# current byte offset
      my $first = '';		# first line of message
      my $header = '';		# header text
      my $in_header = 0;		# are in we a header?
      while (!eof INPUT) {
        my $offset = $start;	# byte offset of this message
        my $header = $first;	# remember first line
        while (<INPUT>) {
	  if ($in_header) {
	    if (/^$/) {
	      $in_header = 0;
	    }
	    else {
	      $header .= $_;
	    }
	  }
	  if (substr($_,0,5) eq "From ") {
	    $in_header = 1;
	    $first = $_;
	    $start = $where;
	    $where = tell INPUT;
	    last;
	  }
	  $where = tell INPUT;
        }
        if ($header) {
          $self->bump_scan_progress();
	  $info->{$offset} = Mail::SpamAssassin::Util::receive_date($header);
	}
      }
      close INPUT;
    }

    while(my($k,$v) = each %{$info}) {
      if (defined $AICache && !$count) {
	$AICache->update($k, $v);
      }

      if ($self->{determine_receive_date}) {
        next if !$self->message_is_useful_by_date($v);
      }

      push(@{$self->{$class}}, index_pack($v, $class, "m", "$file.$k"));
    }

    if (defined $AICache) {
      $AICache = $AICache->finish();
    }
  }
}

sub scan_mbx {
  my ($self, $class, $folder) = @_;
  my (@files, $fp);

  if ($folder ne '-' && -d $folder) {
    # got passed a directory full of mbx folders.
    $folder =~ s/\/\s*$//; # remove trailing slash, if there is one
    if (!opendir(DIR, $folder)) {
      warn "archive-iterator: can't open '$folder' dir: $!\n";
      $self->{access_problem} = 1;
      return;
    }

    while ($_ = readdir(DIR)) {
      if(/^[^\.]\S*$/ && ! -d "$folder/$_") {
	push(@files, "$folder/$_");
      }
    }
    closedir(DIR);
  }
  else {
    push(@files, $folder);
  }

  foreach my $file (@files) {
    $self->bump_scan_progress();

    if ($folder =~ /\.(?:gz|bz2)$/) {
      warn "archive-iterator: compressed mbx folders are not supported at this time\n";
      $self->{access_problem} = 1;
      next;
    }

    my $info = {};
    my $count;

    $self->create_cache('mbx', $file);

    if ($self->{opt_cache}) {
      if ($count = $AICache->count()) {
        $info = $AICache->check();
      }
    }

    unless ($count) {
      if (!mail_open($file)) {
	$self->{access_problem} = 1;
        next;
      }

      # check the mailbox is in mbx format
      $fp = <INPUT>;
      if ($fp !~ /\*mbx\*/) {
        die "archive-iterator: error: mailbox not in mbx format!\n";
      }

      # skip mbx headers to the first email...
      seek(INPUT, 2048, 0);

      my $sep = MBX_SEPARATOR;

      while (<INPUT>) {
        if ($_ =~ /$sep/) {
	  my $offset = tell INPUT;
	  my $size = $2;

	  # gather up the headers...
	  my $header = '';
	  while (<INPUT>) {
	    last if (/^\s*$/);
	    $header .= $_;
	  }

          $self->bump_scan_progress();
	  $info->{$offset} = Mail::SpamAssassin::Util::receive_date($header);

	  # go onto the next message
	  seek(INPUT, $offset + $size, 0);
	}
        else {
	  die "archive-iterator: error: failure to read message body!\n";
        }
      }
      close INPUT;
    }

    while(my($k,$v) = each %{$info}) {
      if (defined $AICache && !$count) {
	$AICache->update($k, $v);
      }

      if ($self->{determine_receive_date}) {
        next if !$self->message_is_useful_by_date($v);
      }

      push(@{$self->{$class}}, index_pack($v, $class, "b", "$file.$k"));
    }

    if (defined $AICache) {
      $AICache = $AICache->finish();
    }
  }
}

############################################################################

sub bump_scan_progress {
  my ($self) = @_;
  if (exists $self->{scan_progress_sub}) {
    return unless ($self->{scan_progress_counter}++ % 50 == 0);
    $self->{scan_progress_sub}->();
  }
}

############################################################################

{
  my $home;

  sub fix_globs {
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

sub min {
  return ($_[0] < $_[1] ? $_[0] : $_[1]);
}

sub create_cache {
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

C<Mail::SpamAssassin>
C<spamassassin>
C<mass-check>

=cut

# vim: ts=8 sw=2 et
