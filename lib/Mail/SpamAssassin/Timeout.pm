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

Mail::SpamAssassin::Timeout - safe, reliable timeouts in perl

=head1 SYNOPSIS

    # non-timeout code...

    my $t = Mail::SpamAssassin::Timeout->new({ secs => 5, deadline => $when });
    
    $t->run(sub {
        # code to run with a 5-second timeout...
    });

    if ($t->timed_out()) {
        # do something...
    }

    # more non-timeout code...

=head1 DESCRIPTION

This module provides a safe, reliable and clean API to provide
C<alarm(2)>-based timeouts for perl code.

Note that C<$SIG{ALRM}> is used to provide the timeout, so this will not
interrupt out-of-control regular expression matches.

Nested timeouts are supported.

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::Timeout;

use strict;
use warnings;
use bytes;
use re 'taint';

use Time::HiRes qw(time);

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

=item my $t = Mail::SpamAssassin::Timeout->new({ ... options ... });

Constructor.  Options include:

=over 4

=item secs => $seconds

time interval, in seconds. Optional; if neither C<secs> nor C<deadline> is
specified, no timeouts will be applied.

=item deadline => $unix_timestamp

Unix timestamp (time in seconds since epoch) when a timeout is reached.
Optional; if neither B<secs> nor B<deadline> is specified, no timeouts will
be applied. If both are specified, the shorter interval of the two prevails.

=back

=cut

use vars qw($id_gen);
BEGIN { $id_gen = 0 }  # unique generator of IDs for timer objects

sub new {
  my ($class, $opts) = @_;
  $class = ref($class) || $class;
  my %selfval = $opts ? %{$opts} : ();
  $selfval{id} = ++$id_gen;
  my $self = \%selfval;

  bless ($self, $class);
  $self;
}

###########################################################################

=item $t->run($coderef)

Run a code reference within the currently-defined timeout.

The timeout is as defined by the B<secs> and B<deadline> parameters
to the constructor.

Returns whatever the subroutine returns, or C<undef> on timeout.
If the timer times out, C<$t-<gt>timed_out()> will return C<1>.

Time elapsed is not cumulative; multiple runs of C<run> will restart the
timeout from scratch. On the other hand, nested timers do observe outer
timeouts if they are shorter, resignalling a timeout to the level which
established them, i.e. code running under an inner timer can not exceed
the time limit established by an outer timer. When restarting an outer
timer the elapsed time of a running code is taken into account.

=item $t->run_and_catch($coderef)

Run a code reference, as per C<$t-<gt>run()>, but also catching any
C<die()> calls within the code reference.

Returns C<undef> if no C<die()> call was executed and C<$@> was unset, or the
value of C<$@> if it was set.  (The timeout event doesn't count as a C<die()>.)

=cut

sub run { $_[0]->_run($_[1], 0); }

sub run_and_catch { $_[0]->_run($_[1], 1); }

sub _run {      # private
  my ($self, $sub, $and_catch) = @_;

  delete $self->{timed_out};

  my $secs = $self->{secs};
  my $deadline = $self->{deadline};

  # assertion
  if (defined $secs && $secs < 0) {
    die "Mail::SpamAssassin::Timeout: oops? neg value for 'secs': $secs";
  }

  if (defined $deadline) {
    my $dt = $deadline - time;
    $secs = $dt  if !defined $secs || $dt < $secs;
  }

  if (!defined $secs) {  # no timeout!  just call the sub and return.
    return &$sub;
  }

  my $id = $self->{id};
  my $ret;
  my $oldalarm = alarm(0);  # remaining time, 0 when disarmed, undef on error
  my $start_time = time;

  # bug 4699: under heavy load, an alarm may fire while $@ will contain "",
  # which isn't very useful.  this flag works around it safely, since
  # it will not require malloc() be called if it fires
  my $timedout = 0;

  my $eval_stat;
  eval {
    if ($secs <= 0) {
      die "__alarm__ignore__($id) (pre-expired)\n";

    } elsif ($oldalarm && $oldalarm < $secs) {
      # just restore outer timer, a timeout signal will be handled there
      alarm($oldalarm);
      $ret = &$sub;

    } else {
      # note use of local to ensure closed scope here
      local $SIG{ALRM} = sub { $timedout = 1;  die "__alarm__ignore__($id)\n" };
      local $SIG{__DIE__};   # bug 4631

      my $isecs = int($secs);
      $isecs++  if $secs > int($isecs);  # ceiling
      alarm($isecs);
      $ret = &$sub;
    }

    # Unset the alarm() before we leave eval{ } scope, as that stack-pop
    # operation can take a second or two under load. Note: previous versions
    # restored $oldalarm here; however, that is NOT what we want to do, since
    # it creates a new race condition, namely that an old alarm could then fire
    # while the stack-pop was underway, thereby appearing to be *this* timeout
    # timing out. In terms of how we might possibly have nested timeouts in
    # SpamAssassin, this is an academic issue with little impact, but it's
    # still worth avoiding anyway.
    #
    alarm(0);  # disarm

    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    alarm(0);  # in case we popped out for some other reason
  };

  # catch timedout  return:
  #    0    0       $ret
  #    0    1       undef
  #    1    0       $eval_stat
  #    1    1       undef
  #
  my $return = $and_catch ? $eval_stat : $ret;

  if (defined $eval_stat) {
    if ($eval_stat =~ /__alarm__ignore__\Q($id)\E/) {
      undef $return;  $self->{timed_out} = 1;
    }
  } elsif ($timedout) {
    # this happens occasionally; haven't figured out why.  seems
    # harmless in effect, though, so just issue a warning and carry on...
    warn "timeout with empty eval status\n";
    undef $return;  $self->{timed_out} = 1;
  }

  my $remaining_time;
  if ($oldalarm) {
    $remaining_time = $start_time + $oldalarm - time;
    if ($remaining_time > 0) {  # still in the future
      # restore the previously-active alarm,
      # taking into account the elapsed time we spent here
      my $iremaining_time = int($remaining_time);
      $iremaining_time++  if $remaining_time > int($remaining_time); # ceiling
      alarm($iremaining_time);
      undef $remaining_time;  # already taken care of
    }
  }
  if (!$and_catch && defined $eval_stat &&
      $eval_stat !~ /__alarm__ignore__\Q($id)\E/) {
    # propagate "real" errors or outer timeouts
    die "Timeout::_run: $eval_stat\n";
  }
  if (defined $remaining_time) {
    kill('ALRM',0);  # previous timer expired meanwhile, re-signal right away
  }
  return $return;
}

###########################################################################

=item $t->timed_out()

Returns C<1> if the most recent code executed in C<run()> timed out, or
C<undef> if it did not.

=cut

sub timed_out {
  my ($self) = @_;
  return $self->{timed_out};
}

###########################################################################

=item $t->reset()

If called within a C<run()> code reference, causes the current alarm timer to
be reset to its starting value.

=cut

sub reset {
  my ($self) = @_;

  my $secs = $self->{secs};
  my $deadline = $self->{deadline};

  if (defined $deadline) {
    my $dt = $deadline - time;
    $secs = $dt  if !defined $secs || $dt < $secs;
  }

  if (!defined $secs) {
    # not timed
  } elsif ($secs > 0) {
    my $isecs = int($secs);
    $isecs++  if $secs > int($isecs);  # ceiling
    alarm($isecs);
  } else {
    kill('ALRM',0);  # previous timer expired meanwhile, re-signal right away
  }
}

###########################################################################

1;
