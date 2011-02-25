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
use Mail::SpamAssassin::Logger;

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

Unix timestamp (seconds since epoch) when a timeout is reached in the latest.
Optional; if neither B<secs> nor B<deadline> is specified, no timeouts will
be applied. If both are specified, the shorter interval of the two prevails.

=back

=cut

use vars qw($id_gen);
BEGIN { $id_gen = 0 }  # unique generator of IDs for timer objects
use vars qw(@expiration);  # stack of expected expiration times, top at [0]

sub new {
  my ($class, $opts) = @_;
  $class = ref($class) || $class;
  my %selfval = $opts ? %{$opts} : ();
  $selfval{id} = ++$id_gen;
  my($package, $filename, $line, $subroutine) = caller(1);
  if (defined $subroutine) {
    $subroutine =~ s/^Mail::SpamAssassin::/::/;
    $selfval{id} = join('/', $id_gen, $subroutine, $line);
  }
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
timer on return, elapsed time of a running code is taken into account.

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

  my $id = $self->{id};
  my $secs = $self->{secs};
  my $deadline = $self->{deadline};
  my $alarm_tinkered_with = 0;
# dbg("timed: %s run", $id);

  # assertion
  if (defined $secs && $secs < 0) {
    die "Mail::SpamAssassin::Timeout: oops? neg value for 'secs': $secs";
  }

  my $start_time = time;
  if (defined $deadline) {
    my $dt = $deadline - $start_time;
    $secs = $dt  if !defined $secs || $dt < $secs;
  }

  # bug 4699: under heavy load, an alarm may fire while $@ will contain "",
  # which isn't very useful.  this flag works around it safely, since
  # it will not require malloc() be called if it fires
  my $timedout = 0;

  my($oldalarm, $handler);
  if (defined $secs) {
    # stop the timer, collect remaining time
    $oldalarm = alarm(0);  # 0 when disarmed, undef on error
    $alarm_tinkered_with = 1;
    if (!@expiration) {
    # dbg("timed: %s no timer in evidence", $id);
    # dbg("timed: %s actual timer was running, time left %.3f s",
    #     $id, $oldalarm)  if $oldalarm;
    } elsif (!defined $expiration[0]) {
    # dbg("timed: %s timer not running according to evidence", $id);
    # dbg("timed: %s actual timer was running, time left %.3f s",
    #      $id, $oldalarm)  if $oldalarm;
    } else {
      my $oldalarm2 = $expiration[0] - $start_time;
    # dbg("timed: %s stopping timer, time left %.3f s%s", $id, $oldalarm2,
    #     !$oldalarm ? '' : sprintf(", reported as %.3f s", $oldalarm));
      $oldalarm = $oldalarm2 < 1 ? 1 : $oldalarm2;
    }
    $self->{end_time} = $start_time + $secs;  # needed by reset()
    $handler = sub { $timedout = 1; die "__alarm__ignore__($id)\n" };
  }

  my($ret, $eval_stat);
  unshift(@expiration, undef);
  eval {
    local $SIG{__DIE__};   # bug 4631

    if (!defined $secs) {  # no timeout specified, just call the sub 
      $ret = &$sub;

    } elsif ($secs <= 0) {
      $self->{timed_out} = 1;
      &$handler;

    } elsif ($oldalarm && $oldalarm < $secs) {  # run under an outer timer
      # just restore outer timer, a timeout signal will be handled there
    # dbg("timed: %s alarm(%.3f) - outer", $id, $oldalarm);
      $expiration[0] = $start_time + $oldalarm;
      alarm($oldalarm); $alarm_tinkered_with = 1;
      $ret = &$sub;
    # dbg("timed: %s post-sub(outer)", $id);

    } else {  # run under a timer specified with this call
      local $SIG{ALRM} = $handler;  # ensure closed scope here
      my $isecs = int($secs);
      $isecs++  if $secs > int($isecs);  # ceiling
    # dbg("timed: %s alarm(%d)", $id, $isecs);
      $expiration[0] = $start_time + $isecs;
      alarm($isecs); $alarm_tinkered_with = 1;
      $ret = &$sub;
    # dbg("timed: %s post-sub", $id);
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
    alarm(0)  if $alarm_tinkered_with;  # disarm

    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # just in case we popped out for some other reason
    alarm(0)  if $alarm_tinkered_with;  # disarm
  };

  delete $self->{end_time};  # reset() is only applicable within a &$sub

  # catch timedout  return:
  #    0    0       $ret
  #    0    1       undef
  #    1    0       $eval_stat
  #    1    1       undef
  #
  my $return = $and_catch ? $eval_stat : $ret;

  if (defined $eval_stat && $eval_stat =~ /__alarm__ignore__\Q($id)\E/) {
    $self->{timed_out} = 1;
  # dbg("timed: %s cought: %s", $id, $eval_stat);
  } elsif ($timedout) {
    # this happens occasionally; haven't figured out why. seems harmless
  # dbg("timed: %s timeout with empty eval status", $id);
    $self->{timed_out} = 1;
  }

  shift(@expiration);  # pop off the stack

  # covers all cases, including where $self->{timed_out} is flagged by reset()
  undef $return  if $self->{timed_out};

  my $remaining_time;
  # restore previous timer if necessary
  if ($oldalarm) {  # an outer alarm was already active when we were called
    $remaining_time = $start_time + $oldalarm - time;
    if ($remaining_time > 0) {  # still in the future
      # restore the previously-active alarm,
      # taking into account the elapsed time we spent here
      my $iremaining_time = int($remaining_time);
      $iremaining_time++  if $remaining_time > int($remaining_time); # ceiling
    # dbg("timed: %s restoring outer alarm(%.3f)", $id, $iremaining_time);
      alarm($iremaining_time); $alarm_tinkered_with = 1;
      undef $remaining_time;  # already taken care of
    }
  }
  if (!$and_catch && defined $eval_stat &&
      $eval_stat !~ /__alarm__ignore__\Q($id)\E/) {
    # propagate "real" errors or outer timeouts
    die "Timeout::_run: $eval_stat\n";
  }
  if (defined $remaining_time) {
  # dbg("timed: %s outer timer expired %.3f s ago", $id, -$remaining_time);
    # mercifully grant two additional seconds
    alarm(2); $alarm_tinkered_with = 1;
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

If called within a C<run()> code reference, causes the current alarm timer
to be restored to its original setting (useful after our alarm setting was
clobbered by some underlying module).

=back

=cut

sub reset {
  my ($self) = @_;

  my $id = $self->{id};
# dbg("timed: %s reset", $id);
  return if !defined $self->{end_time};

  my $secs = $self->{end_time} - time;
  if ($secs > 0) {
    my $isecs = int($secs);
    $isecs++  if $secs > int($isecs);  # ceiling
  # dbg("timed: %s reset: alarm(%.3f)", $self->{id}, $isecs);
    alarm($isecs);
  } else {
    $self->{timed_out} = 1;
  # dbg("timed: %s reset, timer expired %.3f s ago", $id, -$secs);
    alarm(2);  # mercifully grant two additional seconds
  }
}

###########################################################################

1;
