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

    my $t = Mail::SpamAssassin::Timeout->new({ secs => 5 });
    
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

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

=item my $t = Mail::SpamAssassin::Timeout->new({ ... options ... });

Constructor.  Options include:

=over 4

=item secs => $seconds

timeout, in seconds.  Optional; if not specified, no timeouts will be applied.

=back

=cut

sub new {
  my ($class, $opts) = @_;
  $class = ref($class) || $class;
  my %selfval = $opts ? %{$opts} : ();
  my $self = \%selfval;

  bless ($self, $class);
  $self;
}

###########################################################################

=item $t->run($coderef)

Run a code reference within the currently-defined timeout.

The timeout is as defined by the B<secs> parameter to the constructor.

Returns whatever the subroutine returns, or C<undef> on timeout.
If the timer times out, C<$t-<gt>timed_out()> will return C<1>.

Time elapsed is not cumulative; multiple runs of C<run> will restart the
timeout from scratch.

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

  if (!$self->{secs}) { # no timeout!  just call the sub and return.
    return &$sub;
  }

  # assertion
  if ($self->{secs} < 0) {
    die "Mail::SpamAssassin::Timeout: oops? neg value for 'secs': $self->{secs}";
  }

  my $oldalarm = 0;
  my $ret;

  # bug 4699: under heavy load, an alarm may fire while $@ will contain "",
  # which isn't very useful.  this counter works around it safely, since
  # it will not require malloc() be called if it fires
  my $timedout = 0;

  eval {
    # note use of local to ensure closed scope here
    local $SIG{ALRM} = sub { $timedout++; die "__alarm__ignore__\n" };
    local $SIG{__DIE__};   # bug 4631

    $oldalarm = alarm($self->{secs});

    $ret = &$sub;

    # Unset the alarm() before we leave eval{ } scope, as that stack-pop
    # operation can take a second or two under load. Note: previous versions
    # restored $oldalarm here; however, that is NOT what we want to do, since
    # it creates a new race condition, namely that an old alarm could then fire
    # while the stack-pop was underway, thereby appearing to be *this* timeout
    # timing out. In terms of how we might possibly have nested timeouts in
    # SpamAssassin, this is an academic issue with little impact, but it's
    # still worth avoiding anyway.

    alarm 0;
  };

  my $err = $@;

  if (defined $oldalarm) {
    # now, we could have died from a SIGALRM == timed out.  if so,
    # restore the previously-active one, or zero all timeouts if none
    # were previously active.
    alarm $oldalarm;
  }

  if ($err) {
    if ($err =~ /__alarm__ignore__/) {
      $self->{timed_out} = 1;
    } else {
      if ($and_catch) {
        return $@;
      } else {
        die $@;             # propagate any "real" errors
      }
    }
  } elsif ($timedout) {
    # this happens occasionally; haven't figured out why.  seems
    # harmless in effect, though, so just issue a warning and carry on...
    warn "timeout with empty \$@";  
    $self->{timed_out} = 1;
  }

  if ($and_catch) {
    return;                 # undef
  } else {
    return $ret;
  }
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
  alarm($self->{secs});
}

###########################################################################

1;
