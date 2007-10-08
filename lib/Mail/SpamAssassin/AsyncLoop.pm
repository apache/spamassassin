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

Mail::SpamAssassin::AsyncLoop - scanner asynchronous event loop

=head1 DESCRIPTION

An asynchronous event loop used for long-running operations, performed "in the
background" during the Mail::SpamAssassin::check() scan operation, such as DNS
blocklist lookups.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::AsyncLoop;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

our @ISA = qw();

# Load Time::HiRes if it's available
BEGIN {
  eval { require Time::HiRes };
  Time::HiRes->import( qw(time) ) unless $@;
}

#############################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    main                => $main,
    queries_started     => 0,
    queries_completed   => 0,
    total_queries_started   => 0,
    total_queries_completed => 0,
    pending_lookups     => { },
    timing_by_query     => { },
  };

  bless ($self, $class);
  $self;
}

# ---------------------------------------------------------------------------

=item $obj = $async->start_lookup($obj)

Register the start of a long-running asynchronous lookup operation. C<$obj>
is a hash reference containing the following items:

=over 4

=item key (required)

A key string, unique to this lookup.  This is what is reported in
debug messages, used as the key for C<get_lookup()>, etc.

=item id (required)

An ID string, also unique to this lookup.  Typically, this is the DNS packet ID
as returned by DnsResolver's C<bgsend> method.  Sadly, the Net::DNS
architecture forces us to keep a separate ID string for this task instead of
reusing C<key> -- if you are not using DNS lookups through DnsResolver, it
should be OK to just reuse C<key>.

=item type (required)

A string, typically one word, used to describe the type of lookup in log
messages, such as C<DNSBL>, C<MX>, C<TXT>.

=item poll_callback (optional)

A code reference, which will be called periodically during the
background-processing period.  If you will be performing an async lookup on a
non-DNS-based service, you will need to implement this so that it checks for
new responses and calls C<set_response_packet()> or C<report_id_complete()> as
appropriate.   DNS-based lookups can leave it undefined, since
DnsResolver::poll_responses() will be called automatically anyway.

The code reference will be called with one argument, the C<$ent> object.

=item completed_callback (optional)

A code reference which will be called when an asynchronous task (e.g. a
DNS lookup) is completed, either normally, or aborted, e.g. by a timeout.

When a task has been reported as completed via C<set_response_packet()>
the response (as provided to C<set_response_packet()>) is stored in
$ent->{response_packet} (possibly undef, its semantics is defined by the
caller). When completion is reported via C<report_id_complete()> or a
task was aborted, the $ent->{response_packet} is guaranteed to be undef.
If it is necessary to distinguish between the last two cases, the
$ent->{status} may be examined for a string 'ABORTING' or 'FINISHED'.

The code reference will be called with one argument, the C<$ent> object.

=back

C<$obj> is returned by this method.

=cut

sub start_lookup {
  my ($self, $ent) = @_;

  die "oops, no id"   unless $ent->{id}   ne '';
  die "oops, no key"  unless $ent->{key}  ne '';
  die "oops, no type" unless $ent->{type} ne '';

  my $now = time;
  my $key = $ent->{key};
  my $id  = $ent->{id};
  $ent->{status} = 'STARTED';
  $ent->{start_time} = $now  if !defined $ent->{start_time};
  $ent->{timeout} =
    $self->{main}->{conf}->{rbl_timeout}  if !defined $ent->{timeout};
  $ent->{display_id} =  # identifies entry in debug logging and similar
    join(", ", grep { defined }
               map { ref $ent->{$_} ? @{$ent->{$_}} : $ent->{$_} }
               qw(sets rules rulename type key) );

  $self->{queries_started}++;
  $self->{total_queries_started}++;
  $self->{pending_lookups}->{$key} = $ent;

  dbg("async: starting: %s (timeout %.1f s)",
      $ent->{display_id}, $ent->{timeout});
  $ent;
}

# ---------------------------------------------------------------------------

=item $obj = $async->get_lookup($key)

Retrieve the pending-lookup object for the given key C<$key>.

If the lookup is complete, this will return C<undef>.

Note that a lookup is still considered "pending" until C<complete_lookups()> is
called, even if it has been reported as complete via C<set_response_packet()>
or C<report_id_complete()>.

=cut

sub get_lookup {
  my ($self, $key) = @_;
  return $self->{pending_lookups}->{$key};
}

# ---------------------------------------------------------------------------

=item @objs = $async->get_pending_lookups()

Retrieve the lookup objects for all pending lookups.

Note that a lookup is still considered "pending" until C<complete_lookups()> is
called, even if it has been reported as complete via C<set_response_packet()>
or C<report_id_complete()>.

=cut

sub get_pending_lookups {
  my ($self) = @_;
  return values %{$self->{pending_lookups}};
}

# ---------------------------------------------------------------------------

=item $async->log_lookups_timing()

Log sorted timing for all completed lookups.

=cut

sub log_lookups_timing {
  my ($self) = @_;
  my $timings = $self->{timing_by_query};
  for my $key (sort { $timings->{$a} <=> $timings->{$b} } keys %$timings) {
    dbg("async: timing: %.3f %s", $timings->{$key}, $key);
  }
}

# ---------------------------------------------------------------------------

=item $alldone = $async->complete_lookups()

Perform a poll of the pending lookups, to see if any are completed; if they
are, their <completed_callback> is called with the entry object for that
lookup.

If there are no lookups remaining, or if too long has elapsed since any results
were returned, C<1> is returned, otherwise C<0>.

=cut

sub complete_lookups {
  my ($self, $timeout, $allow_aborting_of_expired) = @_;
  my $alldone = 0;
  my $anydone = 0;
  my $allexpired = 1;
  my %typecount;

  my $pending = $self->{pending_lookups};
  $self->{queries_started} = 0;
  $self->{queries_completed} = 0;

  my $now = time;

  if (defined $timeout && $timeout > 0 &&
      %$pending && $self->{total_queries_started} > 0)
  {
    # shrink 'select' timeout if a caller specified unnecessarily long
    # value, beyond the latest deadline of any outstanding request;
    # can save needless wait time (up to 1 second in harvest_dnsbl_queries)
    my $timeout_shrink_factor =
           1 - 0.7 * ( ($self->{total_queries_completed} /
                        $self->{total_queries_started}) ** 2 );
    my $max_deadline;
    while (my($key,$ent) = each %$pending) {
      my $dt = $ent->{timeout};
      if ($dt > 1.0) {  # only allow shrinking of timeouts over 1 second
        $dt *= $timeout_shrink_factor;
        $dt = 1.0  if $dt < 1.0;  # don't shrink below 1 second
      }
      my $deadline = $ent->{start_time} + $dt;
      if (!defined $max_deadline || $deadline > $max_deadline) {
        $max_deadline = $deadline;
      }
    }
    my $sufficient_timeout = $max_deadline - $now;
    $sufficient_timeout = 0  if $sufficient_timeout < 0;
    if (defined $max_deadline && $timeout > $sufficient_timeout) {
      dbg("async: reducing select timeout from %.1f to %.1f s",
          $timeout, $sufficient_timeout);
      $timeout = $sufficient_timeout;
    }
  }

  # trap this loop in an eval { } block, as Net::DNS could throw
  # die()s our way; in particular, process_dnsbl_results() has
  # thrown die()s before (bug 3794).
  eval {

    if (%$pending) {  # any outstanding requests still?
      $self->{last_poll_responses_time} = $now;
      my $nfound = $self->{main}->{resolver}->poll_responses($timeout);
      dbg("async: select found %s responses ready (t.o.=%.1f)",
          !$nfound ? 'no' : $nfound,  $timeout);
    }
    $now = time;  # capture new timestamp, after possible sleep in 'select'

    while (my($key,$ent) = each %$pending) {
      my $id = $ent->{id};
      my $finished = exists $self->{finished}->{$id};
      if ($finished) {
        $anydone = 1;
        delete $self->{finished}->{$id};
        $ent->{status} = 'FINISHED';
        $ent->{finish_time} = $now  if !defined $ent->{finish_time};
      }
      # call a "poll_callback" sub, if one exists
      if (defined $ent->{poll_callback}) {
        $ent->{poll_callback}->($ent);
      }
      if ($finished) {
        my $elapsed = $ent->{finish_time} - $ent->{start_time};
        dbg("async: completed in %.3f s: %s", $elapsed, $ent->{display_id});

        # call a "completed_callback" sub, if one exists
        if (defined $ent->{completed_callback}) {
          $ent->{completed_callback}->($ent);
        }
        $self->{timing_by_query}->{". $key"} += $elapsed;
        $self->{queries_completed}++;
        $self->{total_queries_completed}++;
        delete $pending->{$key};
      }
    }

    if (%$pending) {  # still any requests outstanding? are they expired?
      my $timeout_shrink_factor =
        !$allow_aborting_of_expired || !$self->{total_queries_started} ? 1.0
          :  1 - 0.7 * ( ($self->{total_queries_completed} /
                          $self->{total_queries_started}) ** 2 );
      dbg("async: timeout shrink factor: %.2f",
          $timeout_shrink_factor)  if $timeout_shrink_factor != 1;

      while (my($key,$ent) = each %$pending) {
        $typecount{$ent->{type}}++;
        my $dt = $ent->{timeout};
        if ($dt > 1.0) {  # only allow shrinking of timeouts over 1 second
          $dt *= $timeout_shrink_factor;
          $dt = 1.0  if $dt < 1.0;  # don't shrink below 1 second
        }
        $allexpired = 0  if $now <= $ent->{start_time} + $dt;
      }
      dbg("async: queries completed: %d, started: %d",
          $self->{queries_completed}, $self->{queries_started});
    }

    # ensure we don't get stuck if a request gets lost in the ether.
    if (! %$pending) {
      $alldone = 1;
    }
    elsif ($allexpired && $allow_aborting_of_expired) {
      # avoid looping forever if we haven't got all results.
      dbg("async: escaping: lost or timed out requests or responses");
      $self->abort_remaining_lookups();
      $alldone = 1;
    }
    else {
      dbg("async: queries active: %s%s at %s",
          join (' ', map { "$_=$typecount{$_}" } sort keys %typecount),
          $allexpired ? ', all expired' : '', scalar(localtime(time)));
      $alldone = 0;
    }
    1;

  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("async: caught complete_lookups death, aborting: %s", $eval_stat);
    $alldone = 1;      # abort remaining
  };

  return wantarray ? ($alldone,$anydone) : $alldone;
}

# ---------------------------------------------------------------------------

=item $async->abort_remaining_lookups()

Abort any remaining lookups.

=cut

sub abort_remaining_lookups {
  my ($self) = @_;

  my $pending = $self->{pending_lookups};
  my $foundcnt = 0;
  my $now = time;
  while (my($key,$ent) = each %$pending) {
    dbg("async: aborting after %.3f s, %s: %s",
        $now - $ent->{start_time},
        defined $ent->{timeout} && $now > $ent->{start_time} + $ent->{timeout}
          ? 'past original deadline' : 'deadline shrunk',
        $ent->{display_id} );
    $foundcnt++;
    $self->{timing_by_query}->{"X $key"} = $now - $ent->{start_time};

    if (defined $ent->{completed_callback}) {
      $ent->{finish_time} = $now  if !defined $ent->{finish_time};
      $ent->{response_packet} = undef;
      $ent->{status} = 'ABORTING';
      $ent->{completed_callback}->($ent);
    }
    delete $pending->{$key};
  }
  dbg("async: aborted %d remaining lookups", $foundcnt)  if $foundcnt > 0;
  delete $self->{last_poll_responses_time};
  $self->{main}->{resolver}->bgabort();
  1;
}

# ---------------------------------------------------------------------------

=item $async->set_response_packet($id, $pkt, $key, $timestamp)

Register a "response packet" for a given query.  C<$id> is the ID for the
query, and must match the C<id> supplied in C<start_lookup()>. C<$pkt> is the
packet object for the response. A parameter C<$key> identifies an entry in a
hash %{$self->{pending_lookups}} where the object which spawned this query can
be found, and through which futher information about the query is accessible.

If this was called, C<$pkt> will be available in the C<completed_callback>
function as C<$ent-<gt>{response_packet}>.

One or the other of C<set_response_packet()> or C<report_id_complete()>
should be called, but not both.

=cut

sub set_response_packet {
  my ($self, $id, $pkt, $key, $timestamp) = @_;
  $self->{finished}->{$id} = 1;  # only key existence matters, any value
  $timestamp = time  if !defined $timestamp;
  my $pending = $self->{pending_lookups};
  if (!defined $key) {  # backwards compatibility with 3.2.3 and older plugins
    # a third-party plugin did not provide $key in a call, search for it:
    if ($id eq $pending->{$id}->{id}) {  # I feel lucky, key==id ?
      $key = $id;
    } else {  # then again, maybe not, be more systematic
      for my $tkey (keys %$pending) {
        if ($id eq $pending->{$tkey}->{id}) { $key = $tkey; last }
      }
    }
    dbg("async: searching for lookup with id $id, found $key");
  }
  if (!defined $key) {
    info("async: no key, response packet not remembered, id $id");
  } else {
    my $ent = $pending->{$key};
    if ($id ne $ent->{id}) {
      info("async: ignoring response, mismatched id $id, $ent->{id}");
    } else {
      $ent->{finish_time} = $timestamp;
      $ent->{response_packet} = $pkt;
    }
  }
  1;
}

=item $async->report_id_complete($id,$key,$key,$timestamp)

Register that a query has completed, and is no longer "pending". C<$id> is the
ID for the query, and must match the C<id> supplied in C<start_lookup()>.

One or the other of C<set_response_packet()> or C<report_id_complete()>
should be called, but not both.

=cut

sub report_id_complete {
  my ($self, $id, $key, $timestamp) = @_;
  $self->set_response_packet($id, undef, $key, $timestamp);
}

# ---------------------------------------------------------------------------

=item $time = $async->last_poll_responses_time()

Get the time of the last call to C<poll_responses()> (which is called
from C<complete_lookups()>.  If C<poll_responses()> was never called or
C<abort_remaining_lookups()> has been called C<last_poll_responses_time()>
will return undef.

=cut

sub last_poll_responses_time {
  my ($self) = @_;
  return $self->{last_poll_responses_time};
}  

1;

=back

=cut
