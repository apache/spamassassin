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

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

our @ISA = qw();

#############################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    main                => $main,
    last_count          => 0,
    times_count_was_same => 0,
    queries_started     => 0,
    queries_completed   => 0,
    pending_lookups     => { }
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

A code reference, which will be called when the lookup has been reported as
complete via C<set_response_packet()> or C<report_id_complete()>.

The code reference will be called with one argument, the C<$ent> object.

=back

C<$obj> is returned by this method.

=cut

sub start_lookup {
  my ($self, $ent) = @_;

  die "oops, no id"  unless $ent->{id};
  die "oops, no key" unless $ent->{key};
  die "oops, no type" unless $ent->{type};

  $self->{queries_started}++;
  $self->{pending_lookups}->{$ent->{key}} = $ent;
  $self->{last_start_lookup_time} = time;
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

=item $alldone = $async->complete_lookups()

Perform a poll of the pending lookups, to see if any are completed; if they
are, their <completed_callback> is called with the entry object for that
lookup.

If there are no lookups remaining, or if too long has elapsed since any results
were returned, C<1> is returned, otherwise C<0>.

=cut

sub complete_lookups {
  my ($self, $timeout) = @_;
  my %typecount = ();
  my $stillwaiting = 0;

  my $pending = $self->{pending_lookups};
  if (scalar keys %{$pending} <= 0) {
    return 1;           # nothing left to do
  }

  $self->{queries_started} = 0;
  $self->{queries_completed} = 0;

  # trap this loop in an eval { } block, as Net::DNS could throw
  # die()s our way; in particular, process_dnsbl_results() has
  # thrown die()s before (bug 3794).
  eval {

    my $nfound = $self->{main}->{resolver}->poll_responses($timeout);
    $nfound ||= 'no';
    dbg ("async: select found $nfound socks ready");

    foreach my $key (keys %{$pending}) {
      my $ent = $pending->{$key};

      # call a "poll_callback" sub, if one exists
      if (defined $ent->{poll_callback}) {
        $ent->{poll_callback}->($ent);
      }

      my $type = $ent->{type};
      if (!exists ($self->{finished}->{$ent->{id}})) {
        $typecount{$type}++;
        next;
      }

      $ent->{response_packet} = delete $self->{finished}->{$ent->{id}};
      if (defined $ent->{completed_callback}) {
        $ent->{completed_callback}->($ent);
      }

      $self->{queries_completed}++;
      delete $self->{pending_lookups}->{$key};
    }

    dbg("async: queries completed: ".$self->{queries_completed}.
                  " started: ".$self->{queries_started});

    if (1) {
      dbg("async: queries active: ".
          join (' ', map { "$_=$typecount{$_}" } sort keys %typecount)." at ".
          localtime(time));
    }

    # ensure we don't get stuck if a request gets lost in the ether.
    if (!$stillwaiting) {
      my $numkeys = scalar keys %{$self->{pending_lookups}};
      if ($numkeys == 0) {
        $stillwaiting = 0;

      } else {
        $stillwaiting = 1;

        # avoid looping forever if we haven't got all results.
        if ($self->{last_count} == $numkeys) {
          $self->{times_count_was_same}++;
          if ($self->{times_count_was_same} > 20)
          {
            dbg("async: escaping: must have lost requests");
            $self->abort_remaining_lookups();
            $stillwaiting = 0;
          }
        } else {
          $self->{last_count} = $numkeys;
          $self->{times_count_was_same} = 0;
        }
      }
    }

  };

  if ($@) {
    dbg("async: caught complete_lookups death, aborting: $@");
    $stillwaiting = 0;      # abort remaining
  }

  return (!$stillwaiting);
}

# ---------------------------------------------------------------------------

=item $async->abort_remaining_lookups()

Abort any remaining lookups.

=cut

sub abort_remaining_lookups {
  my ($self) = @_;

  my $pending = $self->{pending_lookups};
  my $foundone = 0;
  foreach my $key (keys %{$pending})
  {
    if (!$foundone) {
      dbg("async: aborting remaining lookups");
      $foundone = 1;
    }

    delete $pending->{$key};
  }
  delete $self->{last_start_lookup_time};
  $self->{main}->{resolver}->bgabort();
}

# ---------------------------------------------------------------------------

=item $async->set_response_packet($id, $pkt)

Register a "response packet" for a given query.  C<$id> is the ID for the
query, and must match the C<id> supplied in C<start_lookup()>. C<$pkt> is the
packet object for the response.

If this was called, C<$pkt> will be available in the C<completed_callback>
function as C<$ent-<gt>{response_packet}>.

One or the other of C<set_response_packet()> or C<report_id_complete()>
should be called, but not both.

=cut

sub set_response_packet {
  my ($self, $id, $pkt) = @_;
  $self->{finished}->{$id} = $pkt;
}

=item $async->report_id_complete($id)

Register that a query has completed, and is no longer "pending". C<$id> is the
ID for the query, and must match the C<id> supplied in C<start_lookup()>.

One or the other of C<set_response_packet()> or C<report_id_complete()>
should be called, but not both.

=cut

sub report_id_complete {
  my ($self, $id) = @_;
  $self->{finished}->{$id} = undef;
}

# ---------------------------------------------------------------------------

=item $time = $async->get_last_start_lookup_time()

Get the time of the last call to C<start_lookup()>.  If C<start_lookup()> was
never called or C<abort_remaining_lookups()> has been called
C<get_last_start_lookup_time()> will return undef.

=cut

sub get_last_start_lookup_time {
  my ($self) = @_;
  return $self->{last_start_lookup_time};
}  

# ---------------------------------------------------------------------------

1;

=back

=cut
