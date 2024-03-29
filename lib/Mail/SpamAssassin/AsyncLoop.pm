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
# use bytes;
use re 'taint';

use Time::HiRes qw(time);

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(idn_to_ascii domain_to_search_list);

our @ISA = qw();

# obtain timer resolution if possible
our $timer_resolution;
BEGIN {
  eval {
    $timer_resolution = Time::HiRes->can('clock_getres')
      ? Time::HiRes::clock_getres(Time::HiRes::CLOCK_REALTIME())
      : 0.001;  # wild guess, assume resolution is better than 1s
    1;
  } or do {
    $timer_resolution = 1;  # Perl's builtin timer ticks at one second
  };
}

#############################################################################

sub new {
  # called from PerMsgStatus, a new AsyncLoop object is created
  # for each new message processing
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    main                => $main,
    queries_started     => 0,
    queries_completed   => 0,
    pending_lookups     => { },
    pending_rules	=> { },  # maintain pending rules list for meta evaluation
    rules_for_key	=> { },  # record all rules used by a key for logging
    timing_by_query     => { },
    all_lookups         => { },  # keyed by "rr_type/domain"
  };

  bless ($self, $class);
  $self;
}

# ---------------------------------------------------------------------------

=item $ent = $async-E<gt>bgsend_and_start_lookup($name, $type, $class, $ent, $cb, %options)

Launch async DNS lookups.  This is the only official method supported for
plugins since version 4.0.0.  Do not use bgsend and start_lookup separately.

Merges duplicate queries automatically, only launches one and calls all
related callbacks on answer.

=over 4

=item $name (required)

Name to query.

=item $type (required)

Type to query, A, TXT, NS, etc.

=item $class (required/deprecated)

Deprecated, ignored, set as undef.

=item C<$ent> is a required hash reference containing the following items:

=over 4

=item $ent-E<gt>{rulename} (required)

The rulename that started and/or depends on this query.  Required for rule
dependencies to work correctly.  Can be a single rulename, or array of
multiple rulenames.

=item $ent-E<gt>{type} (optional)

A string, typically one word, used to describe the type of lookup in log
messages, such as C<DNSBL>, C<URIBL-A>.  If not defined, default is value of
$type.

=item $ent-E<gt>{zone} (optional)

A zone specification (typically a DNS zone name - e.g.  host, domain, or
RBL) which may be used as a key to look up per-zone settings.  No semantics
on this parameter is imposed by this module.  Currently used to fetch
by-zone timeouts (from rbl_timeout setting).  Defaults to $name.

=item $ent-E<gt>{timeout_initial} (optional)

An initial value of elapsed time for which we are willing to wait for a
response (time in seconds, floating point value is allowed). When elapsed
time since a query started exceeds the timeout value and there are no other
queries to wait for, the query is aborted. The actual timeout value ranges
from timeout_initial and gradually approaches timeout_min (see next parameter)
as the number of already completed queries approaches the number of all
queries started.

If a caller does not explicitly provide this parameter or its value is
undefined, a default initial timeout value is settable by a configuration
variable rbl_timeout.

If a value of the timeout_initial parameter is below timeout_min, the initial
timeout is set to timeout_min.

=item $ent-E<gt>{timeout_min} (optional)

A lower bound (in seconds) to which the actual timeout approaches as the
number of queries completed approaches the number of all queries started.
Defaults to 0.2 * timeout_initial.

=item $ent-E<gt>{key}, $ent-E<gt>{id} (deprecated)

Deprecated, ignored, automatically generated since 4.0.0.

=item $ent-E<gt>{YOUR_OWN_ITEM}

Any other custom values/objects that you want to pass on to the answer
callback.

=back

=item $cb (required)

Callback function for answer, called as $cb-E<gt>($ent, $pkt).  C<$ent> is the
same object that bgsend_and_start_lookup was called with.  C<$pkt> is the
packet object for the response, Net::DNS:RR objects can be found from
$pkt-E<gt>answer.

=item %options (required)

Hash of options. Only supported and required option is master_deadline:

  master_deadline => $pms->{master_deadline}

=back

=cut

sub start_queue {
  my($self) = @_;

  $self->{wait_queue} = 1;
}

sub launch_queue {
  my($self) = @_;

  delete $self->{wait_queue};

  if ($self->{bgsend_queue}) {
    dbg("async: launching queued lookups");
    foreach (@{$self->{bgsend_queue}}) {
      $self->bgsend_and_start_lookup(@$_);
    }
    delete $self->{bgsend_queue};
  }
}

sub bgsend_and_start_lookup {
  my $self = shift;
  my($domain, $type, $class, $ent, $cb, %options) = @_;

  return if $self->{main}->{resolver}->{no_resolver};

  # Waiting for priority -100 to launch?
  if ($self->{wait_queue}) {
    push @{$self->{bgsend_queue}}, [@_];
    dbg("async: DNS priority not reached, queueing lookup: $domain/$type");
    return $ent;
  }

  if (!defined $ent->{rulename} && !$self->{rulename_warned}++) {
    my($package, $filename, $line) = caller;
    warn "async: bgsend_and_start_lookup called without rulename, ".
         "from $package ($filename) line $line. You are likely using ".
         "a plugin that is not compatible with SpamAssasin 4.0.0.";
  }

  $domain =~ s/\.+\z//s;  # strip trailing dots, these sometimes still sneak in
  $domain = idn_to_ascii($domain);

  # At this point the $domain should already be encoded to UTF-8 and
  # IDN converted to ASCII-compatible encoding (ACE).  Make sure this is
  # really the case in order to be able to catch any leftover omissions.
  if (utf8::is_utf8($domain)) {
    utf8::encode($domain);
    my($package, $filename, $line) = caller;
    info("bgsend_and_start_lookup: Unicode domain name, expected octets: %s, ".
         "called from %s line %d", $domain, $package, $line);
  } elsif ($domain =~ tr/\x00-\x7F//c) {  # is not all-ASCII
    my($package, $filename, $line) = caller;
    info("bgsend_and_start_lookup: non-ASCII domain name: %s, ".
         "called from %s line %d", $domain, $package, $line);
  }

  my $dnskey = uc($type).'/'.lc($domain);
  my $dns_query_info = $self->{all_lookups}{$dnskey};

  $ent = {}  if !$ent;
  $ent->{id} = undef;
  my $key = $ent->{key} = $dnskey;
  $ent->{query_type} = $type;
  $ent->{query_domain} = $domain;
  $ent->{type} = $type  if !exists $ent->{type};
  $ent->{zone} = $domain  if !exists $ent->{zone};
  $cb = $ent->{completed_callback}  if !$cb;  # compatibility with SA < 3.4

  my @rulenames = grep { defined } (ref $ent->{rulename} ?
                    @{$ent->{rulename}} : $ent->{rulename});

  $self->{rules_for_key}->{$key}{$_} = 1 foreach (@rulenames);

  if ($dns_query_info) {  # DNS query already underway or completed
    if ($dns_query_info->{blocked}) {
      dbg("async: blocked by %s: %s, rules: %s", $dns_query_info->{blocked},
          $dnskey, join(", ", @rulenames));
      return;
    }
    my $id = $ent->{id} = $dns_query_info->{id};  # re-use existing query
    return if !defined $id;  # presumably some fatal failure
    my $id_tail = $id; $id_tail =~ s{^\d+/IN/}{};
    lc($id_tail) eq lc($dnskey)
      or info("async: unmatched id %s, key=%s", $id, $dnskey);

    my $pkt = $dns_query_info->{pkt};
    if (!$pkt) {  # DNS query underway, still waiting for results
      # just add our query to the existing one
      push(@{$dns_query_info->{applicants}}, [$ent,$cb]);
      $self->{pending_rules}->{$_}{$key} = 1 foreach (@rulenames);
      dbg("async: query %s already underway, adding no.%d, rules: %s",
          $id, scalar @{$dns_query_info->{applicants}},
          join(", ", @rulenames));

    } else {  # DNS query already completed, re-use results
      # answer already known, just do the callback and be done with it
      delete $self->{pending_rules}->{$_}{$key} foreach (@rulenames);
      if (!$cb) {
        dbg("async: query %s already done, re-using for %s, rules: %s",
            $id, $key, join(", ", @rulenames));
      } else {
        dbg("async: query %s already done, re-using for %s, callback, rules: %s",
            $id, $key, join(", ", @rulenames));
        eval {
          $cb->($ent, $pkt); 1;
        } or do {
          chomp $@;
          # resignal if alarm went off
          die "async: (1) $@\n"  if $@ =~ /__alarm__ignore__\(.*\)/s;
          warn sprintf("async: query %s completed, callback %s failed: %s\n",
                       $id, $key, $@);
        };
      }
    }
  }

  else {  # no existing query, open a new DNS query
    $dns_query_info = $self->{all_lookups}{$dnskey} = {};  # new query needed
    my($id, $blocked, $check_dbrdom);
    # dns_query_restriction
    my $blocked_by = 'dns_query_restriction';
    my $dns_query_blockages = $self->{main}->{conf}->{dns_query_blocked};
    # dns_block_rule
    my $dns_block_domains = $self->{main}->{conf}->{dns_block_rule_domains};
    if ($dns_query_blockages || $dns_block_domains) {
      my $search_list = domain_to_search_list($domain);
      foreach my $parent_domain ((@$search_list, '*')) {
        if ($dns_query_blockages) {
          $blocked = $dns_query_blockages->{$parent_domain};
          last if defined $blocked; # stop at first defined, can be true or false
        }
        if ($parent_domain ne '*' && exists $dns_block_domains->{$parent_domain}) {
          # save for later check.. ps. untainted already
          $check_dbrdom = $dns_block_domains->{$parent_domain};
        }
      }
    }
    if (!$blocked && $check_dbrdom) {
      my $blockfile =
        $self->{main}->sed_path("__global_state_dir__/dnsblock_${check_dbrdom}");
      if (my $mtime = (stat($blockfile))[9]) {
        if (time - $mtime <= $self->{main}->{conf}->{dns_block_time}) {
          $blocked = 1;
          $blocked_by = 'dns_block_rule';
        } else {
          dbg("async: dns_block_rule removing expired $blockfile");
          unlink($blockfile);
        }
      }
    }
    if ($blocked) {
      dbg("async: blocked by %s: %s, rules: %s", $blocked_by, $dnskey,
          join(", ", @rulenames));
      $dns_query_info->{blocked} = $blocked_by;
    } else {
      dbg("async: launching %s, rules: %s", $dnskey, join(", ", @rulenames));
      $id = $self->{main}->{resolver}->bgsend($domain, $type, $class, sub {
          my($pkt, $pkt_id, $timestamp) = @_;
          # this callback sub is called from DnsResolver::poll_responses()
          # dbg("async: in a bgsend_and_start_lookup callback, id %s", $pkt_id);
          if ($pkt_id ne $id) {
            warn "async: mismatched dns id: got $pkt_id, expected $id\n";
            return;
          }
          $self->set_response_packet($pkt_id, $pkt, $ent->{key}, $timestamp);
          $dns_query_info->{pkt} = $pkt;
          my $cb_count = 0;
          foreach my $tuple (@{$dns_query_info->{applicants}}) {
            my($appl_ent, $appl_cb) = @$tuple;
            my @rulenames = grep { defined } (ref $appl_ent->{rulename} ?
                      @{$appl_ent->{rulename}} : $appl_ent->{rulename});
            foreach (@rulenames) {
              delete $self->{pending_rules}->{$_}{$appl_ent->{key}};
            }
            if ($appl_cb) {
              dbg("async: calling callback on key %s, rules: %s",
                  $key, join(", ", @rulenames));
              $cb_count++;
              eval {
                $appl_cb->($appl_ent, $pkt); 1;
              } or do {
                chomp $@;
                # resignal if alarm went off
                die "async: (2) $@\n"  if $@ =~ /__alarm__ignore__\(.*\)/s;
                warn sprintf("async: query %s completed, callback %s failed: %s\n",
                             $id, $appl_ent->{key}, $@);
              };
            }
          }
          delete $dns_query_info->{applicants};
          dbg("async: query $id completed, no callbacks run")  if !$cb_count;
        });
    }
    return if !defined $id;
    $dns_query_info->{id} = $ent->{id} = $id;
    push(@{$dns_query_info->{applicants}}, [$ent,$cb]);
    $self->{pending_rules}->{$_}{$key} = 1 foreach (@rulenames);
    $self->_start_lookup($ent, $options{master_deadline});
  }
  return $ent;
}

# ---------------------------------------------------------------------------

=item $ent = $async-E<gt>start_lookup($ent, $master_deadline)

DIRECT USE DEPRECATED since 4.0.0, please use bgsend_and_start_lookup.

=cut

sub start_lookup {
  my $self = shift;

  if (!$self->{start_lookup_warned}++) {
    my($package, $filename, $line) = caller;
    warn "async: deprecated start_lookup called, ".
         "from $package ($filename) line $line. You are likely using ".
         "a plugin that is not compatible with SpamAssasin 4.0.0.";
  }

  return if $self->{main}->{resolver}->{no_resolver};
  $self->_start_lookup(@_);
}

# Internal use not deprecated. :-)
sub _start_lookup {
  my ($self, $ent, $master_deadline) = @_;

  my $id  = $ent->{id};
  my $key = $ent->{key};
  defined $id && $id ne ''  or die "oops, no id";
  $key                      or die "oops, no key";
  $ent->{type}              or die "oops, no type";

  my $now = time;
  $ent->{start_time} = $now  if !defined $ent->{start_time};

  # are there any applicable per-zone settings?
  my $zone = $ent->{zone};
  my $settings;  # a ref to a by-zone or to global settings
  my $conf_by_zone = $self->{main}->{conf}->{by_zone};
  if (defined $zone && $conf_by_zone) {
  # dbg("async: searching for by_zone settings for $zone");
    $zone =~ s/^\.//;  $zone =~ s/\.\z//;  # strip leading and trailing dot
    for (;;) {  # 2.10.example.com, 10.example.com, example.com, com, ''
      if (exists $conf_by_zone->{$zone}) {
        $settings = $conf_by_zone->{$zone};
        last;
      } elsif ($zone eq '') {
        last;
      } else {  # strip one level, careful with address literals
        $zone = ($zone =~ /^( (?: [^.] | \[ (?: \\. | [^\]\\] )* \] )* )
                            \. (.*) \z/xs) ? $2 : '';
      }
    }
  }

  dbg("async: applying by_zone settings for %s", $zone)  if $settings;

  my $t_init = $ent->{timeout_initial};  # application-specified has precedence
  $t_init = $settings->{rbl_timeout}  if $settings && !defined $t_init;
  $t_init = $self->{main}->{conf}->{rbl_timeout}  if !defined $t_init;
  $t_init = 0  if !defined $t_init;      # last-resort default, just in case

  my $t_end = $ent->{timeout_min};       # application-specified has precedence
  $t_end = $settings->{rbl_timeout_min}  if $settings && !defined $t_end;
  $t_end = $self->{main}->{conf}->{rbl_timeout_min}  if !defined $t_end; # added for bug 7070
  $t_end = 0.2 * $t_init  if !defined $t_end;
  $t_end = 0  if $t_end < 0;  # just in case
  $t_init = $t_end  if $t_init < $t_end;

  my $clipped_by_master_deadline = 0;
  if (defined $master_deadline) {
    my $time_avail = $master_deadline - time;
    $time_avail = 0.5  if $time_avail < 0.5;  # give some slack
    if ($t_init > $time_avail) {
      $t_init = $time_avail; $clipped_by_master_deadline = 1;
      $t_end  = $time_avail  if $t_end > $time_avail;
    }
  }
  $ent->{timeout_initial} = $t_init;
  $ent->{timeout_min} = $t_end;

  my @rulenames = grep { defined } (ref $ent->{rulename} ?
                    @{$ent->{rulename}} : $ent->{rulename});
  $ent->{display_id} =  # identifies entry in debug logging and similar
    join(", ", grep { defined } map { $ent->{$_} } qw(type key));

  $self->{pending_lookups}->{$key} = $ent;

  $self->{queries_started}++;
  dbg("async: starting: %s%s (timeout %.1fs, min %.1fs)%s",
      @rulenames ? join(", ", @rulenames).", " : '',
      $ent->{display_id}, $ent->{timeout_initial}, $ent->{timeout_min},
      !$clipped_by_master_deadline ? '' : ', capped by time limit');

  $ent;
}

# ---------------------------------------------------------------------------

=item $ent = $async-E<gt>get_lookup($key)

DEPRECATED since 4.0.0. Do not use.

=cut

sub get_lookup {
  my ($self, $key) = @_;
  warn("async: deprecated get_lookup function used\n");
  return $self->{pending_lookups}->{$key};
}

# ---------------------------------------------------------------------------

=item $async-E<gt>log_lookups_timing()

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

=item $alldone = $async-E<gt>complete_lookups()

Perform a poll of the pending lookups, to see if any are completed.
Callbacks on completed queries will be called from poll_responses().

If there are no lookups remaining, or if too much time has elapsed since
any results were returned, C<1> is returned, otherwise C<0>.

=cut

sub complete_lookups {
  my ($self, $timeout, $allow_aborting_of_expired) = @_;
  my $alldone = 0;
  my $anydone = 0;
  my $allexpired = 1;
  my %typecount;

  my $pending = $self->{pending_lookups};

  my $now = time;

  if (defined $timeout && $timeout > 0 &&
      %$pending && $self->{queries_started} > 0)
  {
    # shrink a 'select' timeout if a caller specified unnecessarily long
    # value beyond the latest deadline of any outstanding request;
    # can save needless wait time (up to 1 second in harvest_dnsbl_queries)
    my $r = $self->{queries_completed} / $self->{queries_started};
    my $r2 = $r * $r;  # 0..1
    my $max_deadline;
    while (my($key,$ent) = each %$pending) {
      my $t_init = $ent->{timeout_initial};
      my $dt = $t_init - ($t_init - $ent->{timeout_min}) * $r2;
      my $deadline = $ent->{start_time} + $dt;
      $max_deadline = $deadline  if !defined $max_deadline ||
                                    $deadline > $max_deadline;
    }
    if (defined $max_deadline) {
      # adjust to timer resolution, only deals with 1s and with fine resolution
      $max_deadline = 1 + int $max_deadline
        if $timer_resolution == 1 && $max_deadline > int $max_deadline;
      my $sufficient_timeout = $max_deadline - $now;
      $sufficient_timeout = 0  if $sufficient_timeout < 0;
      if ($timeout > $sufficient_timeout) {
        dbg("async: reducing select timeout from %.1f to %.1f s",
            $timeout, $sufficient_timeout);
        $timeout = $sufficient_timeout;
      }
    }
  }

  # trap this loop in an eval { } block, as Net::DNS could throw
  # die()s our way; in particular, process_dnsbl_results() has
  # thrown die()s before (bug 3794).
  eval {

    if (%$pending) {  # any outstanding requests still?
      $self->{last_poll_responses_time} = $now;
      my ($nfound, $ncb) = $self->{main}->{resolver}->poll_responses($timeout);
      dbg("async: select found %d responses ready (t.o.=%.1f), did %d callbacks",
          $nfound, $timeout, $ncb);
    }
    $now = time;  # capture new timestamp, after possible sleep in 'select'

    # A callback routine may generate another DNS query, which may insert
    # an entry into the %$pending hash thus invalidating the each() context.
    # So, make sure that callbacks are not called while the each() context
    # is open. [Bug 6937]
    #
    while (my($key,$ent) = each %$pending) {
      my $id = $ent->{id};
      if (exists $self->{finished}->{$id}) {
        delete $self->{finished}->{$id};
        $anydone = 1;
        $ent->{finish_time} = $now  if !defined $ent->{finish_time};
        my $elapsed = $ent->{finish_time} - $ent->{start_time};
        my @rulenames = keys %{$self->{rules_for_key}->{$key}};
        dbg("async: completed in %.3f s: %s, rules: %s",
            $elapsed, $ent->{display_id}, join(", ", @rulenames));
        $self->{timing_by_query}->{". $key ($ent->{type})"} += $elapsed;
        $self->{queries_completed}++;
        delete $pending->{$key};
      }
    }

    if (%$pending) {  # still any requests outstanding? are they expired?
      my $r =
        !$allow_aborting_of_expired || !$self->{queries_started} ? 1.0
        : $self->{queries_completed} / $self->{queries_started};
      my $r2 = $r * $r;  # 0..1
      while (my($key,$ent) = each %$pending) {
        $typecount{$ent->{type}}++;
        my $t_init = $ent->{timeout_initial};
        my $dt = $t_init - ($t_init - $ent->{timeout_min}) * $r2;
        # adjust to timer resolution, only deals with 1s and fine resolution
        $dt = 1 + int $dt  if $timer_resolution == 1 && $dt > int $dt;
        $allexpired = 0  if $now <= $ent->{start_time} + $dt;
      }
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
      dbg("async: queries still pending: %s%s",
          join (' ', map { "$_=$typecount{$_}" } sort keys %typecount),
          $allexpired ? ', all expired' : '');
      $alldone = 0;
    }
    1;

  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # resignal if alarm went off
    die "async: (3) $eval_stat\n"  if $eval_stat =~ /__alarm__ignore__\(.*\)/s;
    dbg("async: caught complete_lookups death, aborting: %s", $eval_stat);
    $alldone = 1;      # abort remaining
  };

  return wantarray ? ($alldone,$anydone) : $alldone;
}

# ---------------------------------------------------------------------------

=item $async-E<gt>abort_remaining_lookups()

Abort any remaining lookups.

=cut

sub abort_remaining_lookups {
  my ($self) = @_;

  my $pending = $self->{pending_lookups};
  my $foundcnt = 0;
  my $now = time;

  $self->{pending_rules} = {};

  while (my($key,$ent) = each %$pending) {
    my $dur = $now - $ent->{start_time};
    my @rulenames = keys %{$self->{rules_for_key}->{$key}};
    my $msg = sprintf( "async: aborting after %.3f s, %s: %s, rules: %s",
        $dur,
        (defined $ent->{timeout_initial} &&
         $now > $ent->{start_time} + $ent->{timeout_initial}
           ? 'past original deadline' : 'deadline shrunk'),
        $ent->{display_id}, join(", ", @rulenames) );
    $dur > 1 ? info($msg) : dbg($msg);
    $foundcnt++;
    $self->{timing_by_query}->{"X $key"} = $dur;
    $ent->{finish_time} = $now  if !defined $ent->{finish_time};
    delete $pending->{$key};
  }

  # call any remaining callbacks, indicating the query has been aborted
  #
  my $all_lookups_ref = $self->{all_lookups};
  foreach my $dnskey (keys %$all_lookups_ref) {
    my $dns_query_info = $all_lookups_ref->{$dnskey};
    my $cb_count = 0;
    foreach my $tuple (@{$dns_query_info->{applicants}}) {
      my($ent, $cb) = @$tuple;
      if ($cb) {
        my @rulenames = grep { defined } (ref $ent->{rulename} ?
                  @{$ent->{rulename}} : $ent->{rulename});
        dbg("async: calling callback/abort on key %s, rules: %s", $dnskey,
            join(", ", @rulenames));
        $cb_count++;
        eval {
          $cb->($ent, undef); 1;
        } or do {
          chomp $@;
          # resignal if alarm went off
          die "async: (2) $@\n"  if $@ =~ /__alarm__ignore__\(.*\)/s;
          warn sprintf("async: query %s aborted, callback %s failed: %s\n",
                       $dnskey, $ent->{key}, $@);
        };
      }
      dbg("async: query $dnskey aborted, no callbacks run")  if !$cb_count;
    }
    delete $dns_query_info->{applicants};
  }

  dbg("async: aborted %d remaining lookups", $foundcnt)  if $foundcnt > 0;
  delete $self->{last_poll_responses_time};
  $self->{main}->{resolver}->bgabort();
  1;
}

# ---------------------------------------------------------------------------

=item $async-E<gt>set_response_packet($id, $pkt, $key, $timestamp)

For internal use, do not call from plugins.

Register a "response packet" for a given query.  C<$id> is the ID for the
query, and must match the C<id> supplied in C<start_lookup()>. C<$pkt> is the
packet object for the response. A parameter C<$key> identifies an entry in a
hash %{$self-E<gt>{pending_lookups}} where the object which spawned this query can
be found, and through which further information about the query is accessible.

C<$pkt> may be undef, indicating that no response packet is available, but a
query has completed (e.g. was aborted or dismissed) and is no longer "pending".

The DNS resolver's response packet C<$pkt> will be made available to a callback
subroutine through its argument as well as in C<$ent-E<gt>{response_packet}>.

=cut

sub set_response_packet {
  my ($self, $id, $pkt, $key, $timestamp) = @_;
  $self->{finished}->{$id} = 1;  # only key existence matters, any value
  $timestamp = time  if !defined $timestamp;
  my $pending = $self->{pending_lookups};
  if (!defined $key) {  # backward compatibility with 3.2.3 and older plugins
    # a third-party plugin did not provide $key in a call, search for it:
    if ($id eq $pending->{$id}->{id}) {  # I feel lucky, key==id ?
      $key = $id;
    } else {  # then again, maybe not, be more systematic
      for my $tkey (keys %$pending) {
        if ($id eq $pending->{$tkey}->{id}) { $key = $tkey; last }
      }
    }
    dbg("async: got response on id $id, search found key $key");
  }
  if (!defined $key) {
    info("async: no key, response packet not remembered, id $id");
  } else {
    my $ent = $pending->{$key};
    my $ent_id = $ent->{id};
    if (!defined $ent_id) {
      # should not happen, troubleshooting
      info("async: ignoring response, id %s, ent_id is undef: %s",
           $id, join(', ', %$ent));
    } elsif ($id ne $ent_id) {
      info("async: ignoring response, mismatched id $id, expected $ent_id");
    } else {
      $ent->{finish_time} = $timestamp;
      $ent->{response_packet} = $pkt;
    }
  }
  1;
}

=item $async-E<gt>report_id_complete($id,$key,$key,$timestamp)

DEPRECATED since 4.0.0. Do not use.

Legacy. Equivalent to $self-E<gt>set_response_packet($id,undef,$key,$timestamp),
i.e. providing undef as a response packet. Register that a query has
completed and is no longer "pending". C<$id> is the ID for the query,
and must match the C<id> supplied in C<start_lookup()>.

One or the other of C<set_response_packet()> or C<report_id_complete()>
should be called, but not both.

=cut

sub report_id_complete {
  my ($self, $id, $key, $timestamp) = @_;
  $self->set_response_packet($id, undef, $key, $timestamp);
}

# ---------------------------------------------------------------------------

=item $time = $async-E<gt>last_poll_responses_time()

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
