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

URIDNSBL - look up URLs against DNS blocklists

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::URIDNSBL
  uridnsbl	URIBL_SBLXBL    sbl-xbl.spamhaus.org.   TXT

=head1 DESCRIPTION

This works by analysing message text and HTML for URLs, extracting the
domain names from those, querying their NS records in DNS, resolving
the hostnames used therein, and querying various DNS blocklists for
those IP addresses.  This is quite effective.

=head1 CONFIGURATION

=over 4

=item uridnsbl NAME_OF_RULE dnsbl_zone lookuptype

Specify a lookup.  C<NAME_OF_RULE> is the name of the rule to be
used, C<dnsbl_zone> is the zone to look up IPs in, and C<lookuptype>
is the type of lookup (B<TXT> or B<A>).   Note that you must also
define a body-eval rule calling C<check_uridnsbl()> to use this.

Example:

 uridnsbl        URIBL_SBLXBL    sbl-xbl.spamhaus.org.   TXT
 body            URIBL_SBLXBL    eval:check_uridnsbl('URIBL_SBLXBL')
 describe        URIBL_SBLXBL    Contains a URL listed in the SBL/XBL blocklist

=item urirhsbl NAME_OF_RULE rhsbl_zone lookuptype

Specify a RHSBL-style domain lookup.  C<NAME_OF_RULE> is the name of the rule
to be used, C<rhsbl_zone> is the zone to look up domain names in, and
C<lookuptype> is the type of lookup (B<TXT> or B<A>).   Note that you must also
define a body-eval rule calling C<check_uridnsbl()> to use this.

An RHSBL zone is one where the domain name is looked up, as a string; e.g. a
URI using the domain C<foo.com> will cause a lookup of
C<foo.com.uriblzone.net>.  Note that hostnames are stripped from the domain
used in the URIBL lookup, so the domain C<foo.bar.com> will look up
C<bar.com.uriblzone.net>, and C<foo.bar.co.uk> will look up
C<bar.co.uk.uriblzone.net>.

If a URI consists IP address instead of a hostname, the IP address is looked
up (using the standard reversed quads method) in each C<rhsbl_zone>.

Example:

  urirhsbl        URIBL_RHSBL    rhsbl.example.org.   TXT

=item urirhssub NAME_OF_RULE rhsbl_zone lookuptype subtest

Specify a RHSBL-style domain lookup with a sub-test.  C<NAME_OF_RULE> is the
name of the rule to be used, C<rhsbl_zone> is the zone to look up domain names
in, and C<lookuptype> is the type of lookup (B<TXT> or B<A>).

C<subtest> is the sub-test to run against the returned data.  The sub-test may
either be an IPv4 dotted address for RHSBLs that return multiple A records or a
non-negative decimal number to specify a bitmask for RHSBLs that return a
single A record containing a bitmask of results.

Note that, as with C<urirhsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

Example:

  urirhssub   URIBL_RHSBL_4    rhsbl.example.org.   A    127.0.0.4
  urirhssub   URIBL_RHSBL_8    rhsbl.example.org.   A    8

=item uridnsbl_timeout N		(default: 2)

Specify the maximum number of seconds to wait for a result before
giving up on the lookup.  Note that this is in addition to the normal
DNS timeout applied for DNSBL lookups on IPs found in the Received headers.

=item uridnsbl_max_domains N		(default: 20)

The maximum number of domains to look up.

=item uridnsbl_skip_domain domain1 domain2 ...

Specify a domain, or a number of domains, which should be skipped for the
URIBL checks.  This is very useful to specify very common domains which are
not going to be listed in URIBLs.

=back

=cut

package Mail::SpamAssassin::Plugin::URIDNSBL;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use constant LOG_COMPLETION_TIMES => 0;

# constructor
sub new {
  my $class = shift;
  my $samain = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($samain);
  bless ($self, $class);

  # this can be effectively global, at least in each process, safely

  $self->{finished} = { };

  $self->register_eval_rule ("check_uridnsbl");
  $self->set_config($samain->{conf});

  return $self;
}

# this is just a placeholder; in fact the results are dealt with later
sub check_uridnsbl {
  return 0;
}

# ---------------------------------------------------------------------------

# once the metadata is parsed, we can access the URI list.  So start off
# the lookups here!
sub parsed_metadata {
  my ($self, $opts) = @_;
  my $scanner = $opts->{permsgstatus};

  if (!$scanner->is_dns_available()) {
    $self->{dns_not_available} = 1;
    return;
  }

  $self->{scanner} = $scanner;
  my $scanstate = $scanner->{uribl_scanstate} = {
    self => $self,
    scanner => $scanner,
    activerules => { },
    hits => { }
  };

  # only hit DNSBLs for active rules (defined and score != 0)
  $scanstate->{active_rules_rhsbl} = { };
  $scanstate->{active_rules_revipbl} = { };
  foreach my $rulename (keys %{$scanner->{conf}->{uridnsbls}}) {
    next unless ($scanner->{conf}->is_rule_active('body_evals',$rulename));

    my $rulecf = $scanstate->{scanner}->{conf}->{uridnsbls}->{$rulename};
    if ($rulecf->{is_rhsbl}) {
      $scanstate->{active_rules_rhsbl}->{$rulename} = 1;
    } else {
      $scanstate->{active_rules_revipbl}->{$rulename} = 1;
    }
  }

  $self->setup ($scanstate);


  # get all domains in message

  # don't keep dereferencing this
  my $skip_domains = $scanner->{main}->{conf}->{uridnsbl_skip_domains};

  # list of arrays to use in order
  my @uri_ordered = ();

  # Generate the full list of html-parsed domains.
  my $uris = $scanner->get_uri_detail_list();

  # go from uri => info to uri_ordered
  # 0: a
  # 1: form
  # 2: img
  # 3: !a_empty
  # 4: parsed
  # 5: a_empty
  while (my($uri, $info) = each %{$uris}) {
    # we want to skip mailto: uris
    next if ($uri =~ /^mailto:/);

    # no domains were found via this uri, so skip
    next unless ($info->{domains});

    my $entry = 3;

    if ($info->{types}->{a}) {
      $entry = 5;

      # determine a vs a_empty
      foreach my $at (@{$info->{anchor_text}}) {
        if (length $at) {
	  $entry = 0;
	  last;
	}
      }
    }
    elsif ($info->{types}->{form}) {
      $entry = 1;
    }
    elsif ($info->{types}->{img}) {
      $entry = 2;
    }
    elsif ($info->{types}->{parsed} && (keys %{$info->{types}} == 1)) {
      $entry = 4;
    }

    # take the usable domains and add to the ordered list
    foreach ( keys %{ $info->{domains} } ) {
      if (exists $skip_domains->{$_}) {
        dbg("uridnsbl: domain $_ in skip list");
        next;
      }
      $uri_ordered[$entry]->{$_} = 1;
    }
  }

  # at this point, @uri_ordered is an ordered array of uri hashes

  my %domlist = ();
  while (keys %domlist < $scanner->{main}->{conf}->{uridnsbl_max_domains} && @uri_ordered) {
    my $array = shift @uri_ordered;
    next unless $array;

    # run through and find the new domains in this grouping
    my @domains = grep(!$domlist{$_}, keys %{$array});
    next unless @domains;

    # the new domains are all useful, just add them in
    if (keys(%domlist) + @domains <= $scanner->{main}->{conf}->{uridnsbl_max_domains}) {
      foreach (@domains) {
        $domlist{$_} = 1;
      }
    }
    else {
      # trim down to a limited number - pick randomly
      my $i;
      while (@domains && keys %domlist < $scanner->{main}->{conf}->{uridnsbl_max_domains}) {
        my $r = int rand (scalar @domains);
        $domlist{splice (@domains, $r, 1)} = 1;
      }
    }
  }

  # and query
  dbg("uridnsbl: domains to query: ".join(' ',keys %domlist));
  foreach my $dom (keys %domlist) {
    $self->query_domain ($scanstate, $dom);
  }

  return 1;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push(@cmds, {
    setting => 'uridnsbl_timeout',
    default => 3,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push(@cmds, {
    setting => 'uridnsbl_max_domains',
    default => 20,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push (@cmds, {
    setting => 'uridnsbl',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_rhsbl => 0
        };
      }
      elsif ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

  push (@cmds, {
    setting => 'urirhsbl',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_rhsbl => 1
        };
      }
      elsif ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

  push (@cmds, {
    setting => 'urirhssub',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\d{1,10}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        my $subrule = $4;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_rhsbl => 1, is_subrule => 1
        };
        $self->{uridnsbl_subs}->{$zone} ||= { };
        $self->{uridnsbl_subs}->{$zone}->{$subrule} = {
          rulename => $rulename
        };
      }
      elsif ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

  push (@cmds, {
    setting => 'uridnsbl_skip_domain',
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{uridnsbl_skip_domains}->{lc $domain} = 1;
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub check_tick {
  my ($self, $opts) = @_;

  return if ($self->{dns_not_available});
  $self->complete_lookups($opts->{permsgstatus}->{uribl_scanstate}, 0.3);
  return 1;
}

sub check_post_dnsbl {
  my ($self, $opts) = @_;

  return if ($self->{dns_not_available});

  my $scan = $opts->{permsgstatus};
  my $scanstate = $scan->{uribl_scanstate};

  # try to complete a few more
  if (!$self->complete_lookups($scanstate, 0.1)) {
    my $secs_to_wait = $scan->{conf}->{uridnsbl_timeout};
    if ($secs_to_wait < 0) { $secs_to_wait = 0; }
    my $now = time;
    my $deadline = $now + $secs_to_wait;
    dbg("uridnsbl: waiting $secs_to_wait seconds for URIDNSBL lookups to complete");

    while ($now < $deadline) {
      last if ($self->complete_lookups($scanstate, $deadline - $now));
      $now = time;
    }
    dbg("uridnsbl: done waiting for URIDNSBL lookups to complete");
  }

  foreach my $rulename (keys %{$scanstate->{active_rules_revipbl}},
                        keys %{$scanstate->{active_rules_rhsbl}})
  {
    $scan->clear_test_state();

    if ($scanstate->{hits}->{$rulename}) {
      my $uris = join (' ', keys %{$scanstate->{hits}->{$rulename}});
      $scan->test_log ("URIs: $uris");
      $scan->got_hit ($rulename, "");
    }
  }

  $self->abort_remaining_lookups ($scanstate);
}

# ---------------------------------------------------------------------------

sub setup {
  my ($self, $scanstate) = @_;

  $scanstate->{pending_lookups} = { };
  $scanstate->{seen_domain} = { };
  $scanstate->{last_count} = 0;
  $scanstate->{times_count_was_same} = 0;
}

# ---------------------------------------------------------------------------

sub query_domain {
  my ($self, $scanstate, $dom) = @_;

  #warn "uridnsbl: domain $dom\n";
  #return;

  $dom = lc $dom;
  return if $scanstate->{seen_domain}->{$dom};
  $scanstate->{seen_domain}->{$dom} = 1;
  $self->log_dns_result("querying domain $dom");

  my $obj = {
    querystart => time,
    dom => $dom
  };

  my $single_dnsbl = 0;
  if ($dom =~ /^\d+\.\d+\.\d+\.\d+$/) { 
    my $IPV4_ADDRESS = IPV4_ADDRESS;
    my $IP_PRIVATE = IP_PRIVATE;
    # only look up the IP if it is public and valid
    if ($dom =~ /^$IPV4_ADDRESS$/ && $dom !~ /^$IP_PRIVATE$/) {
      $self->lookup_dnsbl_for_ip($scanstate, $obj, $dom);
      # and check the IP in RHSBLs too
      if ($dom =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
	$dom = "$4.$3.$2.$1";
	$single_dnsbl = 1;
      }
    }
  }
  else {
    $single_dnsbl = 1;
  }

  if ($single_dnsbl) {
    # look up the domain in the RHSBL subset
    my $cf = $scanstate->{active_rules_rhsbl};
    foreach my $rulename (keys %{$cf}) {
      my $rulecf = $scanstate->{scanner}->{conf}->{uridnsbls}->{$rulename};
      $self->lookup_single_dnsbl($scanstate, $obj, $rulename,
				 $dom, $rulecf->{zone}, $rulecf->{type});
    }

    # perform NS, A lookups to look up the domain in the non-RHSBL subset
    if ($dom !~ /^\d+\.\d+\.\d+\.\d+$/) {
      $self->lookup_domain_ns($scanstate, $obj, $dom);
    }
  }
}

# ---------------------------------------------------------------------------

sub lookup_domain_ns {
  my ($self, $scanstate, $obj, $dom) = @_;

  my $key = "NS:".$dom;
  return if $scanstate->{pending_lookups}->{$key};

  # dig $dom ns
  my $ent = $self->start_lookup ($scanstate, 'NS', $self->res_bgsend($dom, 'NS'));
  $ent->{obj} = $obj;
  $scanstate->{pending_lookups}->{$key} = $ent;
}

sub complete_ns_lookup {
  my ($self, $scanstate, $ent, $dom) = @_;

  my $packet = $ent->{response_packet};
  my @answer = $packet->answer;

  my $IPV4_ADDRESS = IPV4_ADDRESS;
  my $IP_PRIVATE = IP_PRIVATE;

  foreach my $rr (@answer) {
    my $str = $rr->string;
    next unless (defined($str) && defined($dom));
    $self->log_dns_result ("NSs for $dom: $str");

    if ($str =~ /IN\s+NS\s+(\S+)/) {
      my $nsmatch = $1;

      if ($nsmatch =~ /^\d+\.\d+\.\d+\.\d+\.?$/) {
	$nsmatch =~ s/\.$//;
	# only look up the IP if it is public and valid
	if ($nsmatch =~ /^$IPV4_ADDRESS$/ && $nsmatch !~ /^$IP_PRIVATE$/) {
	  $self->lookup_dnsbl_for_ip($scanstate, $ent->{obj}, $nsmatch);
	}
      }
      else {
	$self->lookup_a_record($scanstate, $ent->{obj}, $nsmatch);
      }
    }
  }
}

# ---------------------------------------------------------------------------

sub lookup_a_record {
  my ($self, $scanstate, $obj, $hname) = @_;

  my $key = "A:".$hname;
  return if $scanstate->{pending_lookups}->{$key};

  # dig $hname a
  my $ent = $self->start_lookup ($scanstate, 'A', $self->res_bgsend($hname, 'A'));
  $ent->{obj} = $obj;
  $scanstate->{pending_lookups}->{$key} = $ent;
}

sub complete_a_lookup {
  my ($self, $scanstate, $ent, $hname) = @_;

  foreach my $rr ($ent->{response_packet}->answer) {
    my $str = $rr->string;
    $self->log_dns_result ("A for NS $hname: $str");

    if ($str =~ /IN\s+A\s+(\S+)/) {
      $self->lookup_dnsbl_for_ip($scanstate, $ent->{obj}, $1);
    }
  }
}

# ---------------------------------------------------------------------------

sub lookup_dnsbl_for_ip {
  my ($self, $scanstate, $obj, $ip) = @_;

  $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  my $revip = "$4.$3.$2.$1";

  my $cf = $scanstate->{active_rules_revipbl};
  foreach my $rulename (keys %{$cf}) {
    my $rulecf = $scanstate->{scanner}->{conf}->{uridnsbls}->{$rulename};
    $self->lookup_single_dnsbl($scanstate, $obj, $rulename,
			       $revip, $rulecf->{zone}, $rulecf->{type});
  }
}

sub lookup_single_dnsbl {
  my ($self, $scanstate, $obj, $rulename, $lookupstr, $dnsbl, $qtype) = @_;

  my $key = "DNSBL:".$dnsbl.":".$lookupstr;
  return if $scanstate->{pending_lookups}->{$key};
  my $item = $lookupstr.".".$dnsbl;

  # dig $ip txt
  my $ent = $self->start_lookup ($scanstate, 'DNSBL',
        $self->res_bgsend($item, $qtype));
  $ent->{obj} = $obj;
  $ent->{rulename} = $rulename;
  $ent->{zone} = $dnsbl;
  $scanstate->{pending_lookups}->{$key} = $ent;
}

sub complete_dnsbl_lookup {
  my ($self, $scanstate, $ent, $dnsblip) = @_;

  my $scan = $scanstate->{scanner};
  my $conf = $scan->{conf};
  my @subtests = ();
  my $rulename = $ent->{rulename};
  my $rulecf = $conf->{uridnsbls}->{$rulename};

  my $packet = $ent->{response_packet};
  my @answer = $packet->answer;

  my $uridnsbl_subs = $conf->{uridnsbl_subs}->{$ent->{zone}};
  foreach my $rr (@answer)
  {
    next if ($rr->type ne 'A' && $rr->type ne 'TXT');

    my $rdatastr = $rr->rdatastr;
    my $dom = $ent->{obj}->{dom};

    if (!$rulecf->{is_subrule}) {
      # this zone is a simple rule, not a set of subrules
      # skip any A record that isn't on 127/8
      if ($rr->type eq 'A' && $rr->rdatastr !~ /^127\./) {
	warn("uridnsbl: bogus rr for domain=$dom, rule=$rulename, id=" .
            $packet->header->id." rr=".$rr->string);
	next;
      }
      $self->got_dnsbl_hit($scanstate, $ent, $rdatastr, $dom, $rulename);
    }
    else {
      foreach my $subtest (keys (%{$uridnsbl_subs}))
      {
        my $subrulename = $uridnsbl_subs->{$subtest}->{rulename};

        if ($subtest eq $rdatastr) {
          $self->got_dnsbl_hit($scanstate, $ent, $rdatastr, $dom, $subrulename);
        }
        # bitmask
        elsif ($subtest =~ /^\d+$/) {
	  if ($rdatastr =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ &&
	      Mail::SpamAssassin::Util::my_inet_aton($rdatastr) & $subtest)
          {
            $self->got_dnsbl_hit($scanstate, $ent, $rdatastr, $dom, $subrulename);
          }
        }
      }
    }
  }
}

sub got_dnsbl_hit {
  my ($self, $scanstate, $ent, $str, $dom, $rulename) = @_;

  $str =~ s/\s+/  /gs;	# long whitespace => short
  dbg("uridnsbl: domain \"$dom\" listed ($rulename): $str");

  if (!defined $scanstate->{hits}->{$rulename}) {
    $scanstate->{hits}->{$rulename} = { };
  };
  $scanstate->{hits}->{$rulename}->{$dom} = 1;
}

# ---------------------------------------------------------------------------

sub start_lookup {
  my ($self, $scanstate, $type, $id) = @_;
  my $ent = {
    type => $type,
    id => $id
  };
  $scanstate->{queries_started}++;
  $ent;
}

# ---------------------------------------------------------------------------

# perform a poll of our lookups, to see if any are completed; if they
# are, the next lookup in the sequence will be kicked off.

sub complete_lookups {
  my ($self, $scanstate, $timeout) = @_;
  my %typecount = ();
  my $stillwaiting = 0;

  my $pending = $scanstate->{pending_lookups};
  if (scalar keys %{$pending} <= 0) {
    return 1;		# nothing left to do
  }

  $scanstate->{queries_started} = 0;
  $scanstate->{queries_completed} = 0;

  my $nfound = $self->{main}->{resolver}->poll_responses($timeout);
  $nfound ||= 'no';
  dbg ("uridnsbl: select found $nfound socks ready");

  foreach my $key (keys %{$pending}) {
    my $ent = $pending->{$key};
    my $type = $ent->{type};

    if (!exists ($self->{finished}->{$ent->{id}})) {
      $typecount{$type}++;
      #$stillwaiting = 1;
      next;
    }

    $ent->{response_packet} = delete $self->{finished}->{$ent->{id}};
    $key =~ /:(\S+)$/; my $val = $1;

    if (LOG_COMPLETION_TIMES) {
      my $secs = (time - $ent->{start});
      my $totalsecs = (time - $ent->{obj}->{querystart});
      printf "# time: %s %3.3f %3.3f %s\n",
		$type, $secs, $totalsecs, $ent->{obj}->{dom};
    }

    if ($type eq 'NS') {
      $self->complete_ns_lookup ($scanstate, $ent, $val);
    }
    elsif ($type eq 'A') {
      $self->complete_a_lookup ($scanstate, $ent, $val);
    }
    elsif ($type eq 'DNSBL') {
      $self->complete_dnsbl_lookup ($scanstate, $ent, $val);
      my $totalsecs = (time - $ent->{obj}->{querystart});
      dbg("uridnsbl: query for ".$ent->{obj}->{dom}." took ".
		$totalsecs." seconds to look up ($val)");
    }

    $scanstate->{queries_completed}++;
    delete $scanstate->{pending_lookups}->{$key};
  }

  dbg("uridnsbl: queries completed: ".$scanstate->{queries_completed}.
		" started: ".$scanstate->{queries_started});

  if (1) {
    dbg("uridnsbl: queries active: ".
	join (' ', map { "$_=$typecount{$_}" } sort keys %typecount)." at ".
	localtime(time));
  }

  # ensure we don't get stuck if a request gets lost in the ether.
  if (!$stillwaiting) {
    my $numkeys = scalar keys %{$scanstate->{pending_lookups}};
    if ($numkeys == 0) {
      $stillwaiting = 0;

    } else {
      $stillwaiting = 1;

      # avoid looping forever if we haven't got all results. 
      if ($scanstate->{last_count} == $numkeys) {
	$scanstate->{times_count_was_same}++;
	if ($scanstate->{times_count_was_same} > 20) {
	  dbg("uridnsbl: escaping: must have lost requests");
	  $self->abort_remaining_lookups ($scanstate);
	  $stillwaiting = 0;
	}
      } else {
	$scanstate->{last_count} = $numkeys;
	$scanstate->{times_count_was_same} = 0;
      }
    }
  }

  return (!$stillwaiting);
}

# ---------------------------------------------------------------------------

sub abort_remaining_lookups  {
  my ($self, $scanstate) = @_;

  my $pending = $scanstate->{pending_lookups};
  my $foundone = 0;
  foreach my $key (keys %{$pending})
  {
    if (!$foundone) {
      dbg("uridnsbl: aborting remaining lookups");
      $foundone = 1;
    }

    delete $pending->{$key};
  }
  $self->{main}->{resolver}->bgabort();
}

# ---------------------------------------------------------------------------

sub res_bgsend {
  my ($self, $host, $type) = @_;

  return $self->{main}->{resolver}->bgsend($host, $type, undef, sub {
        my $pkt = shift;
        my $id = shift;
        $self->{finished}->{$id} = $pkt;
      });
}

sub log_dns_result {
  #my $self = shift;
  #Mail::SpamAssassin::dbg("uridnsbl: ".join (' ', @_));
}

# ---------------------------------------------------------------------------

1;
