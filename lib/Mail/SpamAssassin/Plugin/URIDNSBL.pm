=head1 NAME

URIDNSBL - look up URLs against DNS blocklists

This works by analysing message text and HTML for URLs, extracting the
domain names from those, querying their NS records in DNS, resolving
the hostnames used therein, and querying various DNS blocklists for
those IP addresses.  This is quite effective.

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::URIDNSBL
  uridnsbl	URIBL_SBLXBL    sbl-xbl.spamhaus.org.   TXT

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
URI using the domain C<foo.com> will cause a lookup of C<foo.com.uriblzone.net>.
Note that hostnames are stripped from the domain used in the URIBL lookup,
so the domain C<foo.bar.com> will look up C<bar.com.uriblzone.net>, and
C<foo.bar.co.uk> will look up C<bar.co.uk.uriblzone.net>.

Example:

  urirhsbl        URIBL_RHSBL    rhsbl.example.org.   TXT

=item urirhssub NAME_OF_RULE rhsbl_zone lookuptype subtest

Specify a RHSBL-style domain lookup with a sub-test.  C<NAME_OF_RULE> is the
name of the rule to be used, C<rhsbl_zone> is the zone to look up domain names
in, and C<lookuptype> is the type of lookup (B<TXT> or B<A>).

C<subtest> is the sub-test to run against the returned data.  The sub-test may
either be an IPv4 dotted address for RHSBLs that return multiple A records, a
non-negative decimal number to specify a bitmask for RHSBLs that return a
single A record containing a bitmask of results, or (if none of the preceding
options seem to fit) a regular expression.

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

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
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

  # TODO: use infrastructure from Mail::SpamAssassin::Dns!
  eval {
    require Net::DNS;
    require Net::DNS::Resolver; 

    $self->{res} = Net::DNS::Resolver->new();
  };

  if ($@) {
    dbg("uridnsbl: failed to load Net::DNS::Resolver: $@");
  }

  if ($self->{res}) {
    $self->{res}->defnames(0);
    $self->{res}->dnsrch(0);
    $self->{res}->retrans(3);
    $self->{res}->retry(1);
  }

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

  if (!($self->{res} && $scanner->is_dns_available())) {
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
  # TODO! we need a method that provides more metadata about where
  # the URI was found so we can ignore hammy decoys.
  my %domlist = ( );
  foreach my $uri ($scanner->get_uri_list()) {
    my $dom = Mail::SpamAssassin::Util::uri_to_domain($uri);
    if ($dom) {
      if (exists $scanner->{main}->{conf}->{uridnsbl_skip_domains}->{$dom}) {
        dbg("uridnsbl: found domain $dom in skip list");
      }
      else {
        $domlist{$dom} = 1;
      }
    }
  }

  # trim down to a limited number - pick randomly
  my $i;
  my @longlist = keys %domlist;
  my @shortlist = ();
  for ($i = $scanner->{main}->{conf}->{uridnsbl_max_domains}; $i > 0; $i--) {
    my $r = int rand (scalar @longlist);
    push (@shortlist, splice (@longlist, $r, 1));
    last if (scalar @longlist <= 0);
  }

  # and query
  dbg("uridnsbl: domains to query: ".join(' ',@shortlist));
  foreach my $dom (@shortlist) {
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
    }
  });

  push (@cmds, {
    setting => 'urirhssub',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/) {
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
    }
  });

  push (@cmds, {
    setting => 'uridnsbl_skip_domain',
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
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

  # do a microscopic sleep to give other processes/the DNS server
  # time to get at the CPU
  select (undef, undef, undef, 0.01);

  $self->complete_lookups($opts->{permsgstatus}->{uribl_scanstate});
  return 1;
}

sub check_post_dnsbl {
  my ($self, $opts) = @_;

  return if ($self->{dns_not_available});

  my $scan = $opts->{permsgstatus};
  my $scanstate = $scan->{uribl_scanstate};

  # try to complete a few more
  if (!$self->complete_lookups($scanstate)) {
    my $secs_to_wait = $scan->{conf}->{uridnsbl_timeout};
    dbg("uridnsbl: waiting $secs_to_wait seconds for URIDNSBL lookups to complete");
    while ($secs_to_wait-- >= 0) {
      last if ($self->complete_lookups($scanstate));
      sleep 1;
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
  return if $scanstate->{seen_domain}->{$dom}; $scanstate->{seen_domain}->{$dom}=1;
  $self->log_dns_result ("querying domain $dom");

  my $obj = {
    querystart => time,
    dom => $dom
  };

  if ($dom =~ /^\d+\.\d+\.\d+\.\d+$/) { 
    $self->lookup_dnsbl_for_ip ($scanstate, $obj, $dom);
  }
  else {
    # look up the domain in the RHSBL subset
    my $cf = $scanstate->{active_rules_rhsbl};
    foreach my $rulename (keys %{$cf}) {
      my $rulecf = $scanstate->{scanner}->{conf}->{uridnsbls}->{$rulename};
      $self->lookup_single_dnsbl ($scanstate, $obj, $rulename,
                          $dom, $rulecf->{zone}, $rulecf->{type});
    }

    # perform NS, A lookups to look up the domain in the non-RHSBL subset
    $self->lookup_domain_ns ($scanstate, $obj, $dom);
  }
}

# ---------------------------------------------------------------------------

sub lookup_domain_ns {
  my ($self, $scanstate, $obj, $dom) = @_;

  my $key = "NS:".$dom;
  return if $scanstate->{pending_lookups}->{$key};

  # dig $dom ns
  my $ent = $self->start_lookup ($scanstate, 'NS', $self->{res}->bgsend ($dom, 'NS'));
  $ent->{obj} = $obj;
  $scanstate->{pending_lookups}->{$key} = $ent;
}

sub complete_ns_lookup {
  my ($self, $scanstate, $ent, $dom) = @_;

  my $packet = $self->{res}->bgread($ent->{sock});
  $self->close_ent_socket ($ent);
  my @answer = $packet->answer;

  foreach my $rr (@answer) {
    my $str = $rr->string;
    next unless (defined($str) && defined($dom));
    $self->log_dns_result ("NSs for $dom: $str");

    if ($str =~ /IN\s+NS\s+(\S+)/) {
      $self->lookup_a_record($scanstate, $ent->{obj}, $1);
    }
  }
}

# ---------------------------------------------------------------------------

sub lookup_a_record {
  my ($self, $scanstate, $obj, $hname) = @_;

  my $key = "A:".$hname;
  return if $scanstate->{pending_lookups}->{$key};

  # dig $hname a
  my $ent = $self->start_lookup ($scanstate, 'A', $self->{res}->bgsend ($hname, 'A'));
  $ent->{obj} = $obj;
  $scanstate->{pending_lookups}->{$key} = $ent;
}

sub complete_a_lookup {
  my ($self, $scanstate, $ent, $hname) = @_;

  my $packet = $self->{res}->bgread($ent->{sock});
  $self->close_ent_socket ($ent);
  my @answer = $packet->answer;

  foreach my $rr (@answer) {
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
    $self->lookup_single_dnsbl ($scanstate, $obj, $rulename,
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
				$self->{res}->bgsend ($item, $qtype));
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

  my $packet = $self->{res}->bgread($ent->{sock});
  $self->close_ent_socket ($ent);
  my @answer = $packet->answer;
  my $uridnsbl_subs = $conf->{uridnsbl_subs}->{$ent->{zone}};
  my $uridnsbl_subs_bits = 0;
  $uridnsbl_subs_bits |= $_ for keys %{$uridnsbl_subs};
  foreach my $rr (@answer)
  {
    next if ($rr->type ne 'A' && $rr->type ne 'TXT');

    my $rdatastr = $rr->rdatastr;
    my $dom = $ent->{obj}->{dom};

    if (!$rulecf->{is_subrule}) {
      # this zone is a simple rule, not a set of subrules
      # skip any A record that isn't on 127/8
      next if ($rr->type eq 'A' && $rr->rdatastr !~ /^127\./);
      $self->got_dnsbl_hit ($scanstate, $ent, $rdatastr, $dom, $rulename);
    }
    else {
      # skip any A record that isn't on 127/8 if we're not looking for
      # any bits in the first octet, this is a workaround for bug 3997
      next if ($rr->type eq 'A' && $rr->rdatastr !~ /^127\./ &&
	       !($uridnsbl_subs_bits & 0xff000000));
      foreach my $subtest (keys (%{$uridnsbl_subs}))
      {
        my $subrulename = $uridnsbl_subs->{$subtest}->{rulename};

        if ($subtest eq $rdatastr) {
          $self->got_dnsbl_hit ($scanstate, $ent, $rdatastr, $dom, $subrulename);
        }
        # bitmask
        elsif ($subtest =~ /^\d+$/) {
          if ($rdatastr =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ &&
              Mail::SpamAssassin::Util::my_inet_aton($rdatastr) & $subtest)
          {
            $self->got_dnsbl_hit ($scanstate, $ent, $rdatastr, $dom, $subrulename);
          }
        }
        # regular expression
        else {
          if ($rdatastr =~ /${subtest}/) {
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
  my ($self, $scanstate, $type, $sock) = @_;
  my $ent = {
    type => $type,
    sock => $sock
  };
  $scanstate->{queries_started}++;
  $ent;
}

# ---------------------------------------------------------------------------

# perform a poll of our lookups, to see if any are completed; if they
# are, the next lookup in the sequence will be kicked off.

sub complete_lookups {
  my ($self, $scanstate) = @_;
  my %typecount = ();
  my $stillwaiting = 0;

  my $pending = $scanstate->{pending_lookups};
  if (scalar keys %{$pending} <= 0) {
    return 1;		# nothing left to do
  }

  $scanstate->{queries_started} = 0;
  $scanstate->{queries_completed} = 0;

  foreach my $key (keys %{$pending}) {
    my $ent = $pending->{$key};

    my $type = $ent->{type};
    $key =~ /:(\S+)$/; my $val = $1;

    if (!$self->{res}->bgisready ($ent->{sock})) {
      $typecount{$type}++;
      #$stillwaiting = 1;
      next;
    }

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

    $self->close_ent_socket ($pending->{$key});
    delete $pending->{$key};
  }
}

sub close_ent_socket {
  my ($ent) = @_;
  if ($ent->{sock}) {
    $ent->{sock}->close();
    delete $ent->{sock};
  }
}

# ---------------------------------------------------------------------------

sub log_dns_result {
  #my $self = shift;
  #Mail::SpamAssassin::dbg("uridnsbl: ".join (' ', @_));
}

# ---------------------------------------------------------------------------

1;
