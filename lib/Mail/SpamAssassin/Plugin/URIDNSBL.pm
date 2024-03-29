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

This works by analysing message text and HTML for URLs, extracting host
names from those, then querying various DNS blocklists for either:
IP addresses of these hosts (uridnsbl,a) or their nameservers (uridnsbl,ns),
or domain names of these hosts (urirhsbl), or domain names of their
nameservers (urinsrhsbl, urifullnsrhsbl).

=head1 USER SETTINGS

=over 4

=item skip_uribl_checks ( 0 | 1 )   (default: 0)

Turning on the skip_uribl_checks setting will disable the URIDNSBL plugin.

By default, SpamAssassin will run URI DNSBL checks. Individual URI blocklists
may be disabled selectively by setting a score of a corresponding rule to 0
or through the uridnsbl_skip_domain parameter.

See also a related configuration parameter skip_rbl_checks,
which controls the DNSEval plugin (documented in the Conf man page).

=back

=over 4

=item uridnsbl_skip_domain domain1 domain2 ...

Specify a domain, or a number of domains, which should be skipped for the
URIBL checks.  This is very useful to specify very common domains which are
not going to be listed in URIBLs.

In addition to trimmed domain, the full hostname is also checked from the
list.

=back

=over 4

=item clear_uridnsbl_skip_domain [domain1 domain2 ...]

If no argument is given, then clears the entire list of domains declared
by I<uridnsbl_skip_domain> configuration directives so far. Any subsequent
I<uridnsbl_skip_domain> directives will start creating a new list of skip
domains.

When given a list of domains as arguments, only the specified domains
are removed from the list of skipped domains.

=back

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=over 4

=item uridnsbl NAME_OF_RULE dnsbl_zone lookuptype

Specify a lookup.  C<NAME_OF_RULE> is the name of the rule to be
used, C<dnsbl_zone> is the zone to look up IPs in, and C<lookuptype>
is the type of lookup (B<TXT> or B<A>).   Note that you must also
define a body-eval rule calling C<check_uridnsbl()> to use this.

This works by collecting domain names from URLs and querying DNS
blocklists with an IP address of host names found in URLs or with
IP addresses of their name servers, according to tflags as follows.

If the corresponding body rule has a tflag 'a', the DNS blocklist will
be queried with an IP address of a host found in URLs.

If the corresponding body rule has a tflag 'ns', DNS will be queried
for name servers (NS records) of a domain name found in URLs, then
these name server names will be resolved to their IP addresses, which
in turn will be sent to DNS blocklist.

Tflags directive may specify either 'a' or 'ns' or both flags. In absence
of any of these two flags, a default is a 'ns', which is compatible with
pre-3.4 versions of SpamAssassin.

The choice of tflags must correspond to the policy and expected use of
each DNS blocklist and is normally not a local decision. As an example,
a blocklist expecting queries resulting from an 'a' tflag is a
"black_a.txt" ( http://www.uribl.com/datasets.shtml ).

Example:

 uridnsbl        URIBL_SBLXBL    sbl-xbl.spamhaus.org.   TXT
 body            URIBL_SBLXBL    eval:check_uridnsbl('URIBL_SBLXBL')
 describe        URIBL_SBLXBL    Contains a URL listed in the SBL/XBL blocklist
 tflags          URIBL_SBLXBL    net ns

=item uridnssub NAME_OF_RULE dnsbl_zone lookuptype subtest

Specify a DNSBL-style domain lookup with a sub-test.  C<NAME_OF_RULE> is the
name of the rule to be used, C<dnsbl_zone> is the zone to look up IPs in,
and C<lookuptype> is the type of lookup (B<TXT> or B<A>).

Tflags 'ns' and 'a' on a corresponding body rule are recognized and have
the same meaning as in the uridnsbl directive.

C<subtest> is a sub-test to run against the returned data.  The sub-test may
be in one of the following forms: m, n1-n2, or n/m, where n,n1,n2,m can be
any of: decimal digits, 0x followed by up to 8 hexadecimal digits, or an IPv4
address in quad-dot form. The 'A' records (IPv4 dotted address) as returned
by DNSBLs lookups are converted into a numerical form (r) and checked against
the specified sub-test as follows:
for a range n1-n2 the following must be true: (r E<gt>= n1 && r E<lt>= n3);
for a n/m form the following must be true: (r & m) == (n & m);
for a single value in quad-dot form the following must be true: r == n;
for a single decimal or hex form the following must be true:
  ((r & n) != 0) && ((r & 0xff000000) == 0x7f000000), i.e. within 127.0.0.0/8

Some typical examples of a sub-test are: 127.0.1.2, 127.0.1.20-127.0.1.39,
127.0.1.0/255.255.255.0, 0.0.0.16/0.0.0.16, 0x10/0x10, 16, 0x10 .

Note that, as with C<uridnsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

Example:

  uridnssub   URIBL_DNSBL_4    dnsbl.example.org.   A    127.0.0.4
  uridnssub   URIBL_DNSBL_8    dnsbl.example.org.   A    8

=item urirhsbl NAME_OF_RULE rhsbl_zone lookuptype

Specify a RHSBL-style domain lookup.  C<NAME_OF_RULE> is the name of the rule
to be used, C<rhsbl_zone> is the zone to look up domain names in, and
C<lookuptype> is the type of lookup (B<TXT> or B<A>).   Note that you must also
define a body-eval rule calling C<check_uridnsbl()> to use this.

An RHSBL zone is one where the domain name is looked up, as a string; e.g. a
URI using the domain C<foo.com> will cause a lookup of
C<foo.com.uriblzone.net>.  Note that hostnames are trimmed to the domain
portion in the URIBL lookup, so the domain C<foo.bar.com> will look up
C<bar.com.uriblzone.net>, and C<foo.bar.co.uk> will look up
C<bar.co.uk.uriblzone.net>.  Using tflag C<notrim> will force full hostname
lookup, but the specific uribl must support this method.

If an URI consists of an IP address instead of a hostname, the IP address is
looked up (using the standard reversed quads method) in each C<rhsbl_zone>.

Example:

  urirhsbl        URIBL_RHSBL    rhsbl.example.org.   TXT

=item urirhssub NAME_OF_RULE rhsbl_zone lookuptype subtest

Specify a RHSBL-style domain lookup with a sub-test.  C<NAME_OF_RULE> is the
name of the rule to be used, C<rhsbl_zone> is the zone to look up domain names
in, and C<lookuptype> is the type of lookup (B<TXT> or B<A>).

C<subtest> is a sub-test to run against the returned data.  The sub-test may
be in one of the following forms: m, n1-n2, or n/m, where n,n1,n2,m can be
any of: decimal digits, 0x followed by up to 8 hexadecimal digits, or an IPv4
address in quad-dot form. The 'A' records (IPv4 dotted address) as returned
by DNSBLs lookups are converted into a numerical form (r) and checked against
the specified sub-test as follows:
for a range n1-n2 the following must be true: (r E<gt>= n1 && r E<lt>= n2);
for a n/m form the following must be true: (r & m) == (n & m);
for a single value in quad-dot form the following must be true: r == n;
for a single decimal or hex form the following must be true:
  ((r & n) != 0) && ((r & 0xff000000) == 0x7f000000), i.e. within 127.0.0.0/8

Some typical examples of a sub-test are: 127.0.1.2, 127.0.1.20-127.0.1.39,
127.2.3.0/255.255.255.0, 0.0.0.16/0.0.0.16, 0x10/0x10, 16, 0x10 .

Note that, as with C<urirhsbl>, you must also define a body-eval rule
calling C<check_uridnsbl()> to use this.  Hostname to domain trimming is
also done similarly.

Example:

  urirhssub   URIBL_RHSBL_4    rhsbl.example.org.   A    127.0.0.4
  urirhssub   URIBL_RHSBL_8    rhsbl.example.org.   A    8

=item urinsrhsbl NAME_OF_RULE rhsbl_zone lookuptype

Perform a RHSBL-style domain lookup against the contents of the NS records
for each URI.  In other words, a URI using the domain C<foo.com> will cause
an NS lookup to take place; assuming that domain has an NS of C<ns0.bar.com>,
that will cause a lookup of C<bar.com.uriblzone.net>.  Note that hostnames
are stripped from both the domain used in the URI, and the domain in the
lookup.

C<NAME_OF_RULE> is the name of the rule to be used, C<rhsbl_zone> is the zone
to look up domain names in, and C<lookuptype> is the type of lookup (B<TXT> or
B<A>).

Note that, as with C<urirhsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

=item urinsrhssub NAME_OF_RULE rhsbl_zone lookuptype subtest

Specify a RHSBL-style domain-NS lookup, as above, with a sub-test.
C<NAME_OF_RULE> is the name of the rule to be used, C<rhsbl_zone> is the zone
to look up domain names in, and C<lookuptype> is the type of lookup (B<TXT> or
B<A>).  C<subtest> is the sub-test to run against the returned data; see
C<urirhssub>.

Note that, as with C<urirhsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

=item urifullnsrhsbl NAME_OF_RULE rhsbl_zone lookuptype

Perform a RHSBL-style domain lookup against the contents of the NS records for
each URI.  In other words, a URI using the domain C<foo.com> will cause an NS
lookup to take place; assuming that domain has an NS of C<ns0.bar.com>, that
will cause a lookup of C<ns0.bar.com.uriblzone.net>.

C<NAME_OF_RULE> is the name of the rule to be used, C<rhsbl_zone> is the zone
to look up domain names in, and C<lookuptype> is the type of lookup (B<TXT> or
B<A>).

Note that, as with C<urirhsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

=item urifullnsrhssub NAME_OF_RULE rhsbl_zone lookuptype subtest

Specify a RHSBL-style domain-NS lookup, as above, with a sub-test.
C<NAME_OF_RULE> is the name of the rule to be used, C<rhsbl_zone> is the zone
to look up domain names in, and C<lookuptype> is the type of lookup (B<TXT> or
B<A>).  C<subtest> is the sub-test to run against the returned data; see
C<urirhssub>.

Note that, as with C<urirhsbl>, you must also define a body-eval rule calling
C<check_uridnsbl()> to use this.

=item tflags NAME_OF_RULE ips_only

Only URIs containing IP addresses as the "host" component will be matched
against the named "urirhsbl"/"urirhssub" rule.

=item tflags NAME_OF_RULE domains_only

Only URIs containing a non-IP-address "host" component will be matched against
the named "urirhsbl"/"urirhssub" rule.

=item tflags NAME_OF_RULE ns

The 'ns' flag may be applied to rules corresponding to uridnsbl and uridnssub
directives. Host names from URLs will be mapped to their name server IP
addresses (a NS lookup followed by an A lookup), which in turn will be sent
to blocklists. This is a default when neither 'a' nor 'ns' flags are specified.

=item tflags NAME_OF_RULE a

The 'a' flag may be applied to rules corresponding to uridnsbl and uridnssub
directives. Host names from URLs will be mapped to their IP addresses, which
will be sent to blocklists. When both 'ns' and 'a' flags are specified,
both queries will be performed.

=item tflags NAME_OF_RULE notrim

The full hostname component will be matched against the named
"urirhsbl"/"urirhssub" rule, instead of using the trimmed domain.
This works better, but the specific uribl must support this method.

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item uridnsbl_max_domains N		(default: 20)

The maximum number of domains to look up.

=item parse_dkim_uris ( 0 / 1 )

Include DKIM uris in lookups. This option is documented in
Mail::SpamAssassin::Conf.

=item uridnsbl_skip_mailto ( 0 / 1)	(default: 1)

Skip mailto links on uris lookups.

=back

=head1 NOTES

The C<uridnsbl_timeout> option has been obsoleted by the C<rbl_timeout>
option.  See the C<Mail::SpamAssassin::Conf> POD for details on C<rbl_timeout>.

=cut

package Mail::SpamAssassin::Plugin::URIDNSBL;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(idn_to_ascii reverse_ip_address);
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

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

  $self->register_eval_rule ("check_uridnsbl"); # type does not matter
  $self->set_config($samain->{conf});

  return $self;
}

# this is just a placeholder; in fact the results are dealt with later	 
sub check_uridnsbl {
  my ($self, $pms) = @_;
  return; # return undef for async status
}

# ---------------------------------------------------------------------------

# once the metadata is parsed, we can access the URI list.
# Use check_dnsbl hook to launch lookups at correct time (priority -100)

sub check_dnsbl {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  return if $conf->{skip_uribl_checks};
  return if !$pms->is_dns_available();

  $pms->{uridnsbl_activerules} = [ ];
  $pms->{uridnsbl_hits} = { };
  $pms->{uridnsbl_seen_lookups} = { };

  # only hit DNSBLs for active rules (defined and score != 0)
  $pms->{uridnsbl_active_rules_rhsbl} = { };
  $pms->{uridnsbl_active_rules_rhsbl_ipsonly} = { };
  $pms->{uridnsbl_active_rules_rhsbl_domsonly} = { };
  $pms->{uridnsbl_active_rules_nsrhsbl} = { };
  $pms->{uridnsbl_active_rules_fullnsrhsbl} = { };
  $pms->{uridnsbl_active_rules_nsrevipbl} = { };
  $pms->{uridnsbl_active_rules_arevipbl} = { };

  foreach my $rulename (keys %{$conf->{uridnsbls}}) {
    next if !$conf->{scores}->{$rulename};
    push @{$pms->{uridnsbl_activerules}}, $rulename;

    my $rulecf = $conf->{uridnsbls}->{$rulename};
    my %tfl = map { ($_,1) } split(/\s+/, $conf->{tflags}->{$rulename}||'');

    my $is_rhsbl = $rulecf->{is_rhsbl};
    if (     $is_rhsbl && $tfl{ips_only}) {
      $pms->{uridnsbl_active_rules_rhsbl_ipsonly}->{$rulename} = 1;
    } elsif ($is_rhsbl && $tfl{domains_only}) {
      $pms->{uridnsbl_active_rules_rhsbl_domsonly}->{$rulename} = 1;
    } elsif ($is_rhsbl) {
      $pms->{uridnsbl_active_rules_rhsbl}->{$rulename} = 1;
    } elsif ($rulecf->{is_fullnsrhsbl}) {
      $pms->{uridnsbl_active_rules_fullnsrhsbl}->{$rulename} = 1;
    } elsif ($rulecf->{is_nsrhsbl}) {
      $pms->{uridnsbl_active_rules_nsrhsbl}->{$rulename} = 1;
    } else {  # just a plain dnsbl rule (IP based), not a RHS rule (name-based)
      if ($tfl{a}) {  # tflag 'a' explicitly
        $pms->{uridnsbl_active_rules_arevipbl}->{$rulename} = 1;
      }
      if ($tfl{ns} || !$tfl{a}) {  # tflag 'ns' explicitly, or default
        $pms->{uridnsbl_active_rules_nsrevipbl}->{$rulename} = 1;
      }
    }
  }

  # get all domains in message

  # don't keep dereferencing this
  my $skip_domains = $conf->{uridnsbl_skip_domains} || {};

  # list of hashes to use in order
  my @uri_ordered;

  # Generate the full list of html-parsed domains.
  my $uris = $pms->get_uri_detail_list();

  # go from uri => info to uri_ordered
  # 0: a
  # 1: form
  # 2: img
  # 3: !a_empty
  # 4: parsed
  # 5: a_empty
  my %huris = %{$uris};
  foreach my $uri (keys %huris) {
    my $info = $huris{$uri};
    # we want to skip mailto: uris
    if ($conf->{uridnsbl_skip_mailto}) {
      next if ($uri =~ /^mailto:/i);
    }

    # no hosts/domains were found via this uri, so skip
    next unless ($info->{hosts});

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

    # take the usable domains and add them to the ordered list
    while (my($host,$domain) = each( %{$info->{hosts}} )) {
      if ($skip_domains->{$domain}) {
        dbg("uridnsbl: domain $domain in skip list, host $host");
      }
      elsif ($skip_domains->{$host}) {
        dbg("uridnsbl: host $host in skip list, domain $domain");
      }
      else {
        # use hostname as a key, and drag along the stripped domain name part
        $uri_ordered[$entry]->{$host} = $domain;
      }
    }
  }

  # at this point, @uri_ordered is an ordered array of hostname hashes

  my %hostlist;  # keys are host names, values are their domain parts

  my $umd = $conf->{uridnsbl_max_domains};
  while (keys %hostlist < $umd && @uri_ordered) {
    my $array = shift @uri_ordered;
    next unless $array;

    # run through and find the new domains in this grouping
    my @hosts = grep(!$hostlist{$_}, keys %{$array});
    next unless @hosts;

    # the new hosts are all useful, just add them in
    if (keys(%hostlist) + @hosts <= $umd) {
      foreach my $host (@hosts) {
        $hostlist{$host} = $array->{$host};
      }
    }
    else {
      dbg("uridnsbl: more than $umd URIs, picking a subset");
      # trim down to a limited number - pick randomly
      while (@hosts && keys %hostlist < $umd) {
        my $r = int rand(scalar @hosts);
        my $picked_host = splice(@hosts, $r, 1);
        $hostlist{$picked_host} = $array->{$picked_host};
      }
    }
  }

  my @hnames = sort keys %hostlist;
  $pms->set_tag('URIHOSTS',
                @hnames == 1 ? $hnames[0] : \@hnames);
  my @dnames = do { my %seen; grep { !$seen{$_}++ } sort values %hostlist };
  $pms->set_tag('URIDOMAINS',
                @dnames == 1 ? $dnames[0] : \@dnames);

  # and query
  $self->query_hosts_or_domains($pms, \%hostlist);
}

# Accepts argument in one of the following forms: m, n1-n2, or n/m,
# where n,n1,n2,m can be any of: decimal digits, 0x followed by up to 8
# hexadecimal digits, or an IPv4 address in quad-dot form. The argument
# is checked for syntax (undef is returned on syntax errors), hex numbers
# are converted to decimal, and quad-dot is converted to decimal, then
# reassembled into original string delimited by '-' or '/'. As a special
# backward compatibility measure, a single quad-dot (with no second number)
# is converted into n-n, to distinguish it from a traditional mask-only form.
#
# In practice, arguments like the following are anticipated:
#   127.0.1.2  (same as 127.0.1.2-127.0.1.2 or 127.0.1.2/255.255.255.255)
#   127.0.1.20-127.0.1.39  (= 0x7f000114-0x7f000127 or 2130706708-2130706727)
#   0.0.0.16/0.0.0.16  (same as 0x10/0x10 or 16/0x10 or 16/16)
#   16  (traditional style mask-only, same as 0x10)
#
sub parse_and_canonicalize_subtest {
  my($subtest) = @_;
  my $digested_subtest;

  local($1,$2,$3);
  if ($subtest =~ m{^ ([^/-]+) (?: ([/-]) (.+) )? \z}xs) {
    my($n1,$delim,$n2) = ($1,$2,$3);
    my $any_quad_dot;
    for ($n1,$n2) {
      if (!defined $_) {
        # ok, $n2 may not exist
      } elsif (/^\d{1,10}\z/) {
        # ok, already a decimal number
      } elsif (/^0x[0-9a-zA-Z]{1,8}\z/) {
        $_ = hex($_);  # hex -> number
      } elsif ($_ =~ IS_IPV4_ADDRESS) {
        $_ = Mail::SpamAssassin::Util::my_inet_aton($_);  # quad-dot -> number
        $any_quad_dot = 1;
      } else {
        return;
      }
    }
    $digested_subtest = defined $n2 ? $n1.$delim.$n2
                         : $any_quad_dot ? $n1.'-'.$n1 : "$n1";
  }
  return $digested_subtest;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  push(@cmds, {
    setting => 'skip_uribl_checks',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  push(@cmds, {
    setting => 'uridnsbl_skip_mailto',
    is_admin => 1,
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  push(@cmds, {
    setting => 'uridnsbl_max_domains',
    is_admin => 1,
    default => 20,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push (@cmds, {
    setting => 'uridnsbl',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
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
    setting => 'uridnssub',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3,$4);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)\s+(.*?)\s*$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        my $subrule = $4;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $subrule = parse_and_canonicalize_subtest($subrule);
        defined $subrule or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        $self->{uridnsbls}->{$rulename} = {
         zone => $zone, type => $type,
          is_rhsbl => 0, subtest => $subrule,
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
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
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
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3,$4);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)\s+(.*?)\s*$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        my $subrule = $4;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $subrule = parse_and_canonicalize_subtest($subrule);
        defined $subrule or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_rhsbl => 1, subtest => $subrule,
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
    setting => 'urinsrhsbl',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_nsrhsbl => 1
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
    setting => 'urinsrhssub',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3,$4);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)\s+(.*?)\s*$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        my $subrule = $4;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $subrule = parse_and_canonicalize_subtest($subrule);
        defined $subrule or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_nsrhsbl => 1, subtest => $subrule,
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
    setting => 'urifullnsrhsbl',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_fullnsrhsbl => 1
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
    setting => 'urifullnsrhssub',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2,$3,$4);
      if ($value =~ /^(\w+)\s+(\S+)\s+(\S+)\s+(.*?)\s*$/) {
        my $rulename = $1;
        my $zone = $2;
        my $type = $3;
        my $subrule = $4;
        $zone =~ s/\.\z//;  # strip a redundant trailing dot
        $subrule = parse_and_canonicalize_subtest($subrule);
        defined $subrule or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        $self->{uridnsbls}->{$rulename} = {
	  zone => $zone, type => $type,
          is_fullnsrhsbl => 1, subtest => $subrule,
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
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
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

  push (@cmds, {
    setting => 'clear_uridnsbl_skip_domain',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
        # clear the entire list
        $self->{uridnsbl_skip_domains} = {};
      } else {
        foreach my $domain (split(/\s+/, $value)) {
          delete $self->{uridnsbl_skip_domains}->{lc $domain};
        }
      }
    }
  });

  # obsolete
  push(@cmds, {
    setting => 'uridnsbl_timeout',
    code => sub {
      # not a lint_warn(), since it's pretty harmless and we don't want
      # to break stuff like sa-update
      warn("config: 'uridnsbl_timeout' is obsolete, use 'rbl_timeout' instead");
      return 0;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub query_hosts_or_domains {
  my ($self, $pms, $hosthash_ref) = @_;
  my $conf = $pms->{conf};
  my $seen_lookups = $pms->{uridnsbl_seen_lookups};

  my $rhsblrules = $pms->{uridnsbl_active_rules_rhsbl};
  my $rhsbliprules = $pms->{uridnsbl_active_rules_rhsbl_ipsonly};
  my $rhsbldomrules = $pms->{uridnsbl_active_rules_rhsbl_domsonly};
  my $nsrhsblrules = $pms->{uridnsbl_active_rules_nsrhsbl};
  my $fullnsrhsblrules = $pms->{uridnsbl_active_rules_fullnsrhsbl};
  my $nsreviprules = $pms->{uridnsbl_active_rules_nsrevipbl};
  my $areviprules = $pms->{uridnsbl_active_rules_arevipbl};

  my @nsrules = (
    keys %$nsrhsblrules,
    keys %$fullnsrhsblrules,
    keys %$nsreviprules,
  );

  my %launched_rules;

  while (my($host,$domain) = each(%$hosthash_ref)) {
    $domain = lc $domain;  # just in case
    $host = lc $host;
    dbg("uridnsbl: considering host=$host, domain=$domain");

    # rule names which look up a domain in the basic RHSBL subset
    my @rhsblrules = keys %$rhsblrules;

    # IPv4 look-a-like / IPv6 address literal?
    if ($host =~ /^\d+\.\d+\.\d+\.\d+$/ || $host =~ /^\[/) {
      # only look up the IPv4 if it is public and valid
      if ($host =~ IS_IPV4_ADDRESS && $host !~ IS_IP_PRIVATE) {
        # Use IP in RHSBL lookups
        $domain = $host;
      } else {
        # Skip bogus/private/IPv6 completely
        next;
      }
      # Add ips_only rules to RHSBL checks
      push @rhsblrules, keys %$rhsbliprules;
    } else {
      # perform NS+A or A queries to look up the domain in the non-RHSBL subset,
      # but only if there are active reverse-IP-URIBL rules
      if (!$seen_lookups->{"NS:$domain"} && @nsrules > 0) {
        $seen_lookups->{"NS:$domain"} = 1;
        if ($self->lookup_domain_ns($pms, $domain, \@nsrules)) {
          $launched_rules{$_} = 1  foreach (@nsrules);
        }
      }
      if (!$seen_lookups->{"A:$host"} && %$areviprules) {
        $seen_lookups->{"A:$host"} = 1;
        if ($self->lookup_a_record($pms, $host, [keys %$areviprules])) {
          $launched_rules{$_} = 1  foreach (keys %$areviprules);
        }
      }
      # Add domains_only rules to RHSBL checks
      push @rhsblrules, keys %$rhsbldomrules;
    }

    # Launch RHSBL checks
    foreach my $rulename (@rhsblrules) {
      my $rulecf = $conf->{uridnsbls}->{$rulename};
      # Check notrim tflag to query full hostname (Bug 7835)
      my $query = ($conf->{tflags}->{$rulename}||'') =~ /\bnotrim\b/ ? $host : $domain;
      if ($self->lookup_single_dnsbl($pms, $query, $rulename,
            $rulecf->{zone}, $rulecf->{type})) {
        $launched_rules{$rulename} = 1;
      }
    }
  }

  # mark any rule that was not used ready for metas
  foreach my $rulename (@{$pms->{uridnsbl_activerules}}) {
    $pms->rule_ready($rulename)  unless $launched_rules{$rulename};
  }
}

# ---------------------------------------------------------------------------

sub lookup_domain_ns {
  my ($self, $pms, $lookup, $rules) = @_;

  $lookup = idn_to_ascii($lookup);

  my $ent = {
    rulename => [@$rules],
    type => "URIBL",
    lookup => $lookup,
    domain => $lookup,
  };
  $pms->{async}->bgsend_and_start_lookup($lookup, 'NS', undef, $ent,
    sub { my ($ent,$pkt) = @_; $self->complete_ns_lookup($pms, $ent, $pkt) },
      master_deadline => $pms->{master_deadline} );
}

sub complete_ns_lookup {
  my ($self, $pms, $ent, $pkt) = @_;

  if (!$pkt) {
    # $pkt will be undef if the DNS query was aborted (e.g. timed out)
    dbg("uridnsbl: complete_ns_lookup aborted %s", $ent->{key});
    return;
  }

  dbg("uridnsbl: complete_ns_lookup %s %s", $ent->{key},
    join(',', @{$ent->{rulename}}));
  my $conf = $pms->{conf};
  my @answer = $pkt->answer;

  my $nsrhsblrules = $pms->{uridnsbl_active_rules_nsrhsbl};
  my $fullnsrhsblrules = $pms->{uridnsbl_active_rules_fullnsrhsbl};
  my $areviprules = $pms->{uridnsbl_active_rules_arevipbl};
  my $seen_lookups = $pms->{uridnsbl_seen_lookups};

  my $j = 0;
  foreach my $rr (@answer) {
    $j++;
    my $str = $rr->string;
    next unless defined $str && defined $ent->{lookup};
    $str =~ s/.*\s//; # strip IN NS
    dbg("uridnsbl: got($j) NS for $ent->{lookup}: $str");

    if ($rr->type eq 'NS') {
      my $nsmatch = lc $rr->nsdname;  # available since at least Net::DNS 0.14
      my $nsrhblstr = $nsmatch;
      my $fullnsrhblstr = $nsmatch;

      # It would be very rare to receive IP as NS record, which is a
      # misconfigure. Bind doesn't even allow that..
      if ($nsmatch =~ /^\d+\.\d+\.\d+\.\d+$/ || index($nsmatch, ':') >= 0) {
	# only look up the IP if it is public and valid
	if ($nsmatch =~ IS_IPV4_ADDRESS && $nsmatch !~ IS_IP_PRIVATE) {
          # Use IP in RHSBL lookups
          #$nsrhblstr = $nsmatch; # already set
        } else {
          # Skip bogus/private/IPv6 completely
          next;
        }
      }
      else {
        if (!$seen_lookups->{"A:$nsmatch"}) {
          $seen_lookups->{"A:$nsmatch"} = 1;
          $self->lookup_a_record($pms, $nsmatch, [keys %$areviprules]);
        }
        $nsrhblstr = $self->{main}->{registryboundaries}->trim_domain($nsmatch);
      }

      foreach my $rulename (keys %{$nsrhsblrules}) {
        my $rulecf = $conf->{uridnsbls}->{$rulename};
        $self->lookup_single_dnsbl($pms, $nsrhblstr, $rulename,
          $rulecf->{zone}, $rulecf->{type});
      }

      foreach my $rulename (keys %{$fullnsrhsblrules}) {
        my $rulecf = $conf->{uridnsbls}->{$rulename};
        $self->lookup_single_dnsbl($pms, $fullnsrhblstr, $rulename,
          $rulecf->{zone}, $rulecf->{type});
      }
    }
  }

  # Make sure all finished rules are marked ready.  If foreach block above
  # launched new lookups, rule_ready() simply ignores them.
  foreach my $rulename (@{$ent->{rulename}}) {
    $pms->rule_ready($rulename);
  }
}

# ---------------------------------------------------------------------------

sub lookup_a_record {
  my ($self, $pms, $lookup, $rules) = @_;

  $lookup = idn_to_ascii($lookup);

  my $ent = {
    rulename => [@$rules],
    type => "URIBL",
    lookup => $lookup,
    domain => $lookup,
  };
  $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent,
    sub { my ($ent,$pkt) = @_;
          $self->complete_a_lookup($pms, $ent, $pkt) },
    master_deadline => $pms->{master_deadline}
  );
}

sub complete_a_lookup {
  my ($self, $pms, $ent, $pkt) = @_;

  if (!$pkt) {
    # $pkt will be undef if the DNS query was aborted (e.g. timed out)
    dbg("uridnsbl: complete_a_lookup aborted %s", $ent->{key});
    return;
  }

  dbg("uridnsbl: complete_a_lookup %s %s", $ent->{key},
    join(',', @{$ent->{rulename}}));

  my $j = 0;
  my @answer = $pkt->answer;
  foreach my $rr (@answer) {
    $j++;
    next if $rr->type ne 'A';
    my $ip_address = $rr->address;
    dbg("uridnsbl: complete_a_lookup got(%d) A for %s: %s",
        $j, $ent->{lookup}, $ip_address);
    $self->lookup_dnsbl_for_ip($pms, $ip_address, $ent);
  }

  # Make sure all finished rules are marked ready.  If foreach block above
  # launched new lookups, rule_ready() simply ignores them.
  foreach my $rulename (@{$ent->{rulename}}) {
    $pms->rule_ready($rulename);
  }
}

# ---------------------------------------------------------------------------

sub lookup_dnsbl_for_ip {
  my ($self, $pms, $ip, $ent) = @_;

  my $conf = $pms->{conf};
  foreach my $rulename (@{$ent->{rulename}}) {
    my $rulecf = $conf->{uridnsbls}->{$rulename};
    $self->lookup_single_dnsbl($pms, $ip, $rulename,
      $rulecf->{zone}, $rulecf->{type}, $ent->{domain});
  }
}

sub lookup_single_dnsbl {
  my ($self, $pms, $lookup, $rulename, $zone, $type, $orig_domain) = @_;

  $lookup = idn_to_ascii($lookup);

  my $qkey = "$rulename:$lookup:$zone:$type";
  return if exists $pms->{uridnsbl_seen_lookups}{$qkey};
  $pms->{uridnsbl_seen_lookups}{$qkey} = 1;

  # IP queries need to be reversed
  # Let's do it here, and only here..
  my $domain = $lookup;
  if ($lookup =~ /^\d+\.\d+\.\d+\.\d+$/) {
    $lookup = reverse_ip_address($lookup);
  }

  my $ent = {
    rulename => $rulename,
    type => "URIBL",
    lookup => $lookup,
    domain => $domain,
    orig_domain => $orig_domain,
  };
  $pms->{async}->bgsend_and_start_lookup("$lookup.$zone", $type, undef, $ent,
    sub { my ($ent,$pkt) = @_; $self->complete_dnsbl_lookup($pms, $ent, $pkt) },
    master_deadline => $pms->{master_deadline});
}

sub complete_dnsbl_lookup {
  my ($self, $pms, $ent, $pkt) = @_;

  my $rulename = $ent->{rulename};

  if (!$pkt) {
    # $pkt will be undef if the DNS query was aborted (e.g. timed out)
    dbg("uridnsbl: complete_dnsbl_lookup aborted %s %s",
        $rulename, $ent->{key});
    return;
  }

  $pms->rule_ready($rulename); # mark rule ready for metas
  dbg("uridnsbl: complete_dnsbl_lookup $ent->{key} $rulename");

  my $rulecf = $pms->{conf}->{uridnsbls}->{$rulename};
  my @subtests;
  my @answer = $pkt->answer;
  foreach my $rr (@answer)
  {
    my($rdatastr,$rdatanum);
    my $rr_type = $rr->type;

    if ($rr_type eq 'A') {
      $rdatastr = $rr->address;
      if ($rdatastr =~ IS_IPV4_ADDRESS) {
        $rdatanum = Mail::SpamAssassin::Util::my_inet_aton($rdatastr);
      }
    } elsif ($rr_type eq 'TXT') {
      # txtdata returns a non- zone-file-format encoded result, unlike rdstring;
      # avoid space-separated RDATA <character-string> fields if possible;
      # txtdata provides a list of strings in list context since Net::DNS 0.69
      $rdatastr = join('', $rr->txtdata);
      utf8::encode($rdatastr)  if utf8::is_utf8($rdatastr);
    } else {
      next;
    }

    my $subtest = $rulecf->{subtest};

    dbg("uridnsbl: %s . %s -> %s, %s%s",
        $ent->{domain}, $ent->{zone}, $rdatastr, $rulename,
        !defined $subtest ? '' : ', subtest:'.$subtest);

    my $match;
    if (!defined $subtest) {
      # this zone is a simple rule, not a set of subrules
      # skip any A record that isn't on 127/8
      if ($rr_type eq 'A' && $rdatastr !~ /^127\./) {
	warn("uridnsbl: bogus rr for domain=$ent->{domain}, rule=$rulename, id=" .
            $pkt->header->id." rr=".$rr->string);
	next;
      }
      $match = 1;
    } elsif ($subtest eq $rdatastr) {
      $match = 1;
    } elsif ($subtest =~ m{^ (\d+) (?: ([/-]) (\d+) )? \z}x) {
      my($n1,$delim,$n2) = ($1,$2,$3);
      $match =
        !defined $n2  ? ($rdatanum & $n1) &&                  # mask only
                          (($rdatanum & 0xff000000) == 0x7f000000)  # 127/8
      : $delim eq '-' ? $rdatanum >= $n1 && $rdatanum <= $n2  # range
      : $delim eq '/' ? ($rdatanum & $n2) == (int($n1) & $n2) # value/mask
      : 0; # notice int($n1) to fix perl ~5.14 taint bug (Bug 7725)

      dbg("uridnsbl: %s . %s -> %s, %s, %08x %s %s",
          $ent->{domain}, $ent->{zone}, $rdatastr, $rulename, $rdatanum,
          !defined $n2 ? sprintf('& %08x', $n1)
          : $n1 == $n2 ? sprintf('== %08x', $n1)
          :              sprintf('%08x%s%08x', $n1,$delim,$n2),
          $match ? 'match' : 'no');
    }
    if ($match) {
      $self->got_dnsbl_hit($pms, $ent, $rdatastr, $rulename);
    }
  }
}

sub got_dnsbl_hit {
  my ($self, $pms, $ent, $str, $rulename) = @_;

  $str =~ s/\s+/  /gs;	# long whitespace => short
  dbg("uridnsbl: domain \"$ent->{domain}\" listed ($rulename): $str");

  $pms->{uridnsbl_hits}->{$rulename}->{$ent->{domain}} = 1;

  if (defined $ent->{orig_domain}) {
    $pms->test_log("URI: $ent->{orig_domain}/$ent->{domain}", $rulename);
  } else {
    $pms->test_log("URI: $ent->{domain}", $rulename);
  }
  $pms->got_hit($rulename, '', ruletype => 'eval');
}

# ---------------------------------------------------------------------------

# capability checks for "if can()":
#
sub has_tflags_domains_only { 1 }
sub has_subtest_for_ranges { 1 }
sub has_uridnsbl_for_a { 1 }  # uridnsbl rules recognize tflags 'a' and 'ns'
sub has_uridnsbl_a_ns { 1 }  # has an actually working 'a' flag, unlike above :-(
sub has_tflags_notrim { 1 }  # Bug 7835
sub has_uridnsbl_skip_mailto { 1 }

1;
