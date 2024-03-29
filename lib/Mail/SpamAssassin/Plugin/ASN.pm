# SpamAssassin - ASN Lookup Plugin
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
#
###########################################################################
#
# Originated by Matthias Leisi, 2006-12-15 (SpamAssassin enhancement #4770).
# Modifications by D. Stussy, 2010-12-15 (SpamAssassin enhancement #6484):
#
# Since SA 3.4.0 a fixed text prefix (such as AS) to each ASN is configurable
# through an asn_prefix directive. Its value is 'AS' by default for backward
# compatibility with SA 3.3.*, but is rather redundant and can be set to an
# empty string for clarity if desired.
#
# Enhanced TXT-RR decoding for alternative formats from other DNS zones.
# Some of the supported formats of TXT RR are (quoted strings here represent
# individual string fields in a TXT RR):
#   "1103" "192.88.99.0" "24"
#   "559 1103 1239 1257 1299 | 192.88.99.0/24 | US | iana | 2001-06-01"
#   "192.88.99.0/24 | AS1103 | SURFnet, The Netherlands | 2002-10-15 | EU"
#   "15169 | 2a00:1450::/32 | IE | ripencc | 2009-10-05"
#   "as1103"
# Multiple routes are sometimes provided by returning multiple TXT records
# (e.g. from cymru.com). This form of a response is handled as well.
#
# Some zones also support IPv6 lookups, for example:
#   asn_lookup_ipv6 origin6.asn.cymru.com [_ASN_ _ASNCIDR_]

=head1 NAME

Mail::SpamAssassin::Plugin::ASN - SpamAssassin plugin to look up the
Autonomous System Number (ASN) of the connecting IP address.

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::ASN

 # Default / recommended settings
 asn_use_geodb 1
 asn_use_dns 1
 asn_prefer_geodb 1

 # Do lookups and add tags / X-Spam-ASN header
 asn_lookup asn.routeviews.org _ASN_ _ASNCIDR_
 asn_lookup_ipv6 origin6.asn.cymru.com _ASN_ _ASNCIDR_
 add_header all ASN _ASN_ _ASNCIDR_

 # Rules to test ASN or Organization
 # NOTE: Do not use rules that check metadata X-ASN header,
 # only check_asn() eval function works correctly.
 # Rule argument is full regexp to match.

 # ASN Number: GeoIP ASN or DNS
 # Matched string includes asn_prefix if defined, and normally
 # looks like "AS1234" (DNS) or "AS1234 Google LLC" (GeoIP)
 header AS_1234 eval:check_asn('/^AS1234\b/')

 # ASN Organisation: GeoIP ASN has, DNS lists might not have
 # Note the second parameter which checks MYASN tag (default is ASN)
 asn_lookup myview.example.com _MYASN_ _MYASNCIDR_
 header AS_GOOGLE eval:check_asn('/\bGoogle\b/i', 'MYASN')

=head1 DESCRIPTION

This plugin uses DNS lookups to the services of an external DNS zone such
as at C<https://www.routeviews.org/> to do the actual work. Please make
sure that your use of the plugin does not overload their infrastructure -
this generally means that B<you should not use this plugin in a
high-volume environment> or that you should use a local mirror of the
zone (see C<ftp://ftp.routeviews.org/dnszones/>).  Other similar zones
may also be used.

GeoDB (GeoIP ASN) database lookups are supported since SpamAssassin 4.0 and
it's recommended to use them instead of DNS queries, unless C<_ASNCIDR_>
is needed.

=head1 TEMPLATE TAGS

This plugin allows you to create template tags containing the connecting
IP's AS number and route info for that AS number.

If you use add_header as documented in the example before, a header field is
added that looks like this:

 X-Spam-ASN: AS24940 213.239.192.0/18

where "24940" is the ASN and "213.239.192.0/18" is the route
announced by that ASN where the connecting IP address came from.
If the AS announces multiple networks (more/less specific), they will
all be added to the C<_ASNCIDR_> tag, separated by spaces, eg:

 X-Spam-ASN: AS1680 89.138.0.0/15 89.139.0.0/16

Note that the literal "AS" before the ASN in the _ASN_ tag is configurable
through the I<asn_prefix> directive and may be set to an empty string.

C<_ASNCIDR_> is not available with local GeoDB ASN lookups.

=head1 USER SETTINGS

=over 4

=item clear_asn_lookups

Removes all previously declared I<asn_lookup> or I<asn_lookup_ipv6> entries
from the list of queries.

=item asn_prefix 'prefix_string'       (default: 'AS')

The string specified in the argument is prepended to each ASN when storing
it as a tag. This prefix is rather redundant, but its default value 'AS'
is kept for backward compatibility with versions of SpamAssassin earlier
than 3.4.0. A sensible setting is an empty string. The argument may be (but
need not be) enclosed in single or double quotes for clarity.

=back

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=over 4

=item asn_lookup asn-zone.example.com [ _ASNTAG_ _ASNCIDRTAG_ ]

Use this to lookup the ASN info in the specified zone for the first external
IPv4 address and add the AS number to the first specified tag and routing info
to the second specified tag.

If no tags are specified the AS number will be added to the _ASN_ tag and the
routing info will be added to the _ASNCIDR_ tag.  You must specify either none
or both of the tag names.  Tag names must start and end with an underscore.

If two or more I<asn_lookup>s use the same set of template tags, the results of
their lookups will be appended to each other in the template tag values in no
particular order.  Duplicate results will be omitted when combining results.
In a similar fashion, you can also use the same template tag for both the AS
number tag and the routing info tag.

Examples:

  asn_lookup asn.routeviews.org

  asn_lookup asn.routeviews.org _ASN_ _ASNCIDR_
  asn_lookup myview.example.com _MYASN_ _MYASNCIDR_

  asn_lookup asn.routeviews.org _COMBINEDASN_ _COMBINEDASNCIDR_
  asn_lookup myview.example.com _COMBINEDASN_ _COMBINEDASNCIDR_

  asn_lookup in1tag.example.net _ASNDATA_ _ASNDATA_

=item asn_lookup_ipv6 asn-zone6.example.com [_ASN_ _ASNCIDR_]

Use specified zone for lookups of IPv6 addresses.  If zone supports both
IPv4 and IPv6 queries, use both asn_lookup and asn_lookup_ipv6 for the same
zone.

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item asn_use_geodb ( 0 / 1 )          (default: 1)

Use Mail::SpamAssassin::GeoDB module to lookup ASN numbers.  You need
suitable supported module like GeoIP2 or GeoIP with ISP or ASN database
installed (for example, add EditionIDs GeoLite2-ASN in GeoIP.conf for
geoipupdate program).

GeoDB can only set _ASN_ tag, it has no data for _ASNCIDR_.  If you need
both, then set asn_prefer_geodb 0 so DNS rules are tried.

=item asn_prefer_geodb ( 0 / 1 )       (default: 1)

If set, DNS lookups (asn_lookup rules) will not be run if GeoDB successfully
finds ASN. Set this to 0 to get _ASNCIDR_ even if GeoDB finds _ASN_.

=item asn_use_dns ( 0 / 1 )            (default: 1)

Set to 0 to never allow DNS queries.

=back

=head1 BAYES

The bayes tokenizer will use ASN data for bayes calculations, and thus
affect which BAYES_* rule will trigger for a particular message.  No
in-depth analysis of the usefulness of bayes tokenization of ASN data has
been performed.

=head1 SEE ALSO

https://www.routeviews.org/ - all data regarding routing, ASNs, etc....

=cut

package Mail::SpamAssassin::Plugin::ASN;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(reverse_ip_address compile_regexp);
use Mail::SpamAssassin::Constants qw(:ip);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->register_eval_rule("check_asn", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  $self->set_config($mailsa->{conf});

  # we need GeoDB ASN
  $self->{main}->{geodb_wanted}->{asn} = 1;

  return $self;
}

###########################################################################

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'asn_lookup',
    is_priv => 1,
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      local($1,$2,$3);
      unless ($value =~ /^(\S+?)\.?(?:\s+_(\S+)_\s+_(\S+)_)?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my ($zone, $asn_tag, $route_tag) = ($1, $2, $3);
      $asn_tag   = 'ASN'     if !defined $asn_tag;
      $route_tag = 'ASNCIDR' if !defined $route_tag;
      push @{$conf->{asnlookups}},
           { zone=>$zone, asn_tag=>$asn_tag, route_tag=>$route_tag };
    }
  });

  push (@cmds, {
    setting => 'asn_lookup_ipv6',
    is_priv => 1,
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      local($1,$2,$3);
      unless ($value =~ /^(\S+?)\.?(?:\s+_(\S+)_\s+_(\S+)_)?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my ($zone, $asn_tag, $route_tag) = ($1, $2, $3);
      $asn_tag   = 'ASN'     if !defined $asn_tag;
      $route_tag = 'ASNCIDR' if !defined $route_tag;
      push @{$conf->{asnlookups_ipv6}},
           { zone=>$zone, asn_tag=>$asn_tag, route_tag=>$route_tag };
    }
  });

  push (@cmds, {
    setting => 'clear_asn_lookups',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      if (defined $value && $value ne '') {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      delete $conf->{asnlookups};
      delete $conf->{asnlookups_ipv6};
    }
  });

  push (@cmds, {
    setting => 'asn_prefix',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    default => 'AS',
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      $value = ''  if !defined $value;
      local($1,$2);
      $value = $2  if $value =~ /^(['"])(.*)\1\z/;  # strip quotes if any
      $conf->{$key} = $value;  # keep tainted
    }
  });

  push (@cmds, {
    setting => 'asn_use_geodb',
    default => 1,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  push (@cmds, {
    setting => 'asn_prefer_geodb',
    default => 1,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  push (@cmds, {
    setting => 'asn_use_dns',
    default => 1,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub extract_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  my $geodb = $self->{main}->{geodb};
  my $has_geodb = $conf->{asn_use_geodb} && $geodb && $geodb->can('asn');
  if ($has_geodb) {
    dbg("asn: using GeoDB ASN for lookups");
  } else {
    dbg("asn: GeoDB ASN not available");
    if (!$conf->{asn_use_dns} || !$pms->is_dns_available()) {
      dbg("asn: DNS is not available, skipping ASN check");
      return;
    }
    if ($self->{main}->{learning}) {
      dbg("asn: learning message, skipping DNS-based ASN check");
      return;
    }
  }

  # initialize the tag data so that if no result is returned from the DNS
  # query we won't end up with a missing tag.  Don't use $pms->set_tag()
  # here to avoid triggering any tag-dependent action unnecessarily
  if ($conf->{asnlookups}) {
    foreach my $entry (@{$conf->{asnlookups}}) {
      $pms->{tag_data}->{$entry->{asn_tag}} ||= '';
      $pms->{tag_data}->{$entry->{route_tag}} ||= '';
    }
  }
  if ($conf->{asnlookups_ipv6}) {
    foreach my $entry (@{$conf->{asnlookups_ipv6}}) {
      $pms->{tag_data}->{$entry->{asn_tag}} ||= '';
      $pms->{tag_data}->{$entry->{route_tag}} ||= '';
    }
  }

  # Initialize status
  $pms->{asn_results} = ();

  # get IP address of last external relay to lookup
  my $relay = $opts->{msg}->{metadata}->{relays_external}->[0];
  if (!defined $relay) {
    dbg("asn: no first external relay IP available, skipping ASN check");
    return;
  } elsif ($relay->{ip_private}) {
    dbg("asn: first external relay is a private IP, skipping ASN check");
    return;
  }
  my $ip = $relay->{ip};
  dbg("asn: using first external relay IP for lookups: %s", $ip);

  # GeoDB lookup
  my $asn_found;
  if ($has_geodb) {
    my $asn = $geodb->get_asn($ip);
    my $org = $geodb->get_asn_org($ip);
    if (!defined $asn) {
      dbg("asn: GeoDB ASN lookup failed");
    } else {
      $asn_found = 1;
      dbg("asn: GeoDB found ASN $asn");
      # Prevent double prefix
      my $asn_value =
        length($conf->{asn_prefix}) && index($asn, $conf->{asn_prefix}) != 0 ?
          $conf->{asn_prefix}.$asn : $asn;
      $asn_value .= ' '.$org if defined $org && length($org);
      $pms->set_tag('ASN', $asn_value);
      # For Bayes
      $pms->{msg}->put_metadata('X-ASN', $asn);
    }
  }

  # Skip DNS if GeoDB was successful and preferred
  if ($asn_found && $conf->{asn_prefer_geodb}) {
    dbg("asn: GeoDB lookup successful, skipping DNS lookups");
    return;
  }

  # No point continuing without DNS from now on
  if (!$conf->{asn_use_dns} || !$pms->is_dns_available()) {
    dbg("asn: skipping disabled DNS lookups");
    return;
  }

  dbg("asn: using DNS for lookups");
  my $lookup_zone;
  if ($ip =~ IS_IPV4_ADDRESS) {
    if (!defined $conf->{asnlookups}) {
      dbg("asn: asn_lookup for IPv4 not defined, skipping");
      return;
    }
    $lookup_zone = "asnlookups";
  } else {
    if (!defined $conf->{asnlookups_ipv6}) {
      dbg("asn: asn_lookup_ipv6 for IPv6 not defined, skipping");
      return;
    }
    $lookup_zone = "asnlookups_ipv6";
  }
  
  my $reversed_ip = reverse_ip_address($ip);
  if (!defined $reversed_ip) {
    dbg("asn: could not parse IP: %s, skipping", $ip);
    return;
  }

  # we use arrays and array indices rather than hashes and hash keys
  # in case someone wants the same zone added to multiple sets of tags
  my $index = 0;
  foreach my $entry (@{$conf->{$lookup_zone}}) {
    # do the DNS query, have the callback process the result
    my $zone_index = $index;
    my $zone = $reversed_ip . '.' . $entry->{zone};
    $pms->{async}->bgsend_and_start_lookup($zone, 'TXT', undef,
      { rulename => 'asn_lookup', type => 'ASN' },
      sub { my($ent, $pkt) = @_;
            $self->process_dns_result($pms, $pkt, $zone_index, $lookup_zone) },
      master_deadline => $pms->{master_deadline}
    );
    $index++;
  }
}

#
# TXT-RR format of response:
#    3 fields, each as one TXT RR <character-string> (RFC 1035): ASN IP MASK
#       The latter two fields are combined to create a CIDR.
#    or:  At least 2 fields made of a single or multiple
#       <character-string>s, fields are separated by a vertical bar.
#       They will be the ASN and CIDR fields in any order.
#    If only one field is returned, it is the ASN.  There will
#       be no CIDR field in that case.
#
sub process_dns_result {
  my ($self, $pms, $pkt, $zone_index, $lookup_zone) = @_;

  # NOTE: $pkt will be undef if the DNS query was aborted (e.g. timed out)
  return if !$pkt;

  my $conf = $self->{main}->{conf};

  my $zone = $conf->{$lookup_zone}[$zone_index]->{zone};
  my $asn_tag = $conf->{$lookup_zone}[$zone_index]->{asn_tag};
  my $route_tag = $conf->{$lookup_zone}[$zone_index]->{route_tag};

  my($any_asn_updates, $any_route_updates, $tag_value);

  my(@asn_tag_data, %asn_tag_data_seen);
  $tag_value = $pms->get_tag($asn_tag);
  if (defined $tag_value) {
    my $prefix = $pms->{conf}->{asn_prefix};
    if (defined $prefix && $prefix ne '') {
      # must strip prefix before splitting on whitespace
      $tag_value =~ s/(^| )\Q$prefix\E(?=\d+)/$1/gs;
    }
    @asn_tag_data = split(/ /,$tag_value);
    %asn_tag_data_seen = map(($_,1), @asn_tag_data);
  }

  my(@route_tag_data, %route_tag_data_seen);
  $tag_value = $pms->get_tag($route_tag);
  if (defined $tag_value) {
    @route_tag_data = split(/ /,$tag_value);
    %route_tag_data_seen = map(($_,1), @route_tag_data);
  }

  foreach my $rr ($pkt->answer) {
    #dbg("asn: %s: lookup result packet: %s", $zone, $rr->string);
    next if $rr->type ne 'TXT';
    my @strings = $rr->txtdata;
    next if !@strings;
    for (@strings) { utf8::encode($_) if utf8::is_utf8($_) }

    my @items;
    if (@strings > 1 && join('',@strings) !~ m{\|}) {
      # routeviews.org style, multiple string fields in a TXT RR
      @items = @strings;
      if (@items >= 3 && $items[1] !~ m{/} && $items[2] =~ /^\d+\z/) {
        $items[1] .= '/' . $items[2];  # append the net mask length to route
      }
    } else {
      # cymru.com and spameatingmonkey.net style, or just a single field
      @items = split(/\s*\|\s*/, join(' ',@strings));
    }

    my(@route_value, @asn_value);
    if (@items && $items[0] =~ /(?: (?:^|\s+) (?:AS)? \d+ )+ \z/xsi) {
      # routeviews.org and cymru.com style, ASN is the first field,
      # possibly a whitespace-separated list (e.g. cymru.com)
      @asn_value = split(' ',$items[0]);
      @route_value = split(' ',$items[1])  if @items >= 2;
    } elsif (@items > 1 && $items[1] =~ /(?: (?:^|\s+) (?:AS)? \d+ )+ \z/xsi) {
      # spameatingmonkey.net style, ASN is the second field
      @asn_value = split(' ',$items[1]);
      @route_value = split(' ',$items[0]);
    } else {
      dbg("asn: unparseable response: %s", join(' ', map("\"$_\"",@strings)));
    }

    foreach my $route (@route_value) {
      if (!defined $route || $route eq '') {
        # ignore, just in case
      } elsif ($route =~ m{/0+\z}) {
        # unassigned/unannounced address space
      } elsif ($route_tag_data_seen{$route}) {
        dbg("asn: %s duplicate route %s", $route_tag, $route);
      } else {
        dbg("asn: %s added route %s", $route_tag, $route);
        push(@route_tag_data, $route);
        $route_tag_data_seen{$route} = 1;
        $any_route_updates = 1;
      }
    }

    foreach my $asn (@asn_value) {
      $asn =~ s/^AS(?=\d+)//si;
      if (!$asn || $asn == 4294967295) {
        # unassigned/unannounced address space
      } elsif ($asn_tag_data_seen{$asn}) {
        dbg("asn: %s duplicate asn %s", $asn_tag, $asn);
      } else {
        dbg("asn: %s added asn %s", $asn_tag, $asn);
        push(@asn_tag_data, $asn);
        $asn_tag_data_seen{$asn} = 1;
        $any_asn_updates = 1;
      }
    }
  }

  if ($any_asn_updates && @asn_tag_data) {
    $pms->{msg}->put_metadata('X-ASN', join(' ',@asn_tag_data));
    my $prefix = $pms->{conf}->{asn_prefix};
    if (defined $prefix && $prefix ne '') { s/^/$prefix/ for @asn_tag_data }
    $pms->set_tag($asn_tag,
                  @asn_tag_data == 1 ? $asn_tag_data[0] : \@asn_tag_data);
  }
  if ($any_route_updates && @route_tag_data) {
    # Bayes already has X-ASN, Route is pointless duplicate, skip
    #$pms->{msg}->put_metadata('X-ASN-Route', join(' ',@route_tag_data));
    $pms->set_tag($route_tag,
                  @route_tag_data == 1 ? $route_tag_data[0] : \@route_tag_data);
  }
}

sub check_asn {
  my ($self, $pms, $re, $asn_tag) = @_;

  my $rulename = $pms->get_current_eval_rule_name();
  if (!defined $re) {
    warn "asn: rule $rulename eval argument missing\n";
    return 0;
  }

  my ($rec, $err) = compile_regexp($re, 2);
  if (!$rec) {
    warn "asn: invalid regexp for $rulename '$re': $err\n";
    return 0;
  }

  $asn_tag = 'ASN' unless defined $asn_tag;
  $pms->action_depends_on_tags($asn_tag,
    sub { my($pms,@args) = @_;
      $self->_check_asn($pms, $rulename, $rec, $asn_tag);
    }
  );

  return; # return undef for async status
}

sub _check_asn {
  my ($self, $pms, $rulename, $rec, $asn_tag) = @_;

  $pms->rule_ready($rulename); # mark rule ready for metas

  my $asn = $pms->get_tag($asn_tag);
  return if !defined $asn;

  if ($asn =~ $rec) {
    $pms->test_log("$asn_tag: $asn", $rulename);
    $pms->got_hit($rulename, "");
  }
}

# Version features
sub has_asn_lookup_ipv6 { 1 }
sub has_asn_geodb { 1 }
sub has_check_asn { 1 }
sub has_check_asn_tag { 1 } # $asn_tag parameter for check_asn()

1;
