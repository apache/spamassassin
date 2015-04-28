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
#   asn_lookup origin6.asn.cymru.com [_ASN_ _ASNCIDR_]

=head1 NAME

Mail::SpamAssassin::Plugin::ASN - SpamAssassin plugin to look up the
Autonomous System Number (ASN) of the connecting IP address.

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::ASN

 asn_lookup asn.routeviews.org _ASN_ _ASNCIDR_

 add_header all ASN _ASN_ _ASNCIDR_

=head1 DESCRIPTION

This plugin uses DNS lookups to the services of an external DNS zone such
as at C<http://www.routeviews.org/> to do the actual work. Please make
sure that your use of the plugin does not overload their infrastructure -
this generally means that B<you should not use this plugin in a
high-volume environment> or that you should use a local mirror of the
zone (see C<ftp://ftp.routeviews.org/dnszones/>).  Other similar zones
may also be used.

=head1 TEMPLATE TAGS

This plugin allows you to create template tags containing the connecting
IP's AS number and route info for that AS number.

The default config will add a header field that looks like this:

 X-Spam-ASN: AS24940 213.239.192.0/18

where "24940" is the ASN and "213.239.192.0/18" is the route
announced by that ASN where the connecting IP address came from.
If the AS announces multiple networks (more/less specific), they will
all be added to the C<_ASNCIDR_> tag, separated by spaces, eg:

 X-Spam-ASN: AS1680 89.138.0.0/15 89.139.0.0/16

Note that the literal "AS" before the ASN in the _ASN_ tag is configurable
through the I<asn_prefix> directive and may be set to an empty string.

=head1 CONFIGURATION

The standard ruleset contains a configuration that will add a header field
containing ASN data to scanned messages.  The bayes tokenizer will use the
added header field for bayes calculations, and thus affect which BAYES_* rule
will trigger for a particular message.

B<Note> that in most cases you should not score on the ASN data directly.
Bayes learning will probably trigger on the _ASNCIDR_ tag, but probably not
very well on the _ASN_ tag alone.

=head1 SEE ALSO

http://www.routeviews.org/ - all data regarding routing, ASNs, etc....

http://issues.apache.org/SpamAssassin/show_bug.cgi?id=4770 -
SpamAssassin Issue #4770 concerning this plugin

=head1 STATUS

No in-depth analysis of the usefulness of bayes tokenization of ASN data has
been performed.

=cut

package Mail::SpamAssassin::Plugin::ASN;

use strict;
use warnings;
use re 'taint';
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(reverse_ip_address);
use Mail::SpamAssassin::Dns;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->set_config($mailsa->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 ADMINISTRATOR SETTINGS

=over 4

=item asn_lookup asn-zone.example.com [ _ASNTAG_ _ASNCIDRTAG_ ]

Use this to lookup the ASN info in the specified zone for the first external
IP address and add the AS number to the first specified tag and routing info
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

=back

=over 4

=item clear_asn_lookups

=back

Removes any previously declared I<asn_lookup> entries from a list of queries.

=over 4

=item asn_prefix 'prefix_string'       (default: 'AS')

The string specified in the argument is prepended to each ASN when storing
it as a tag. This prefix is rather redundant, but its default value 'AS'
is kept for backward compatibility with versions of SpamAssassin earlier
than 3.4.0. A sensible setting is an empty string. The argument may be (but
need not be) enclosed in single or double quotes for clarity.

=back

=cut

  push (@cmds, {
    setting => 'asn_lookup',
    is_admin => 1,
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
    setting => 'clear_asn_lookups',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      if (defined $value && $value ne '') {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      delete $conf->{asnlookups};
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

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $self->{main}->{conf};

  unless ($conf->{asnlookups}) {
    dbg("asn: no asn_lookup configured, skipping ASN lookups");
    return; # no asn_lookups mean no tags need to be initialized
  }

  # get reversed IP address of last external relay to lookup
  # don't return until we've initialized the template tags
  my($ip,$reversed_ip);
  my $relay = $pms->{relays_external}->[0];
  $ip = $relay->{ip}  if defined $relay;
  if (!$pms->is_dns_available()) {
    dbg("asn: DNS is not available, skipping ASN checks");
  } elsif (!defined $ip) {
    dbg("asn: no first external relay IP available, skipping ASN check");
  } elsif ($relay->{ip_private}) {
    dbg("asn: first external relay is a private IP, skipping ASN check");
  } else {
    $reversed_ip = reverse_ip_address($ip);
    if (defined $reversed_ip) {
      dbg("asn: using first external relay IP for lookups: %s", $ip);
    } else {
      dbg("asn: could not parse first external relay IP: %s, skipping", $ip);
    }
  }

  # we use arrays and array indices rather than hashes and hash keys
  # in case someone wants the same zone added to multiple sets of tags
  my $index = 0;
  foreach my $entry (@{$conf->{asnlookups}}) {
    # initialize the tag data so that if no result is returned from the DNS
    # query we won't end up with a missing tag.  Don't use $pms->set_tag()
    # here to avoid triggering any tag-dependent action unnecessarily
    unless (defined $pms->{tag_data}->{$entry->{asn_tag}}) {
      $pms->{tag_data}->{$entry->{asn_tag}} = '';
    }
    unless (defined $pms->{tag_data}->{$entry->{route_tag}}) {
      $pms->{tag_data}->{$entry->{route_tag}} = '';
    }
    next unless $reversed_ip;

    # do the DNS query, have the callback process the result
    my $zone_index = $index;
    my $zone = $reversed_ip . '.' . $entry->{zone};
    my $key = "asnlookup-${zone_index}-$entry->{zone}";
    my $ent = $pms->{async}->bgsend_and_start_lookup(
        $zone, 'TXT', undef,
        { key => $key, zone => $zone },
        sub { my($ent, $pkt) = @_;
              $self->process_dns_result($pms, $pkt, $zone_index) },
      master_deadline => $pms->{master_deadline} );
    if ($ent) {
      dbg("asn: launched DNS TXT query for %s.%s in background",
          $reversed_ip, $entry->{zone});
      $index++;
    }
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
  my ($self, $pms, $pkt, $zone_index) = @_;

  my $conf = $self->{main}->{conf};

  my $zone = $conf->{asnlookups}[$zone_index]->{zone};
  my $asn_tag = $conf->{asnlookups}[$zone_index]->{asn_tag};
  my $route_tag = $conf->{asnlookups}[$zone_index]->{route_tag};

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

  # NOTE: $pkt will be undef if the DNS query was aborted (e.g. timed out)
  my @answer = !defined $pkt ? () : $pkt->answer;

  foreach my $rr (@answer) {
    dbg("asn: %s: lookup result packet: %s", $zone, $rr->string);
    next if $rr->type ne 'TXT';
    my @strings = $rr->char_str_list;
    next if !@strings;

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
    $pms->{msg}->put_metadata('X-ASN-Route', join(' ',@route_tag_data));
    $pms->set_tag($route_tag,
                  @route_tag_data == 1 ? $route_tag_data[0] : \@route_tag_data);
  }
}

1;
