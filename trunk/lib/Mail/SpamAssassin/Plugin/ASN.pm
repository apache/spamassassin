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

=head1 NAME

Mail::SpamAssassin::Plugin::ASN - SpamAssassin plugin to look up the Autonomous System Number (ASN) of the connecting IP address.

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::ASN

 asn_lookup asn.routeviews.org _ASN_ _ASNCIDR_

 add_header all ASN _ASN_ _ASNCIDR_

=head1 DESCRIPTION

This plugin uses DNS lookups to the services of
C<http://www.routeviews.org/> to do the actual work. Please make sure
that your use of the plugin does not overload their infrastructure -
this generally means that B<you should not use this plugin in a
high-volume environment> or that you should use a local mirror of the
zone (see C<ftp://ftp.routeviews.org/dnszones/>).

=head1 TEMPLATE TAGS

This plugin allows you to create template tags containing the connecting
IP's AS number and route info for that AS number.

The default config will add a header that looks like this:

 X-Spam-ASN: AS24940 213.239.192.0/18

where "AS24940" is the ASN and "213.239.192.0/18" is the route
announced by that ASN where the connecting IP address came from. If
the AS announces multiple networks (more/less specific), they will
all be added to the C<_ASNCIDR_> tag, separated by spaces, eg:

 X-Spam-ASN: AS1680 89.138.0.0/15 89.139.0.0/16 

=head1 CONFIGURATION

The standard ruleset contains a configuration that will add a header
containing ASN data to scanned messages.  The bayes tokenizer will use the
added header for bayes calculations, and thus affect which BAYES_* rule will
trigger for a particular message.

B<Note> that in most cases you should not score on the ASN data directly.
Bayes learning will probably trigger on the _ASNCIDR_ tag, but probably not
very well on the _ASN_ tag alone.

=head1 SEE ALSO

http://www.routeviews.org/ - all data regarding routing, ASNs etc

http://issues.apache.org/SpamAssassin/show_bug.cgi?id=4770 -
SpamAssassin Issue #4770 concerning this plugin

=head1 STATUS

Experimental - Dec. 18, 2006

No in-depth analysis of the usefulness of bayes tokenization of ASN data has
been performed.

=cut

package Mail::SpamAssassin::Plugin::ASN;

use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
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
  my @cmds = ();

=head1 ADMINISTRATOR SETTINGS

=over 4

=item asn_lookup asn-zone.example.com [ _ASNTAG_ _ASNCIDRTAG_ ]

Use this to lookup the ASN info for first external IP address in the specified
zone and add the AS number to the first specified tag and routing info to the
second specified tag.

If no tags are specified the AS number will be added to the _ASN_ tag and the
routing info will be added to the _ASNCIDR_ tag.  You must specify either none
or both of the tags.  Tags must start and end with an underscore.

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

=cut

  push (@cmds, {
    setting => 'asn_lookup',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      unless ($value =~ /^(\S+?)\.?(?:\s+_(\S+)_\s+_(\S+)_)?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $zone = $1.'.';
      my $asn_tag = (defined $2 ? $2 : 'ASN');
      my $route_tag = (defined $3 ? $3 : 'ASNCIDR');

      push @{$self->{main}->{conf}->{asnlookups}}, { zone=>$zone, asn_tag=>$asn_tag, route_tag=>$route_tag };
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $scanner = $opts->{permsgstatus};
  my $conf = $self->{main}->{conf};

  unless ($conf->{asnlookups}) {
    dbg("asn: no asn_lookup configured, skipping ASN lookups");
    return; # no asn_lookups mean no tags need to be initialized
  }

  # get reversed IP-quad of last external relay to lookup
  # don't return until we've initialized the template tags
  my $reversed_ip_quad;
  my $relay = $scanner->{relays_external}->[0];
  if (!$scanner->is_dns_available()) {
    dbg("asn: DNS is not available, skipping ASN checks");
  } elsif ($relay->{ip_private}) {
    dbg("asn: first external relay is a private IP, skipping ASN check");
  } else {
    if (defined $relay->{ip} && $relay->{ip} =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
      $reversed_ip_quad = "$4.$3.$2.$1";
      dbg("asn: using first external relay IP for lookups: $relay->{ip}");
    } else {
      dbg("asn: could not parse IP from first external relay, skipping ASN check");
    }
  }

  # random note: we use arrays and array indices rather than hashes and hash
  # keys in case someone wants the same zone added to multiple sets of tags
  my $index = 0;
  foreach my $entry (@{$conf->{asnlookups}}) {
    # initialize the tag data so that if no result is returned from the DNS
    # query we won't end up with a missing tag
    unless (defined $scanner->{tag_data}->{$entry->{asn_tag}}) {
      $scanner->{tag_data}->{$entry->{asn_tag}} = '';
    }
    unless (defined $scanner->{tag_data}->{$entry->{route_tag}}) {
      $scanner->{tag_data}->{$entry->{route_tag}} = '';
    }
    next unless $reversed_ip_quad;
  
    # do the DNS query, have the callback process the result rather than poll for them later
    my $zone_index = $index;
    my $id = $scanner->{main}->{resolver}->bgsend("${reversed_ip_quad}.$entry->{zone}", 'TXT', undef, sub {
      my $pkt = shift;
      $self->process_dns_result($scanner, $pkt, $zone_index);
    });

    $scanner->{async}->start_lookup({ key=>"asnlookup-${zone_index}-$entry->{zone}", id=>$id, type=>'TXT' });
    dbg("asn: launched DNS TXT query for ${reversed_ip_quad}.$entry->{zone} in background");

    $index++;
  }
}

sub process_dns_result {
  my ($self, $scanner, $response, $zone_index) = @_;

  my $conf = $self->{main}->{conf};

  my $zone = $conf->{asnlookups}[$zone_index]->{zone};
  my $asn_tag = $conf->{asnlookups}[$zone_index]->{asn_tag};
  my $route_tag = $conf->{asnlookups}[$zone_index]->{route_tag};

  my @answer = $response->answer;

  foreach my $rr (@answer) {
    dbg("asn: $zone: lookup result packet: '".$rr->string."'");
    if ($rr->type eq 'TXT') {
      my @items = split(/ /, $rr->txtdata);
      unless ($#items == 2) {
        dbg("asn: TXT query response format unknown, ignoring zone: $zone response: '".$rr->txtdata."'");
        next;
      }
      unless ($scanner->{tag_data}->{$asn_tag} =~ /\bAS$items[0]\b/) {
        if ($scanner->{tag_data}->{$asn_tag}) {
          $scanner->{tag_data}->{$asn_tag} .= " AS$items[0]";
        } else {
          $scanner->{tag_data}->{$asn_tag} = "AS$items[0]";
        }
      }
      unless ($scanner->{tag_data}->{$route_tag} =~ m{\b$items[1]/$items[2]\b}) {
        if ($scanner->{tag_data}->{$route_tag}) {
          $scanner->{tag_data}->{$route_tag} .= " $items[1]/$items[2]";
        } else {
          $scanner->{tag_data}->{$route_tag} = "$items[1]/$items[2]";
        }
      }
    }
  }

  return;
}

1;
