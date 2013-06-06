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

RelayCountry - add message metadata indicating the country code of each relay

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::RelayCountry

=head1 DESCRIPTION

The RelayCountry plugin attempts to determine the domain country codes
of each relay used in the delivery path of messages and add that information
to the message metadata as "X-Relay-Countries", or the C<_RELAYCOUNTRY_>
header markup.

=head1 REQUIREMENT

This plugin requires the Geo::IP module from CPAN. For backward
compatibility IP::Country::Fast is used if Geo::IP is not installed.

=cut

package Mail::SpamAssassin::Plugin::RelayCountry;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my ($db, $dbv6);
my $ip_to_cc; # will hold a sub() for the lookup
my $db_info;  # will hold a sub() for database info

# Try to load Geo::IP first
eval {
  require Geo::IP;
  $db = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION, Geo::IP->GEOIP_STANDARD);
  die "GeoIP.dat not found" unless $db;
  # IPv6 requires version Geo::IP 1.39+ with GeoIP C API 1.4.7+
  if (Geo::IP->VERSION >= 1.39 && Geo::IP->api eq 'CAPI') {
    $dbv6 = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION_V6, Geo::IP->GEOIP_STANDARD);
    if (!$dbv6) {
      dbg("metadata: RelayCountry: IPv6 support not enabled, GeoIPv6.dat not found");
    }
  } else {
    dbg("metadata: RelayCountry: IPv6 support not enabled, versions Geo::IP 1.39, GeoIP C API 1.4.7 required");
  }
  $ip_to_cc = sub {
    if ($dbv6 && $_[0] =~ /:/) {
      return $dbv6->country_code_by_addr_v6($_[0]) || "XX";
    } else {
      return $db->country_code_by_addr($_[0]) || "XX";
    }
  };
  $db_info = sub { return "Geo::IP " . ($db->database_info || '?') };
  1;
} or do {
  my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  dbg("metadata: RelayCountry: failed to load 'Geo::IP', skipping: $eval_stat");
  # Try IP::Country::Fast as backup
  eval {
    require IP::Country::Fast;
    $db = IP::Country::Fast->new();
    $ip_to_cc = sub {
      return $db->inet_atocc($_[0]) || "XX";
    };
    $db_info = sub { return "IP::Country::Fast ".localtime($db->db_time()); };
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("metadata: RelayCountry: failed to load 'IP::Country::Fast', skipping: $eval_stat");
    return 1;
  };
};

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);
  return $self;
}

sub extract_metadata {
  my ($self, $opts) = @_;

  return 1 unless $db;

  dbg("metadata: RelayCountry: Using database: ".$db_info->());
  my $msg = $opts->{msg};

  my $countries = '';
  my $IP_PRIVATE = IP_PRIVATE;
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    # Private IPs will always be returned as '**'
    my $cc = $ip =~ /^$IP_PRIVATE$/o ? '**' : $ip_to_cc->($ip);
    $countries .= $cc." ";
  }

  chop $countries;
  $msg->put_metadata("X-Relay-Countries", $countries);
  dbg("metadata: X-Relay-Countries: $countries");

  return 1;
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  return 1 unless $db;

  my $countries =
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries');
  my @c_list = split(' ', $countries);
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRY",
                                 @c_list == 1 ? $c_list[0] : \@c_list);
  return 1;
}

1;
