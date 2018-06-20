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

This plugin requires the Geo::IP or IP::Country::Fast module from CPAN.
For backward compatibility IP::Country::Fast is used if Geo::IP is 
not installed.

=cut

package Mail::SpamAssassin::Plugin::RelayCountry;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $db;
my $dbv6;
my $db_info;  # will hold database info
my $db_type;  # will hold database type

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=over 4

=item country_db_type STRING

This option tells SpamAssassin which type of Geo database to use.
Valid database types are GeoIP and Fast.

=back

=cut

  push (@cmds, {
    setting => 'country_db_type',
    default => "GeoIP",
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ( $value !~ /GeoIP|Fast/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{country_db_type} = $value;
    }
  });
  
  $conf->{parser}->register_commands(\@cmds);
}

sub extract_metadata {
  my ($self, $opts) = @_;
  my $geo;
  my $cc;

  my $conf_country_db_type = $self->{'main'}{'resolver'}{'conf'}->{country_db_type};

  if ( $conf_country_db_type eq "GeoIP") {
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
       $db_info = sub { return "Geo::IP " . ($db->database_info || '?') };
      } else {
       dbg("metadata: RelayCountry: IPv6 support not enabled, versions Geo::IP 1.39, GeoIP C API 1.4.7 required");
      }
   } or do {
     # Fallback to IP::Country::Fast
     dbg("metadata: RelayCountry: GeoIP.dat not found, IP::Country::Fast enabled as fallback");
     $conf_country_db_type = "Fast";
   }
  }
  if( $conf_country_db_type eq "Fast") {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # Try IP::Country::Fast as backup
    eval {
      require IP::Country::Fast;
      $db = IP::Country::Fast->new();
      $db_info = sub { return "IP::Country::Fast ".localtime($db->db_time()); };
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("metadata: RelayCountry: failed to load 'IP::Country::Fast', skipping: $eval_stat");
      return 1;
    };
  };

  return 1 unless $db;

  dbg("metadata: RelayCountry: Using database: ".$db_info->());
  my $msg = $opts->{msg};

  my $countries = '';
  my $IP_PRIVATE = IP_PRIVATE;
  my $IPV4_ADDRESS = IPV4_ADDRESS;
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    # Private IPs will always be returned as '**'
    if ( $conf_country_db_type eq "GeoIP" ) {
	  if ( $ip !~ /^$IPV4_ADDRESS$/o ) {
	    if ( defined $dbv6 ) {
	    	$geo = $dbv6->country_code_by_addr_v6($ip) || "XX";
	    } else {
		$geo = "XX";
	    }
	  } else {
	    $geo = $db->country_code_by_addr($ip) || "XX";
	  }
    } elsif ( $conf_country_db_type eq "Fast" ) {
        $geo = $db->inet_atocc($ip) || "XX";
    }
    $cc = $ip =~ /^$IP_PRIVATE$/o ? '**' : $geo;
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
