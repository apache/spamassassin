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
to the message metadata.

Following metadata headers and tags are added:

 X-Relay-Countries           _RELAYCOUNTRY_     all untrusted relays
 X-Relay-Countries-External  _RELAYCOUNTRYEXT_  all external relays
 X-Relay-Countries-MUA       _RELAYCOUNTRYMUA_  all relays after first MSA
 X-Relay-Countries-All       _RELAYCOUNTRYALL_  all relays

=head1 REQUIREMENT

This plugin requires the GeoIP2, Geo::IP, IP::Country::DB_File or 
IP::Country::Fast module from CPAN.
For backward compatibility IP::Country::Fast is used as fallback if no db_type
is specified in the config file.

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
Valid database types are GeoIP, GeoIP2, DB_File and Fast.

=back

=cut

  push (@cmds, {
    setting => 'country_db_type',
    default => "GeoIP",
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ /^(?:GeoIP|GeoIP2|DB_File|Fast)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{country_db_type} = $value;
    }
  });

=over 4

=item country_db_path STRING

This option tells SpamAssassin where to find MaxMind GeoIP2 or IP::Country::DB_File database.

If not defined, GeoIP2 default search includes:
 /usr/local/share/GeoIP/GeoIP2-Country.mmdb
 /usr/share/GeoIP/GeoIP2-Country.mmdb
 /var/lib/GeoIP/GeoIP2-Country.mmdb
 /usr/local/share/GeoIP/GeoLite2-Country.mmdb
 /usr/share/GeoIP/GeoLite2-Country.mmdb
 /var/lib/GeoIP/GeoLite2-Country.mmdb

=back

=cut

  push (@cmds, {
    setting => 'country_db_path',
    default => "",
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if (!-e $value) {
        info("config: country_db_path \"$value\" is not accessible");
        $self->{country_db_path} = $value;
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{country_db_path} = $value;
    }
  });

  push (@cmds, {
    setting => 'geoip2_default_db_path',
    default => [
      '/usr/local/share/GeoIP/GeoIP2-Country.mmdb',
      '/usr/share/GeoIP/GeoIP2-Country.mmdb',
      '/var/lib/GeoIP/GeoIP2-Country.mmdb',
      '/usr/local/share/GeoIP/GeoLite2-Country.mmdb',
      '/usr/share/GeoIP/GeoLite2-Country.mmdb',
      '/var/lib/GeoIP/GeoLite2-Country.mmdb',
      ],
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRINGLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      push(@{$self->{geoip2_default_db_path}}, split(/\s+/, $value));
    }
  });
  
  $conf->{parser}->register_commands(\@cmds);
}

sub get_country {
    my ($self, $ip, $db, $dbv6, $country_db_type) = @_;
    my $cc;
    my $IP_PRIVATE = IP_PRIVATE;
    my $IPV4_ADDRESS = IPV4_ADDRESS;

    # Private IPs will always be returned as '**'
    if ($ip =~ /^$IP_PRIVATE$/o) {
      $cc = "**";
    }
    elsif ($country_db_type eq "GeoIP") {
      if ($ip =~ /^$IPV4_ADDRESS$/o) {
        $cc = $db->country_code_by_addr($ip);
      } elsif (defined $dbv6) {
        $cc = $dbv6->country_code_by_addr_v6($ip);
      }
    }
    elsif ($country_db_type eq "GeoIP2") {
      my ($country, $country_rec);
      eval {
        $country = $db->country( ip => $ip );
        $country_rec = $country->country();
        $cc = $country_rec->iso_code();
        1;
      } or do {
        $@ =~ s/\s+Trace begun.*//s;
        dbg("metadata: RelayCountry: GeoIP2 failed: $@");
      }
    }
    elsif ($country_db_type eq "DB_File") {
      if ($ip =~ /^$IPV4_ADDRESS$/o ) {
        $cc = $db->inet_atocc($ip);
      } else {
        $cc = $db->inet6_atocc($ip);
      }
    }
    elsif ($country_db_type eq "Fast") {
      $cc = $db->inet_atocc($ip);
    }

    $cc ||= 'XX';

    return $cc;
}

sub extract_metadata {
  my ($self, $opts) = @_;

  my $db;
  my $dbv6;
  my $db_info;  # will hold database info
  my $db_type;  # will hold database type

  my $country_db_type = $opts->{conf}->{country_db_type};
  my $country_db_path = $opts->{conf}->{country_db_path};

  if ($country_db_type eq "GeoIP") {
    eval {
      require Geo::IP;
      $db = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION, Geo::IP->GEOIP_STANDARD);
      die "GeoIP.dat not found" unless $db;
      # IPv6 requires version Geo::IP 1.39+ with GeoIP C API 1.4.7+
      if (Geo::IP->VERSION >= 1.39 && Geo::IP->api eq 'CAPI') {
        $dbv6 = Geo::IP->open_type(Geo::IP->GEOIP_COUNTRY_EDITION_V6, Geo::IP->GEOIP_STANDARD);
        if (!$dbv6) {
          dbg("metadata: RelayCountry: GeoIP: IPv6 support not enabled, GeoIPv6.dat not found");
        }
      } else {
        dbg("metadata: RelayCountry: GeoIP: IPv6 support not enabled, versions Geo::IP 1.39, GeoIP C API 1.4.7 required");
      }
      $db_info = sub { return "Geo::IP IPv4: " . ($db->database_info || '?')." / IPv6: ".($dbv6 ? $dbv6->database_info || '?' : '?') };
      1;
    } or do {
      # Fallback to IP::Country::Fast
      dbg("metadata: RelayCountry: GeoIP: GeoIP.dat not found, trying IP::Country::Fast as fallback");
      $country_db_type = "Fast";
    }
  }
  elsif ($country_db_type eq "GeoIP2") {
    if (!$country_db_path) {
      # Try some default locations
      foreach (@{$opts->{conf}->{geoip2_default_db_path}}) {
        if (-f $_) {
          $country_db_path = $_;
          last;
        }
      }
    }
    if (-f $country_db_path) {
      eval {
        require GeoIP2::Database::Reader;
        $db = GeoIP2::Database::Reader->new(
          file => $country_db_path,
          locales => [ 'en' ]
        );
        die "unknown error" unless $db;
        $db_info = sub {
          my $m = $db->metadata();
          return "GeoIP2 ".$m->description()->{en}." / ".localtime($m->build_epoch());
        };
        1;
      } or do {
        # Fallback to IP::Country::Fast
        $@ =~ s/\s+Trace begun.*//s;
        dbg("metadata: RelayCountry: GeoIP2: ${country_db_path} load failed: $@, trying IP::Country::Fast as fallback");
        $country_db_type = "Fast";
      }
    } else {
      # Fallback to IP::Country::Fast
      my $err = $country_db_path ?
        "$country_db_path not found" : "database not found from default locations";
      dbg("metadata: RelayCountry: GeoIP2: $err, trying IP::Country::Fast as fallback");
      $country_db_type = "Fast";
    }
  }
  elsif ($country_db_type eq "DB_File") {
    if (-f $country_db_path) {
      eval {
        require IP::Country::DB_File;
        $db = IP::Country::DB_File->new($country_db_path);
        die "unknown error" unless $db;
        $db_info = sub { return "IP::Country::DB_File ".localtime($db->db_time()); };
        1;
      } or do {
        # Fallback to IP::Country::Fast
        dbg("metadata: RelayCountry: DB_File: ${country_db_path} load failed: $@, trying IP::Country::Fast as fallback");
        $country_db_type = "Fast";
      }
    } else {
      # Fallback to IP::Country::Fast
      dbg("metadata: RelayCountry: DB_File: ${country_db_path} not found, trying IP::Country::Fast as fallback");
      $country_db_type = "Fast";
    }
  } 

  if ($country_db_type eq "Fast") {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    eval {
      require IP::Country::Fast;
      $db = IP::Country::Fast->new();
      $db_info = sub { return "IP::Country::Fast ".localtime($db->db_time()); };
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("metadata: RelayCountry: failed to load 'IP::Country::Fast', skipping: $eval_stat");
      return 1;
    }
  }

  if (!$db) {
    $self->{relaycountry_disabled} = 1;
    return 1;
  }

  dbg("metadata: RelayCountry: Using database: ".$db_info->());
  my $msg = $opts->{msg};

  my @cc_untrusted;
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    my $cc = $self->get_country($ip, $db, $dbv6, $country_db_type);
    push @cc_untrusted, $cc;
  }

  my @cc_external;
  foreach my $relay (@{$msg->{metadata}->{relays_external}}) {
    my $ip = $relay->{ip};
    my $cc = $self->get_country($ip, $db, $dbv6, $country_db_type);
    push @cc_external, $cc;
  }

  my @cc_mua;
  my $found_msa;
  foreach my $relay (@{$msg->{metadata}->{relays_trusted}}) {
    if ($relay->{msa}) {
      $found_msa = 1;
      next;
    }
    if ($found_msa) {
      my $ip = $relay->{ip};
      my $cc = $self->get_country($ip, $db, $dbv6, $country_db_type);
      push @cc_mua, $cc;
    }
  }

  my @cc_all;
  foreach my $relay (@{$msg->{metadata}->{relays_internal}}, @{$msg->{metadata}->{relays_external}}) {
    my $ip = $relay->{ip};
    my $cc = $self->get_country($ip, $db, $dbv6, $country_db_type);
    push @cc_all, $cc;
  }

  my $ccstr = join(' ', @cc_untrusted);
  $msg->put_metadata("X-Relay-Countries", $ccstr);
  dbg("metadata: X-Relay-Countries: $ccstr");

  $ccstr = join(' ', @cc_external);
  $msg->put_metadata("X-Relay-Countries-External", $ccstr);
  dbg("metadata: X-Relay-Countries-External: $ccstr");

  $ccstr = join(' ', @cc_mua);
  $msg->put_metadata("X-Relay-Countries-MUA", $ccstr);
  dbg("metadata: X-Relay-Countries-MUA: $ccstr");

  $ccstr = join(' ', @cc_all);
  $msg->put_metadata("X-Relay-Countries-All", $ccstr);
  dbg("metadata: X-Relay-Countries-All: $ccstr");

  return 1;
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  return 1 if $self->{relaycountry_disabled};

  my @c_list = split(' ',
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries'));
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRY",
                                 @c_list == 1 ? $c_list[0] : \@c_list);

  @c_list = split(' ',
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries-External'));
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRYEXT",
                                 @c_list == 1 ? $c_list[0] : \@c_list);

  @c_list = split(' ',
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries-MUA'));
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRYMUA",
                                 @c_list == 1 ? $c_list[0] : \@c_list);

  @c_list = split(' ',
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries-All'));
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRYALL",
                                 @c_list == 1 ? $c_list[0] : \@c_list);

  return 1;
}

1;
