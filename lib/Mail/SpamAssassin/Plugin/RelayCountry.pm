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

This plugin uses Mail::SpamAssassin::GeoDB and requires a module supported
by it, for example GeoIP2::Database::Reader.

=cut

package Mail::SpamAssassin::Plugin::RelayCountry;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
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

  # we need GeoDB country
  $self->{main}->{geodb_wanted}->{country} = 1;

  return $self;
}

sub extract_metadata {
  my ($self, $opts) = @_;
  
  return if $self->{relaycountry_disabled};

  if (!$self->{main}->{geodb} ||
        !$self->{main}->{geodb}->can('country')) {
    dbg("metadata: RelayCountry: plugin disabled, GeoDB country not available");
    $self->{relaycountry_disabled} = 1;
    return;
  }

  my $msg = $opts->{msg};
  my $geodb = $self->{main}->{geodb};

  my $countries = '';
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    my $cc = $geodb->get_country($ip);
    $countries .= $cc." ";
  }

  chop $countries;
  $msg->put_metadata("X-Relay-Countries", $countries);
  dbg("metadata: X-Relay-Countries: $countries");
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  return 1 if $self->{relaycountry_disabled};

  my $countries =
    $opts->{permsgstatus}->get_message->get_metadata('X-Relay-Countries');
  my @c_list = split(' ', $countries);
  $opts->{permsgstatus}->set_tag("RELAYCOUNTRY",
                                 @c_list == 1 ? $c_list[0] : \@c_list);
  return 1;
}

1;
