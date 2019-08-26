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

 X-Relay-Countries           _RELAYCOUNTRY_
   All untrusted relays. Contains all relays starting from the
   trusted_networks border. This method has been used by default since
   early SA versions.

 X-Relay-Countries-External  _RELAYCOUNTRYEXT_
   All external relays. Contains all relays starting from the
   internal_networks border. Could be useful in some cases when
   trusted/msa_networks extend beyond the internal border and those
   need to be checked too.

 X-Relay-Countries-All       _RELAYCOUNTRYALL_
   All possible relays (internal + external).

 X-Relay-Countries-Auth      _RELAYCOUNTRYAUTH_
   Auth will contain all relays starting from the first relay that used
   authentication. For example, this could be used to check for hacked
   local users coming in from unexpected countries. If there are no
   authenticated relays, this will be empty.

=head1 REQUIREMENT

This plugin uses Mail::SpamAssassin::GeoDB and requires a module supported
by it, for example MaxMind::DB::Reader (GeoIP2).

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
  my $pms = $opts->{permsgstatus};
  
  return if $self->{relaycountry_disabled};

  if (!$self->{main}->{geodb} ||
        !$self->{main}->{geodb}->can('country')) {
    dbg("metadata: RelayCountry: plugin disabled, GeoDB country not available");
    $self->{relaycountry_disabled} = 1;
    return;
  }

  my $msg = $opts->{msg};
  my $geodb = $self->{main}->{geodb};

  my @cc_untrusted;
  foreach my $relay (@{$msg->{metadata}->{relays_untrusted}}) {
    my $ip = $relay->{ip};
    my $cc = $geodb->get_country($ip);
    push @cc_untrusted, $cc;
  }

  my @cc_external;
  foreach my $relay (@{$msg->{metadata}->{relays_external}}) {
    my $ip = $relay->{ip};
    my $cc = $geodb->get_country($ip);
    push @cc_external, $cc;
  }

  my @cc_auth;
  my $found_auth;
  foreach my $relay (@{$msg->{metadata}->{relays_trusted}}) {
    if ($relay->{auth}) {
      $found_auth = 1;
    }
    if ($found_auth) {
      my $ip = $relay->{ip};
      my $cc = $geodb->get_country($ip);
      push @cc_auth, $cc;
    }
  }

  my @cc_all;
  foreach my $relay (@{$msg->{metadata}->{relays_internal}}, @{$msg->{metadata}->{relays_external}}) {
    my $ip = $relay->{ip};
    my $cc = $geodb->get_country($ip);
    push @cc_all, $cc;
  }

  my $ccstr = join(' ', @cc_untrusted);
  $msg->put_metadata("X-Relay-Countries", $ccstr);
  dbg("metadata: X-Relay-Countries: $ccstr");
  $pms->set_tag("RELAYCOUNTRY", @cc_untrusted == 1 ? $cc_untrusted[0] : \@cc_untrusted);

  $ccstr = join(' ', @cc_external);
  $msg->put_metadata("X-Relay-Countries-External", $ccstr);
  dbg("metadata: X-Relay-Countries-External: $ccstr");
  $pms->set_tag("RELAYCOUNTRYEXT", @cc_external == 1 ? $cc_external[0] : \@cc_external);

  $ccstr = join(' ', @cc_auth);
  $msg->put_metadata("X-Relay-Countries-Auth", $ccstr);
  dbg("metadata: X-Relay-Countries-Auth: $ccstr");
  $pms->set_tag("RELAYCOUNTRYAUTH", @cc_auth == 1 ? $cc_auth[0] : \@cc_auth);

  $ccstr = join(' ', @cc_all);
  $msg->put_metadata("X-Relay-Countries-All", $ccstr);
  dbg("metadata: X-Relay-Countries-All: $ccstr");
  $pms->set_tag("RELAYCOUNTRYALL", @cc_all == 1 ? $cc_all[0] : \@cc_all);
}

1;
