# Mail::SpamAssassin::NetSet - object to manipulate CIDR net IP addrs
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

package Mail::SpamAssassin::NetSet;

use strict;
use warnings;
use bytes;
use re 'taint';
use NetAddr::IP 4.000;

use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;

use vars qw{
  @ISA $TESTCODE $NUMTESTS
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = { };
  bless $self, $class;

  $self;
}

###########################################################################

sub add_cidr {
  my ($self, @nets) = @_;
  local ($_);

  $self->{nets} ||= [ ];
  my $numadded = 0;

  foreach my $cidr (@nets) {
    my $exclude = ($cidr =~ s/^\s*!//) ? 1 : 0;

    my $is_ip4 = 0;
    if ($cidr =~ /^\d+[\.\/]/) {
      if ($cidr =~ /^(\d+)\.(\d+)\.(\d+)\.$/) { $cidr = "$1.$2.$3.0/24"; }
      elsif ($cidr =~ /^(\d+)\.(\d+)\.$/) { $cidr = "$1.$2.0.0/16"; }
      elsif ($cidr =~ /^(\d+)\.$/) { $cidr = "$1.0.0.0/8"; }
      $is_ip4 = 1;
    }

    my $ip = NetAddr::IP->new($cidr);
    if (!defined $ip) {
      warn "netset: illegal network address given: '$cidr'\n";
      next;
    }

    # if this is an IPv4 address, create an IPv6 representation, too
    my ($ip4, $ip6);
    if ($is_ip4) {
      $ip4 = $ip;
      $ip6 = $self->_convert_ipv4_cidr_to_ipv6($cidr);
    } else {
      $ip6 = $ip;
    }

    # bug 5931: this is O(n^2).  bad if there are lots of nets. There are  good
    # reasons to keep it for linting purposes, though, so don't start skipping
    # it until we have over 200 nets in our list
    if (scalar @{$self->{nets}} < 200) {
      next if ($self->is_net_declared($ip4, $ip6, $exclude, 0));
    }

    # note: it appears a NetAddr::IP object takes up about 279 bytes
    push @{$self->{nets}}, {
      exclude => $exclude,
      ip4     => $ip4,
      ip6     => $ip6,
      as_string => $cidr
    };
    $numadded++;
  }

  $numadded;
}

sub get_num_nets {
  my ($self) = @_;

  if (!exists $self->{nets}) { return 0; }
  return scalar @{$self->{nets}};
}

sub _convert_ipv4_cidr_to_ipv6 {
  my ($self, $cidr) = @_;

  # only do this for IPv4 addresses
  return undef unless ($cidr =~ /^\d+[.\/]/);

  if ($cidr !~ /\//) {      # no mask
    return NetAddr::IP->new6("::ffff:".$cidr);
  }

  # else we have a CIDR mask specified. use new6() to do this
  #
  my $ip6 = ""+(NetAddr::IP->new6($cidr));
  # 127.0.0.1 -> 0:0:0:0:0:0:7F00:0001/128
  # 127/8 -> 0:0:0:0:0:0:7F00:0/104

  # now, move that from 0:0:0:0:0:0: space to 0:0:0:0:0:ffff: space
  if (!defined $ip6 || $ip6 !~ /^0:0:0:0:0:0:(.*)$/) {
    warn "oops! unparseable IPv6 address for $cidr: $ip6";
    return undef;
  }

  return NetAddr::IP->new6("::ffff:$1");
}

sub _nets_contains_network {
  my ($self, $net4, $net6, $exclude, $quiet, $netname, $declared) = @_;

  return 0 unless (defined $self->{nets});

  foreach my $net (@{$self->{nets}}) {
    # check to see if the new network is contained by the old network
    my $in4 = defined $net4 && defined $net->{ip4} && $net->{ip4}->contains($net4);
    my $in6 = defined $net6 && defined $net->{ip6} && $net->{ip6}->contains($net6);
    if ($in4 || $in6) {
      warn "netset: cannot " . ($exclude ? "exclude" : "include") 
	 . " $netname as it has already been "
	 . ($net->{exclude} ? "excluded" : "included") . "\n" unless $quiet;

      # a network that matches an excluded network isn't contained by "nets"
      # return 0 if we're not just looking to see if the network was declared
      return 0 if (!$declared && $net->{exclude});
      return 1;
    }
  }
  return 0;
}

sub is_net_declared {
  my ($self, $net4, $net6, $exclude, $quiet) = @_;
  return $self->_nets_contains_network($net4, $net6, $exclude,
                $quiet, $net4 || $net6, 1);
}

sub contains_ip {
  my ($self, $ip) = @_;

  if (!defined $self->{nets}) { return 0; }

  my ($ip4, $ip6);
  if ($ip =~ /^\d+\./) {
    $ip4 = NetAddr::IP->new($ip);
    $ip6 = $self->_convert_ipv4_cidr_to_ipv6($ip);
  } else {
    $ip6 = NetAddr::IP->new($ip);
  }

  foreach my $net (@{$self->{nets}}) {
    return !$net->{exclude} if
        ((defined $ip4 && defined $net->{ip4} && $net->{ip4}->contains($ip4))
        || (defined $ip6 && defined $net->{ip6} && $net->{ip6}->contains($ip6)));
  }
  return 0;
}

sub contains_net {
  my ($self, $net) = @_;
  my $exclude = $net->{exclude};
  my $net4 = $net->{ip4};
  my $net6 = $net->{ip6};
  return $self->_nets_contains_network($net4, $net6, $exclude, 1, "", 0);
}

sub clone {
  my ($self) = @_;
  my $dup = Mail::SpamAssassin::NetSet->new();
  if (defined $self->{nets}) {
    @{$dup->{nets}} = @{$self->{nets}};
  }
  return $dup;
}

###########################################################################

1;
