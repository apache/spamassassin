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

  foreach (@nets) {
    my $exclude = s/^\s*!// ? 1 : 0;
    my ($ip, $bits) = m#^\s*
			((?:(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.){0,3}
			    (?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)?) (?:(?<!\.)/(\d+))?
		      \s*$#x;

    my $err = "netset: illegal network address given: '$_'\n";
    if (!defined $ip) {
      warn $err;
      next;
    }
    elsif ($ip =~ /\.$/) {
      # just use string matching; much simpler than doing smart stuff with arrays ;)
      if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.$/) { $ip = "$1.$2.$3.0"; $bits = 24; }
      elsif ($ip =~ /^(\d+)\.(\d+)\.$/) { $ip = "$1.$2.0.0"; $bits = 16; }
      elsif ($ip =~ /^(\d+)\.$/) { $ip = "$1.0.0.0"; $bits = 8; }
      else {
	warn $err;
	next;
      }
    }

    $bits = 32 if (!defined $bits);

    next if ($self->is_net_declared($ip, $bits, $exclude, 0));

    my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);

    push @{$self->{nets}}, {
      mask    => $mask,
      exclude => $exclude,
      ip      => (Mail::SpamAssassin::Util::my_inet_aton($ip) & $mask),
      as_string => $_
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

sub _nets_contains_network {
  my ($self, $network, $mask, $exclude, $quiet, $netname, $declared) = @_;

  return 0 unless (defined $self->{nets});

  $exclude = 0 if (!defined $exclude);
  $quiet = 0 if (!defined $quiet);
  $declared = 0 if (!defined $declared);

  foreach my $net (@{$self->{nets}}) {
    # a net can not be contained by a (smaller) net with a larger mask
    next if ($net->{mask} > $mask);

    # check to see if the new network is contained by the old network
    if (($network & $net->{mask}) == $net->{ip}) {
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
  my ($self, $network, $bits, $exclude, $quiet) = @_;

  my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);
  my $aton = Mail::SpamAssassin::Util::my_inet_aton($network);

  return $self->_nets_contains_network($aton, $mask, $exclude,
                $quiet, "$network/$bits", 1);
}

sub contains_ip {
  my ($self, $ip) = @_;

  if (!defined $self->{nets}) { return 0; }
  if ($ip !~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) { return 0; }

  $ip = Mail::SpamAssassin::Util::my_inet_aton($ip);
  foreach my $net (@{$self->{nets}}) {
    return !$net->{exclude} if (($ip & $net->{mask}) == $net->{ip});
  }
  0;
}

sub contains_net {
  my ($self, $net) = @_;
  my $mask    = $net->{mask};
  my $exclude = $net->{exclude};
  my $network = $net->{ip};

  return $self->_nets_contains_network($network, $mask, $exclude, 1, "", 0);
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
