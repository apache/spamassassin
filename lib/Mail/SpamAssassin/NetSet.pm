# Mail::SpamAssassin::NetSet - object to manipulate CIDR net IP addrs
# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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
use bytes;

use Mail::SpamAssassin::Util;

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
    my ($ip, $bits) = m#^\s*([\d\.]+)(?:/(\d+))?\s*$#;

    my $err = "illegal network address given: '$_'\n";
    if (!defined $ip) {
      warn $err; next;

    } elsif ($ip =~ /\.$/) {
      # just use string matching; much simpler than doing smart stuff with arrays ;)
      if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.$/) { $ip = "$1.$2.$3.0"; $bits = 24; }
      elsif ($ip =~ /^(\d+)\.(\d+)\.$/) { $ip = "$1.$2.0.0"; $bits = 16; }
      elsif ($ip =~ /^(\d+)\.$/) { $ip = "$1.0.0.0"; $bits = 8; }
      else {
	warn $err; next;
      }
    }

    $bits = 32 if (!defined $bits);
    my $mask = 0xFFffFFff ^ ((2 ** (32-$bits)) - 1);

    push @{$self->{nets}}, {
      mask => $mask,
      ip   => Mail::SpamAssassin::Util::my_inet_aton($ip) & $mask
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

sub contains_ip {
  my ($self, $ip) = @_;

  if (!defined $self->{nets}) { return 0; }

  $ip = Mail::SpamAssassin::Util::my_inet_aton($ip);
  foreach my $net (@{$self->{nets}}) {
    return 1 if (($ip & $net->{mask}) == $net->{ip});
  }
  0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################

1;
