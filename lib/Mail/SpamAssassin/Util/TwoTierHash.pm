# A tied object presenting a hash API to a two-tiered pair of hashes

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

package Mail::SpamAssassin::Util::TwoTierHash;

use strict;
use warnings;
use Carp qw(croak);

our @ISA = qw();

# structure: 2 hashes, "tier 0" and "tier 1".  all writes go to tier 1,
# and all reads from tier 1, and if not found there, tier 0.  In
# effect tier 1 overrides tier 0.  Note that writes will NEVER affect
# tier 0; create a new object to modify the contents of that tier.

###########################################################################

sub TIEHASH {
  my $class = shift;
  my $h0 = shift;
  my $h1 = shift;
  my $self = { h0 => $h0, h1 => $h1 };
  return bless $self, $class;
}

sub STORE {
  my ($self, $k, $v) = @_;
  $self->{h1}->{$k} = $v;
  1;
}

sub FETCH {
  my ($self, $k) = @_;
  if (exists $self->{h1}->{$k}) {
    return $self->{h1}->{$k};
  } else {
    return $self->{h0}->{$k};
  }
}

sub EXISTS {
  my ($self, $k) = @_;
  if (exists $self->{h1}->{$k}) {
    return 1;
  } elsif (exists $self->{h0}->{$k}) {
    return 1;
  } else {
    return;
  }
}

sub DELETE {
  my ($self, $k) = @_;
  return delete $self->{h1}->{$k};
}

sub FIRSTKEY {
  my ($self) = @_;
  $self->{_keys} = make_keys_list($self->{h0}, $self->{h1});
  return each %{$self->{_keys}};
}

sub make_keys_list {
  my ($h0, $h1) = @_;
  my %keys = ();
  foreach my $k (keys %{$h0}) { $keys{$k} = 1; }
  foreach my $k (keys %{$h1}) { $keys{$k} = 1; }
  return \%keys;
}

sub NEXTKEY {
  my ($self, $lastk) = @_;
  return each %{$self->{_keys}};
}

sub CLEAR {
  my ($self) = @_;
  $self->{h1} = { };
}

sub SCALAR {
  my ($self) = @_;
  return scalar $self->{h1};
}

1;
