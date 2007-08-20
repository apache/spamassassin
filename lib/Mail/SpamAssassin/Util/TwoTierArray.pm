# A tied object presenting an array API to a two-tiered pair of arrays

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

package Mail::SpamAssassin::Util::TwoTierArray;

use strict;
use warnings;
use Carp qw(croak);

use Tie::Array;

our @ISA = qw(Tie::Array);

# structure: 2 arrays, "tier 0" and "tier 1".  all writes go to tier 1,
# and all reads from tier 1, and if not found there, tier 0.  In
# effect tier 1 overrides tier 0.  Note that writes will NEVER affect
# tier 0; create a new object to modify the contents of that tier.
# This is different from how TwoTierHash works (which can be written to)

###########################################################################

sub TIEARRAY {
  my $class = shift;
  my $a0 = shift;
  my $a1 = shift;
  my $self = {
    a0 => $a0 || [],
    a1 => $a1 || [],
  };
  return bless $self, $class;
}

sub STORE {
  my ($self, $i, $v) = @_;
  my $a0size = scalar @{$self->{a0}};
  if ($i >= $a0size) {
    $self->{a1}->[$i - $a0size] = $v;
  } else {
    # a write to the a0 area! we cannot do this!
    croak "cannot write to immutable tier 0 part of array: $i / $a0size";
  }
}

sub FETCH {
  my ($self, $i) = @_;
  my $a0size = scalar @{$self->{a0}};
  if ($i >= $a0size) {
    return $self->{a1}->[$i - $a0size];
  } else {
    return $self->{a0}->[$i];
  }
}

sub FETCHSIZE {
  my ($self) = @_;
  return scalar(@{$self->{a0}}) + scalar(@{$self->{a1}});
}

sub STORESIZE {
  my ($self, $count) = @_;
  my $a0size = scalar @{$self->{a0}};
  if ($count > $a0size) {
    @{$self->{a1}} = $count - $a0size;
  } else {
    # a write to the a0 area! we cannot do this!
    croak "cannot resize immutable tier 0 part of array: $count / $a0size";
  }
}

sub EXISTS {
  my ($self, $i) = @_;
  my $a0size = scalar @{$self->{a0}};
  if ($i > $a0size) {
    return exists $self->{a1}->[$i - $a0size];
  } else {
    return exists $self->{a0}->[$i];
  }
}

sub DELETE {
  my ($self, $i) = @_;
  my $a0size = scalar @{$self->{a0}};
  if ($i > $a0size) {
    delete $self->{a1}->[$i - $a0size];
  } else {
    # a write to the a0 area! we cannot do this!
    croak "cannot write to immutable tier 0 part of array: $i / $a0size";
  }
}

1;
