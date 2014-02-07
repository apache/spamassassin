# A memory-efficient, but slow, single-string structure with a hash interface.

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

package Mail::SpamAssassin::Util::TieOneStringHash;

use strict;
use warnings;
use re 'taint';
use Carp qw(croak);

our @ISA = qw();

# the structure is pretty simple: it's a single string, containing
# items like so:
#
#    \n KEY 0x00 VALUE 0x00 \n
#    \n KEY2 0x00 VALUE2 0x00 \n
#    ...
#
# undef values are represented using $UNDEF_VALUE, a hacky magic string.
# Only simple scalars can be stored; refs of any kind produce a croak().
#
# writes are slowest, reads are slow, but memory usage is very low
# compared to a "real" hash table -- in other words, this is perfect
# for infrequently-read data that has to be kept around but should
# affect memory usage as little as possible.

my $UNDEF_VALUE = "_UNDEF_\001";

###########################################################################

sub TIEHASH {
  my $class = shift;
  my $str = '';
  return bless \$str, $class;
}

sub STORE {
  my ($store, $k, $v) = @_;
  $v = $UNDEF_VALUE unless defined($v);

  if (ref $v) {
    croak "oops! only simple scalars can be stored in a TieOneStringHash";
  }
  if (!defined $k) {
    croak "oops! TieOneStringHash requires defined keys";
  }

  if ($$store !~ s{\n\Q$k\E\000.*?\000\n}
                  {\n$k\000$v\000\n}xgs)
  {
    $$store .= "\n$k\000$v\000\n";
  }
  1;
}

sub FETCH {
  my ($store, $k) = @_;
  if ($$store =~ m{\n\Q$k\E\000(.*?)\000\n}xs)
  {
    return $1 eq $UNDEF_VALUE ? undef : $1;
  }
  return;
}

sub EXISTS {
  my ($store, $k) = @_;
  if ($$store =~ m{\n\Q$k\E\000}xs)
  {
    return 1;
  }
  return;
}

sub DELETE {
  my ($store, $k) = @_;
  if ($$store =~ s{\n\Q$k\E\000(.*?)\000\n}
                  {}xgs)
  {
    return $1 eq $UNDEF_VALUE ? undef : $1;
  }
  return;
}

sub FIRSTKEY {
  my ($store) = @_;
  if ($$store =~ m{^\n(.*?)\000}s)
  {
    return $1;
  }
  return;
}

sub NEXTKEY {
  my ($store, $lastk) = @_;
  if ($$store =~ m{\n\Q$lastk\E\000.*?\000\n
                   \n(.*?)\000}xs)
  {
    return $1;
  }
  return;
}

sub CLEAR {
  my ($store) = @_;
  $$store = '';
}

sub SCALAR {
  my ($store) = @_;
  return $$store;       # as a string!
}

1;
