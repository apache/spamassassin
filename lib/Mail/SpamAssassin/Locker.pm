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

package Mail::SpamAssassin::Locker;

use strict;
use warnings;
use bytes;
use Fcntl;

use Mail::SpamAssassin;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);
  $self;
}

###########################################################################

sub safe_lock {
  my ($self, $path, $max_retries, $mode) = @_;
  # max_retries is optional, should default to about 30
  # mode is UNIX-style and optional, should default to 0700,
  # callers must specify --x bits
  die "locker: safe_lock not implemented by Locker subclass";
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;
  die "locker: safe_unlock not implemented by Locker subclass";
}

###########################################################################

sub refresh_lock {
  my ($self, $path) = @_;
  die "locker: refresh_lock not implemented by Locker subclass";
}

###########################################################################

sub jittery_one_second_sleep {
  my ($self) = @_;
  select(undef, undef, undef, (rand(1.0) + 0.5));
}

###########################################################################

1;
