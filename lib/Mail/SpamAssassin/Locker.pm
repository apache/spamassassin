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

package Mail::SpamAssassin::Locker;

use strict;
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
  my ($self, $path, $max_retries) = @_;
  # max_retries is optional, should default to about 30
  die "safe_lock not implemented by Locker subclass";
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;
  die "safe_unlock not implemented by Locker subclass";
}

###########################################################################

1;
