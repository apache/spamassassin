# Helper code to debug dependencies and their versions.

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

package Mail::SpamAssassin::Util::ScopedTimer;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw();

sub new {
  my $class = shift;
  my $self = {
    main => shift,
    timer => shift,
  };
  $self->{main}->timer_start($self->{timer});
  return bless ($self, $class);
}

# OO hack: when the object goes out of scope, the timer ends.  neat!
sub DESTROY {
  my $self = shift;
  # best practices: prevent potential calls to eval and to system routines
  # in code of a DESTROY method from clobbering global variables $@ and $! 
  local($@,$!);  # keep outer error handling unaffected by DESTROY
  $self->{main} && $self->{timer} && $self->{main}->timer_end($self->{timer});
}

1;
