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

Mail::SpamAssassin::Logger::Stderr - log to standard error

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Logger::Stderr

=head1 DESCRIPTION

=cut

package Mail::SpamAssassin::Logger::Stderr;

use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = ();

sub new {
  my $class = shift;

  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);

  return($self);
}

sub log_message {
  my ($self, $level, $msg) = @_;

  print STDERR "[$$] $level: $msg\n";
}

sub close_log {
  my ($self) = @_;
}

1;
