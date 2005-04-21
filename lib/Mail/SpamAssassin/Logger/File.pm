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

=head1 NAME

Mail::SpamAssassin::Logger::File - log to file

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Logger::File

=head1 DESCRIPTION

=cut

package Mail::SpamAssassin::Logger::File;

use strict;
use warnings;
use bytes;
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);
@ISA = ();

sub new {
  my $class = shift;

  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);

  # parameters
  my %params = @_;
  $self->{filename} = $params{filename} || 'spamassassin.log';

  if (! $self->init()) {
    die "logger: file initialization failed\n";
  }

  return($self);
}

# logging via file is requested
sub init {
  my ($self) = @_;

  if (open(STDLOG, ">> $self->{filename}")) {
    dbg("logger: successfully opened file $self->{filename}");
    return 1;
  }
  else {
    warn "logger: failed to open file $self->{filename}: $!\n";
    return 0;
  }
}

sub log_message {
  my ($self, $level, $msg) = @_;

  my @date = reverse((gmtime(time))[0..5]);
  $date[0] += 1900;
  $date[1] += 1;
  syswrite(STDLOG, sprintf("%04d-%02d-%02d %02d:%02d:%02d [%s] %s: %s\n",
			   @date, $$, $level, $msg));
}

sub close {
  my ($self) = @_;

  close(STDLOG) if defined $self->{filename};
}

1;
