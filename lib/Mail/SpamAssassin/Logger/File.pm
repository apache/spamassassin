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

Mail::SpamAssassin::Logger::File - log to file

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Logger::File

=head1 DESCRIPTION

=cut

package Mail::SpamAssassin::Logger::File;

use strict;
use warnings;
use bytes;
use re 'taint';

use POSIX ();
use Time::HiRes ();
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
  $self->{timestamp_fmt} = $params{timestamp_fmt};

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

    # ensure it's unbuffered
    my $oldfh = select STDLOG;
    $| = 1;
    select $oldfh;

    return 1;
  }
  else {
    warn "logger: failed to open file $self->{filename}: $!\n";
    return 0;
  }
}

sub log_message {
  my ($self, $level, $msg) = @_;

  my $timestamp;
  my $fmt = $self->{timestamp_fmt};
  if (!defined $fmt) {
    $timestamp = scalar localtime;  # default, backward compatibility
  } elsif ($fmt eq '') {
    $timestamp = '';
  } else {
    $timestamp = POSIX::strftime($fmt, localtime(Time::HiRes::time));
  }
  $timestamp .= ' '  if $timestamp ne '';

  my($nwrite) = syswrite(STDLOG, sprintf("%s[%s] %s: %s\n",
                                         $timestamp, $$, $level, $msg));
  defined $nwrite  or warn "error writing to log file: $!";
}

sub close_log {
  my ($self) = @_;

  if (defined $self->{filename}) {
    close(STDLOG)  or die "error closing log file: $!";
  }
}

1;
