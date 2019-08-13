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
# use bytes;
use re 'taint';

use POSIX ();
use Time::HiRes ();
use Mail::SpamAssassin::Logger;

our @ISA = ();

# ADDING OS-DEPENDENT LINE TERMINATOR - BUG 6456

# Using Mail::SpamAssassin::Util::am_running_on_windows() leads to circular
# dependencies. So, we are duplicating the code instead.
use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/oi);

my $eol = "\n";
if (RUNNING_ON_WINDOWS) {
  $eol = "\r\n";
}

sub new {
  my $class = shift;

  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);

  my %params = @_;
  $self->{timestamp_fmt} = $params{timestamp_fmt};
  $self->{escape} = $params{escape} if exists $params{escape};

  return($self);
}

sub log_message {
  my ($self, $level, $msg, $ts) = @_;

  my $timestamp;
  my $fmt = $self->{timestamp_fmt};
  my $now = defined $ts ? $ts : Time::HiRes::time;
  if (!defined $fmt) {
    # default since 3.3.0
    my $datetime = POSIX::strftime("%b %d %H:%M", localtime($now));
    utf8::encode($datetime)  if utf8::is_utf8($datetime);  # Bug 7305
    $timestamp = sprintf("%s:%06.3f", $datetime, $now-int($now/60)*60);
    # Bug 6329: %e is not in a POSIX standard, use %d instead and edit
    local $1; $timestamp =~ s/^(\S+\s+)0/$1 /;
  } elsif ($fmt eq '') {
    $timestamp = '';
  } else {
    $timestamp = POSIX::strftime($fmt, localtime($now));
  }
  $timestamp .= ' '  if $timestamp ne '';

  if ($self->{escape}) {
    # Bug 6583, escape
    Mail::SpamAssassin::Logger::escape_str($msg);
  } elsif (!exists $self->{escape}) {
    # Backwards compatible pre-4.0 escaping, if $escape not given.
    # replace control characters with "_", tabs and spaces get
    # replaced with a single space.
    $msg =~ tr/\x09\x20\x00-\x1f/  _/s;
  }

  my($nwrite) = syswrite(STDERR, sprintf("%s[%d] %s: %s%s",
                                         $timestamp, $$, $level, $msg, $eol));
  defined $nwrite  or warn "error writing to log file: $!";
}

sub close_log {
  my ($self) = @_;
}

1;
