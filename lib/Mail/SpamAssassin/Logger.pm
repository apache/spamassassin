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

Mail::SpamAssassin::Logger - SpamAssassin logging module

=head1 SYNOPSIS

  use Mail::SpamAssassin::Logger;

  $SIG{__WARN__} = sub {
    log_message("warn", $_[0]);
  };

  $SIG{__DIE__} = sub {
    log_message("error", $_[0]) if $_[0] !~ /\bin eval\b/;
  };

=cut

package Mail::SpamAssassin::Logger;

use vars qw(@ISA @EXPORT @EXPORT_OK);

require Exporter;

use strict;
use warnings;
use bytes;

@ISA = qw(Exporter);
@EXPORT = qw(dbg info would_log);
@EXPORT_OK = qw(log_message);

use constant ERROR => 0;
use constant WARNING => 1;
use constant INFO => 2;
use constant DBG => 3;

our %LOG_SA;

# defaults
$LOG_SA{level} = WARNING;	# log warnings and errors
$LOG_SA{facility} = {};		# no dbg facilities turned on

# always log to stderr initially
use Mail::SpamAssassin::Logger::Stderr;
$LOG_SA{method}->{stderr} = Mail::SpamAssassin::Logger::Stderr->new();

sub add_facilities {
  my ($facilities) = @_;

  my @facilities = ();
  if (ref ($facilities) eq '') {
    if (defined $facilities && $facilities ne '0') {
      @facilities = split(/,/, $facilities);
    }
  }
  elsif (ref ($facilities) eq 'ARRAY') {
    @facilities = @{ $facilities };
  }
  elsif (ref ($facilities) eq 'HASH') {
    @facilities = keys %{ $facilities };
  }
  @facilities = grep(/^\S+$/, @facilities);
  if (@facilities) {
    $LOG_SA{facility}->{$_} = 1 for @facilities;
    # turn on debugging if facilities other than "info" are enabled
    if (keys %{ $LOG_SA{facility} } > 1 || !$LOG_SA{facility}->{info}) {
      $LOG_SA{level} = DBG if $LOG_SA{level} < DBG;
    }
    else {
      $LOG_SA{level} = INFO if $LOG_SA{level} < INFO;
    }
  }
}

sub log_message {
  my ($level, @message) = @_;
  my $message = join(" ", @message);
  $message =~ s/[\r\n]+$//;		# remove any trailing newlines
  $message =~ s/[\x00-\x1f]/_/g;	# replace control characters with "_"
  while (my ($name, $object) = each %{ $LOG_SA{method} }) {
    $object->log_message($level, $message);
  }
}

# usage: dbg("facility: message")
# This is used for all low priority debugging messages.
sub dbg {
  return unless $LOG_SA{level} >= DBG;
  _log("dbg", @_);
}

# usage: info("facility: message")
# This is used for informational messages indicating a normal, but
# significant, condition.  This should be infrequently called.
sub info {
  return unless $LOG_SA{level} >= INFO;
  _log("info", @_);
}

sub _log {
  my ($level, $message) = @_;

  my $facility = "generic";
  if ($message =~ /^(\S+?):\s*(.*)/s) {
    $facility = $1;
    $message = $2;
  }

  # only debug specific facilities
  # log all info, warn, and error messages
  if ($level eq "dbg") {
    return unless ($LOG_SA{facility}->{all} ||
		   $LOG_SA{facility}->{$facility});
  }

  $message =~ s/\n+$//s;
  $message =~ s/^/${facility}: /mg;

  # no reason to go through warn()
  log_message($level, $message);
}

sub add {
  my %params = @_;

  my $name = lc($params{method});
  my $class = ucfirst($name);

  eval 'use Mail::SpamAssassin::Logger::'.$class.';';
  ($@) and die "logger: add $class failed: $@";

  if (!exists $LOG_SA{method}->{$name}) {
    my $object = eval 'Mail::SpamAssassin::Logger::'.$class.'->new(%params);';
    if (!$@ && $object) {
      $LOG_SA{method}->{$name} = $object;
      dbg("logger: successfully added $name method\n");
      return 1;
    }
    warn("logger: failed to add $name method\n");
    return 0;
  }

  warn("logger: $name method already added\n");
  return 1;
}

sub remove {
  my ($method) = @_;

  my $name = lc($method);
  if (exists $LOG_SA{method}->{$name}) {
    delete $LOG_SA{method}->{$name};
    return 1;
  }
  # should warn here
  return 1;
}

sub would_log {
  my ($level, $facility) = @_;

  if ($level eq "info") {
    return $LOG_SA{level} >= INFO;
  }
  if ($level eq "dbg") {
    return 0 if $LOG_SA{level} < DBG;
    return 1 if !$facility;
    return 2 if $LOG_SA{facility}->{$facility};
    return 1 if $LOG_SA{facility}->{all};
    return 0;
  }
  warn "logger: would_log called with unknown level: $level\n";
  return 0;
}

sub close {
  while (my ($name, $object) = each %{ $LOG_SA{method} }) {
    $object->close();
  }
}

END {
  close();
}

1;
