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

my %log_level = (
		 0 => 'ERROR',
		 1 => 'WARNING',
		 2 => 'INFO',
		 3 => 'DBG',
		 );

# global shared object
our %LOG_SA;

# defaults
$LOG_SA{level} = WARNING;       # log info, warnings and errors
$LOG_SA{facility} = {};		# no dbg facilities turned on

# always log to stderr initially
use Mail::SpamAssassin::Logger::Stderr;
$LOG_SA{method}->{stderr} = Mail::SpamAssassin::Logger::Stderr->new();

=head1 METHODS

=over 4

=item add_facilities(facilities)

Enable debug logging for specific facilities.  Each facility is the area
of code to debug.  Facilities can be specified as a hash reference (the
key names are used), an array reference, an array, or a comma-separated
scalar string.

If "all" is listed, then all debug facilities are enabled.  Higher
priority informational messages that are suitable for logging in normal
circumstances are available with an area of "info".  Some very verbose
messages require the facility to be specifically enabled (see
C<would_log> below).

=cut

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
    # debug statement last so we might see it
    dbg("logger: adding facilities: " . join(", ", @facilities));
    dbg("logger: logging level is " . $log_level{$LOG_SA{level}});
  }
}

=item log_message($level, $message)

=item log_message($level, @message)

Log a message at a specific level.  Levels are specified as strings:
"warn", "error", "info", and "dbg".  The first element of the message
must be prefixed with a facility name followed directly by a colon.

=cut

sub log_message {
  my ($level, @message) = @_;

  # too many die and warn messages out there, don't log the ones that we don't
  # own.  jm: off: this makes no sense -- if a dependency module dies or warns,
  # we want to know about it, unless we're *SURE* it's not something worth
  # worrying about.
  # if ($level eq "error" or $level eq "warn") {
  # return unless $message[0] =~ /^\S+:/;
  # }

  if ($level eq "error") {
    # don't log alarm timeouts or broken pipes of various plugins' network checks
    return if ($message[0] =~ /__ignore__/);

    # dos: we can safely ignore any die's that we eval'd in our own modules so
    # don't log them -- this is caller 0, the use'ing package is 1, the eval is 2
    my @caller = caller 2;
    return if (defined $caller[3] && defined $caller[0] &&
		       $caller[3] =~ /^\(eval\)$/ &&
		       $caller[0] =~ m#^Mail::SpamAssassin(?:$|::)#);
  }

  my $message = join(" ", @message);
  $message =~ s/[\r\n]+$//;		# remove any trailing newlines

  # split on newlines and call log_message multiple times; saves
  # the subclasses having to understand multi-line logs
  foreach my $line (split(/\n/, $message)) {
    # replace control characters with "_", tabs and spaces get
    # replaced with a single space.
    $line =~ tr/\x09\x20\x00-\x1f/  _/s;
    while (my ($name, $object) = each %{ $LOG_SA{method} }) {
      $object->log_message($level, $line);
    }
  }
}

=item dbg("facility: message")

This is used for all low priority debugging messages.

=cut

sub dbg {
  return unless $LOG_SA{level} >= DBG;
  _log("dbg", @_);
}

=item info("facility: message")

This is used for informational messages indicating a normal, but
significant, condition.  This should be infrequently called.  These
messages are typically logged when SpamAssassin is run as a daemon.

=cut

sub info {
  return unless $LOG_SA{level} >= INFO;
  _log("info", @_);
}

# remember to avoid deep recursion, my friend
sub _log {
  my ($level, $message) = @_;

  my $facility = "generic";
  if ($message =~ /^(\S+?): (.*)/s) {
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

=item add(method => 'syslog', socket => $socket, facility => $facility)

C<socket> is the type the syslog ("unix" or "inet").  C<facility> is the
syslog facility (typically "mail").

=item add(method => 'file', filename => $file)

C<filename> is the name of the log file.

=item add(method => 'stderr')

No options are needed for stderr logging, just don't close stderr first.

=cut

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
    warn("logger: failed to add $name method ($@)\n");
    return 0;
  }

  warn("logger: $name method already added\n");
  return 1;
}

=item remove(method)

Remove a logging method.  Only the method name needs to be passed as a
scalar.

=cut

sub remove {
  my ($method) = @_;

  my $name = lc($method);
  if (exists $LOG_SA{method}->{$name}) {
    delete $LOG_SA{method}->{$name};
    info("logger: removing $name method");
    return 1;
  }
  warn("logger: unable to remove $name method, not present to be removed");
  return 1;
}

=item would_log($level, $facility)

Returns 0 if a message at the given level and with the given facility
would be logged.  Returns 1 if a message at a given level and facility
would be logged normally.  Returns 2 if the facility was specifically
enabled.

The facility argument is optional.

=cut

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

=item close_log()

Close all logs.

=cut

sub close_log {
  while (my ($name, $object) = each %{ $LOG_SA{method} }) {
    $object->close_log();
  }
}

END {
  close_log();
}

1;

=back

=cut
