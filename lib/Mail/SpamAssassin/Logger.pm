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
    log_message("error", $_[0])  if !$^S;
  };

=cut

package Mail::SpamAssassin::Logger;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Exporter ();
use Time::HiRes ();

our @ISA = qw(Exporter);
our @EXPORT = qw(dbg info would_log);
our @EXPORT_OK = qw(log_message);

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
our $LOG_ENTERED;  # to avoid recursion on die or warn from within logging
# duplicate message line suppressor
our $LOG_DUPMIN = 10; # only start suppressing after x duplicate lines
our $LOG_DUPLINE = ''; # remembers last log line
our $LOG_DUPLEVEL = ''; # remembers last log level
our $LOG_DUPTIME; # remembers last log line timestamp
our $LOG_DUPCNT = 0; # counts duplicates

# defaults
$LOG_SA{level} = WARNING;       # log info, warnings and errors
$LOG_SA{facility} = {};		# no dbg facilities turned on

# always log to stderr initially
use Mail::SpamAssassin::Logger::Stderr;
$LOG_SA{method}->{stderr} =
  Mail::SpamAssassin::Logger::Stderr->new(escape =>
    exists $ENV{'SA_LOGGER_ESCAPE'} ? $ENV{'SA_LOGGER_ESCAPE'} : 1
  );

# Use of M:SA:Util causes circular dependencies, separate helper here.
my %escape_map =
  ("\r" => '\\r', "\n" => '\\n', "\t" => '\\t', "\\" => '\\\\');
sub escape_str {
  # Things are already forced as octets by _log, no utf8::encode needed
  # Control chars, DEL, backslash
  $_[0] =~ s@
    ( [\x00-\x1F\x7F\x80-\xFF\\] )
    @ $escape_map{$1} || sprintf("\\x{%02X}",ord($1))
    @egsx;
}

=head1 METHODS

=over 4

=item add_facilities(facilities)

Enable debug logging for specific facilities.  Each facility is the area
of code to debug.  Facilities can be specified as a hash reference (the
key names are used), an array reference, an array, or a comma-separated
scalar string. Facility names are case-sensitive.

If "all" is listed, then all debug facilities are implicitly enabled,
except for those explicitly disabled.  A facility name may be preceded
by a "no" (case-insensitive), which explicitly disables it, overriding
the "all".  For example: all,norules,noconfig,nodcc.  When facility names
are given as an ordered list (array or scalar, not a hash), the last entry
applies, e.g. 'nodcc,dcc,dcc,noddc' is equivalent to 'nodcc'.  Note that
currently no facility name starts with a "no", it is advised to keep this
practice with newly added facility names to make life easier.

Higher priority informational messages that are suitable for logging in
normal circumstances are available with an area of "info".  Some very
verbose messages require the facility to be specifically enabled (see
C<would_log> below).

=cut

sub add_facilities {
  my ($facilities) = @_;

  my @facilities;
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
    for my $fac (@facilities) {
      local ($1,$2);
      $LOG_SA{facility}->{$2} = !defined($1)  if $fac =~ /^(no)?(.+)\z/si;
    }
    # turn on debugging if facilities other than "info" are enabled
    if (grep { !/^info\z/ && !/^no./si } keys %{ $LOG_SA{facility} }) {
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
    return if (index($message[0], '__ignore__') != -1);

    # dos: we can safely ignore any die's that we eval'd in our own modules so
    # don't log them -- this is caller 0, the use'ing package is 1, the eval is 2
    my @caller = caller 2;
    return if (defined $caller[3] && defined $caller[0] &&
		       $caller[3] eq '(eval)' &&
		       $caller[0] =~ m#^Mail::SpamAssassin(?:$|::)#);
  }

  return if $LOG_ENTERED;  # avoid recursion on die or warn from within logging
  $LOG_ENTERED = 1;  # no 'returns' from this point on, must clear the flag

  my $message = join(" ", @message);
  $message =~ s/[\r\n]+$//;		# remove any trailing newlines

  my $now = Time::HiRes::time;

  # suppress duplicate loglines
  if ($message eq $LOG_DUPLINE) {
    $LOG_DUPCNT++;
    $LOG_DUPTIME = $now;
    # only start suppressing after x identical lines
    if ($LOG_DUPCNT >= $LOG_DUPMIN) {
      $LOG_ENTERED = 0;
      return;
    }
  } else {
    if ($LOG_DUPCNT >= $LOG_DUPMIN) {
      $LOG_DUPCNT -= $LOG_DUPMIN - 1;
      if ($LOG_DUPCNT > 1) {
        _log_message($LOG_DUPLEVEL,
                     "$LOG_DUPLINE [... logline repeated $LOG_DUPCNT times]",
                     $LOG_DUPTIME);
      } else {
        _log_message($LOG_DUPLEVEL, $LOG_DUPLINE, $LOG_DUPTIME);
      }
    }
    $LOG_DUPCNT = 0;
    $LOG_DUPLINE = $message;
    $LOG_DUPLEVEL = $level;
  }

  _log_message($level, $message, $now);

  $LOG_ENTERED = 0;
}

# Private helper
sub _log_message {
  # split on newlines and call log_message multiple times; saves
  # the subclasses having to understand multi-line logs
  my $first = 1;
  foreach my $line (split(/\n/, $_[1])) {
    # replace control characters with "_", tabs and spaces get
    # replaced with a single space.
    # Deprecated here, see new Bug 6583 escaping in Logger/*.pm modules
    #$line =~ tr/\x09\x20\x00-\x1f/  _/s;

    if ($first) {
      $first = 0;
    } else {
      $line =~ s/^([^:]+?):/$1: [...]/;
    }

    while (my ($name, $object) = each %{ $LOG_SA{method} }) {
      $object->log_message($_[0], $line, $_[2]);
    }
  }
}

=item dbg("facility: message")

This is used for all low priority debugging messages.

=cut

sub dbg {
  _log(DBG, @_)  if $LOG_SA{level} >= DBG;
  1;  # always return the same simple value, regardless of log level
}

=item info("facility: message")

This is used for informational messages indicating a normal, but
significant, condition.  This should be infrequently called.  These
messages are typically logged when SpamAssassin is run as a daemon.

=cut

sub info {
  _log(INFO, @_)  if $LOG_SA{level} >= INFO;
  1;  # always return the same simple value, regardless of log level
}

# remember to avoid deep recursion, my friend
sub _log {
  my $facility;
  local ($1);

  # it's faster to access this as the $_[1] alias, and not to perform
  # string mods until we're sure we actually want to log anything
  if ($_[1] =~ /^([a-z0-9_-]*):/i) {
    $facility = $1;
  } else {
    $facility = "generic";
  }

  # log all info, warn, and error messages;
  # only debug if asked to
  if ($_[0] == DBG) {
    return unless
      exists $LOG_SA{facility}->{$facility} ? $LOG_SA{facility}->{$facility}
                                            : $LOG_SA{facility}->{all};
  }

  my ($level, $message, @args) = @_;

  utf8::encode($message)  if utf8::is_utf8($message); # handle as octets
  foreach (@args) { utf8::encode($_)  if utf8::is_utf8($_); } # Bug 8138

  $message =~ s/^(?:[a-z0-9_-]*):\s*//i;

  $message = sprintf($message,@args)  if @args;
  $message =~ s/\n+$//s;
  $message =~ s/^/${facility}: /mg;

  # no reason to go through warn()
  log_message(($level == INFO ? "info" : "dbg"), $message);
}

=item add(method =E<gt> 'syslog', socket =E<gt> $socket, facility =E<gt> $facility, escape =E<gt> $escape)

C<socket> is the type the syslog ("unix" or "inet").  C<facility> is the
syslog facility (typically "mail").

If optional C<escape> is true, all non-ascii characters are escaped for safe
output: backslashes change to \\ and non-ascii chars to \x{XX} or \x{XXXX}
(Unicode).  If not defined, pre-4.0 style sanitizing is used
( tr/\x09\x20\x00-\x1f/_/s ).

Escape value can be overridden with environment variable
C<SA_LOGGER_ESCAPE>.

=item add(method =E<gt> 'file', filename =E<gt> $file, escape =E<gt> $escape)

C<filename> is the name of the log file.  C<escape> works as described
above.

=item add(method =E<gt> 'stderr', escape =E<gt> $escape)

No options are needed for stderr logging, just don't close stderr first. 
C<escape> works as described above.

=cut

sub add {
  my %params = @_;

  my $name = lc($params{method});
  my $class = ucfirst($name);

  return 0 if $class !~ /^\w+$/; # be paranoid

  if (exists $ENV{'SA_LOGGER_ESCAPE'}) {
    $params{escape} = $ENV{'SA_LOGGER_ESCAPE'}
  }

  eval 'use Mail::SpamAssassin::Logger::'.$class.'; 1'
  or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    die "logger: add $class failed: $eval_stat\n";
  };

  if (!exists $LOG_SA{method}->{$name}) {
    my $object;
    my $eval_stat;
    eval '$object = Mail::SpamAssassin::Logger::'.$class.'->new(%params); 1'
    or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      undef $object;  # just in case
    };
    if (!$object) {
      if (!defined $eval_stat) {
        $eval_stat = "Mail::SpamAssassin::Logger::$class->new ".
                     "failed to return an object";
      }
      warn "logger: failed to add $name method: $eval_stat\n";
    }
    else {
      $LOG_SA{method}->{$name} = $object;
      dbg("logger: successfully added $name method\n");
      return 1;
    }
    return 0;
  }

  warn "logger: $name method already added\n";
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
  warn "logger: unable to remove $name method, not present to be removed\n";
  return 1;
}

=item would_log($level, $facility)

Returns false if a message at the given level and with the given facility
would not be logged.  Returns 1 if a message at a given level and facility
would be logged normally.  Returns 2 if the facility was specifically
enabled.

The facility argument is optional.

=cut

sub would_log {
  my ($level, $facility) = @_;

  if ($level eq 'dbg') {
    return 0 if $LOG_SA{level} < DBG;
    return 1 if !$facility;
    return ($LOG_SA{facility}->{$facility} ? 2 : 0)
      if exists $LOG_SA{facility}->{$facility};
    return 1 if $LOG_SA{facility}->{all};
    return 0;
  } elsif ($level eq 'info') {
    return $LOG_SA{level} >= INFO;
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
