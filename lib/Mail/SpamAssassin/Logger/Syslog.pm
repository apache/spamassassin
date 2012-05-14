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

Mail::SpamAssassin::Logger::Syslog - log to syslog

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Logger::Syslog

=head1 DESCRIPTION

=cut

package Mail::SpamAssassin::Logger::Syslog;

use strict;
use warnings;
use bytes;
use re 'taint';

use POSIX qw(:sys_wait_h setsid sigprocmask);
use Time::HiRes ();
use Sys::Syslog qw(:DEFAULT setlogsock);
use Mail::SpamAssassin::Logger;

use vars qw(@ISA %prio_map $syslog_open);
@ISA = ();

BEGIN {
  # %prio_map maps Logger.pm log level names (warn, error, info, dbg)
  # into standard Sys::Syslog::syslog() log level names
  #
  %prio_map = (dbg => 'debug', debug => 'debug', info => 'info',
               notice => 'notice', warn => 'warning', warning => 'warning',
               error => 'err', err => 'err', crit => 'crit', alert => 'alert',
               emerg => 'emerg');

  # make sure never to hit the CPAN-RT#56826 bug (memory corruption
  # when closelog() is called twice), fixed in Sys-Syslog 0.28
  $syslog_open = 0;
}

sub new {
  my $class = shift;

  $class = ref($class) || $class;
  my $self = { };
  bless ($self, $class);

  # initialization
  $self->{already_done_failure_warning} = 0;
  $self->{disabled} = 0;
  $self->{consecutive_failures} = 0;
  $self->{failure_threshold} = 10;
  $self->{SIGPIPE_RECEIVED} = 0;

  # parameters
  my %params = @_;
  $self->{ident} = $params{ident} || 'spamassassin';
  $self->{log_socket} = $params{socket};
  $self->{log_facility} = $params{facility};
  $self->{timestamp_fmt} = $params{timestamp_fmt};

  if (! $self->init()) {
    die "logger: syslog initialization failed\n";
  }

  return($self);
}

# logging via syslog is requested
sub init {
  my ($self) = @_;

  my $log_socket = $self->{log_socket};
  $log_socket = ''  if !defined $log_socket;

  my $eval_stat;
  eval {
    if ($log_socket eq '') {
      # calling setlogsock is optional, let Sys::Syslog choose a default
    } else {
      dbg("logger: calling setlogsock($log_socket)");
      setlogsock($log_socket) or die "setlogsock($log_socket) failed: $!";
    }
    dbg("logger: opening syslog with $log_socket socket");
    # the next call is required to actually open the socket
    openlog($self->{ident}, 'cons,pid,ndelay', $self->{log_facility});
    $syslog_open = 1;
    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("logger: connection to syslog/$log_socket failed: $eval_stat");
  };

  # Solaris sometimes doesn't support UNIX-domain syslog sockets apparently;
  # the same is true for perl 5.6.0 build on an early version of Red Hat 7!
  # In these cases we try it with INET instead.
  # See also Bug 6267 and Bug 6331.

  if (defined($eval_stat) && $log_socket ne 'inet') {
    dbg("logger: trying setlogsock('inet')");
    undef $eval_stat;
    eval {
      setlogsock('inet') or die "setlogsock('inet') failed: $!";
      dbg("logger: opening syslog using inet socket");
      openlog($self->{ident}, 'cons,pid,ndelay', $self->{log_facility});
      $syslog_open = 1;
      1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      dbg("logger: connection to syslog/inet failed: $eval_stat");
    };
  }

  # we failed!
  if (defined $eval_stat) {
    return 0;
  }
  else {
    dbg("logger: successfully connected to syslog/$log_socket");
    return 1;
  }
}

sub log_message {
  my ($self, $level, $msg) = @_;

  return if $self->{disabled};

  # map level names
  $level = $prio_map{$level};
  if (!defined $level) {  # just in case
    $level = 'err';
    $msg = '(bad prio: ' . $_[1] . ') ' . $msg;
  }

  # install a new handler for SIGPIPE -- this signal has been
  # found to occur with syslog-ng after syslog-ng restarts.
  local $SIG{'PIPE'} = sub {
    $self->{SIGPIPE_RECEIVED}++;
    # force a log-close.   trap possible die() calls
    eval { closelog() } if $syslog_open;
    $syslog_open = 0;
  };

  my $timestamp = '';
  my $fmt = $self->{timestamp_fmt};
  if (defined $fmt && $fmt ne '') {  # for completeness, rarely used
    $timestamp = POSIX::strftime($fmt, localtime(Time::HiRes::time));
  }
  $msg = $timestamp . ' ' . $msg  if $timestamp ne '';

# no longer needed since a patch to bug 6745:
# # important: do not call syslog() from the SIGCHLD handler
# # child_handler().   otherwise we can get into a loop if syslog()
# # forks a process -- as it does in syslog-ng apparently! (bug 3625)
# $Mail::SpamAssassin::Logger::LOG_SA{INHIBIT_LOGGING_IN_SIGCHLD_HANDLER} = 1;

  my $eval_stat;
  eval {
    syslog($level, "%s", $msg); 1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  };

# no longer needed since a patch to bug 6745:
# $Mail::SpamAssassin::Logger::LOG_SA{INHIBIT_LOGGING_IN_SIGCHLD_HANDLER} = 0;

  if (defined $eval_stat) {
    if ($self->check_syslog_sigpipe($msg)) {
      # dealt with
    }
    else {
      warn "logger: syslog failed: $eval_stat\n";

      # only write this warning once, it gets annoying fast
      if (!$self->{already_done_failure_warning}) {
        warn "logger: try using --syslog-socket={unix,inet} or --syslog=file\n";
        $self->{already_done_failure_warning} = 1;
      }
    }
    $self->syslog_incr_failure_counter();
  }
  else {
    $self->{consecutive_failures} = 0;
    $self->check_syslog_sigpipe($msg); # check for SIGPIPE anyway (bug 3625)
  }

  $SIG{PIPE} = 'IGNORE';	# this may have been reset (bug 4026)
}

sub check_syslog_sigpipe {
  my ($self, $msg) = @_;

  if (!$self->{SIGPIPE_RECEIVED}) {
    return 0;     # didn't have a SIGPIPE
  }

  eval {
    # SIGPIPE received when writing to syslog -- close and reopen
    # the log handle, then try again.
    closelog() if $syslog_open;
    $syslog_open = 0;
    openlog($self->{ident}, 'cons,pid,ndelay', $self->{log_facility});
    $syslog_open = 1;
    syslog('debug', "%s", "syslog reopened");
    syslog('info', "%s", $msg);

    # now report what happend
    $msg = "SIGPIPE received, reopening log socket";
    dbg("log: $msg");
    syslog('info', "%s", $msg);

    # if we've received multiple sigpipes, logging is probably still broken.
    if ($self->{SIGPIPE_RECEIVED}) {
      warn "logger: syslog failure: multiple SIGPIPEs received\n";
      $self->{disabled} = 1;
    }

    $self->{SIGPIPE_RECEIVED} = 0;
    return 1;
    1;  # just to not forget a good habit
  } or do {  # something died?  that's not good.
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("log: failure in check_syslog_sigpipe: $eval_stat");
    $self->syslog_incr_failure_counter();
  }
}

sub syslog_incr_failure_counter {
  my ($self) = @_;

  $self->{consecutive_failures}++;
  if ($self->{consecutive_failures}++ > $self->{failure_threshold}) {
    warn("logger: syslog() failed " . $self->{consecutive_failures} .
	 " times in a row, disabled\n");
    $self->{disabled} = 1;
    return 1;
  }
  return 0;
}

sub close_log {
  my ($self) = @_;

  closelog() if $syslog_open;
  $syslog_open = 0;
}

1;
