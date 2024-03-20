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

Mail::SpamAssassin::Plugin::Pyzor - perform Pyzor check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Pyzor

=head1 DESCRIPTION

Pyzor is a collaborative, networked system to detect and block spam
using identifying digests of messages.

See http://pyzor.org/ for more information about Pyzor.

=cut

package Mail::SpamAssassin::Plugin::Pyzor;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::SubProcBackChannel;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path am_running_on_windows
                                proc_status_ok exit_status_str force_die);
use strict;
use warnings;
# use bytes;
use re 'taint';

use Storable;
use POSIX qw(PIPE_BUF WNOHANG);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # are network tests enabled?
  if ($mailsaobject->{local_tests_only}) {
    $self->{pyzor_available} = 0;
    dbg("pyzor: local tests only, disabling Pyzor");
  }
  else {
    $self->{pyzor_available} = 1;
    dbg("pyzor: network tests on, attempting Pyzor");
  }

  $self->register_eval_rule("check_pyzor", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item use_pyzor (0|1)		(default: 1)

Whether to use Pyzor, if it is available.

=cut

  push (@cmds, {
    setting => 'use_pyzor',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item pyzor_count_min NUMBER	(default: 5)

This option sets how often a message's body checksum must have been
reported to the Pyzor server before SpamAssassin will consider the Pyzor
check as matched.

As most clients should not be auto-reporting these checksums, you should
set this to a relatively low value, e.g. C<5>.

=cut

  push (@cmds, {
    setting => 'pyzor_count_min',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  # Deprecated setting, the name makes no sense!
  push (@cmds, {
    setting => 'pyzor_max',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      warn("deprecated setting used, change pyzor_max to pyzor_count_min\n");
      if ($value !~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{pyzor_count_min} = $value;
    }
  });

=item pyzor_welcomelist_min NUMBER	(default: 10)

Previously pyzor_whitelist_min which will work interchangeably until 4.1.

This option sets how often a message's body checksum must have been
welcomelisted to the Pyzor server for SpamAssassin to consider ignoring the
result.  Final decision is made by pyzor_welcomelist_factor.

=cut

  push (@cmds, {
    setting => 'pyzor_welcomelist_min',
    aliases => ['pyzor_whitelist_min'], # removed in 4.1
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item pyzor_welcomelist_factor NUMBER	(default: 0.2)

Previously pyzor_whitelist_factor which will work interchangeably until 4.1.

Ignore Pyzor result if REPORTCOUNT x NUMBER E<gt>= pyzor_welcomelist_min.
For default setting this means: 50 reports requires 10 welcomelistings.

=cut

  push (@cmds, {
    setting => 'pyzor_welcomelist_factor',
    aliases => ['pyzor_whitelist_factor'], # removed in 4.1
    default => 0.2,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item pyzor_fork (0|1)		(default: 1)

Instead of running Pyzor synchronously, fork separate process for it and
read the results in later (similar to async DNS lookups).  Increases
throughput. Considered experimental on Windows, where default is 0.

=cut

  push(@cmds, {
    setting => 'pyzor_fork',
    is_admin => 1,
    default => am_running_on_windows()?0:1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item pyzor_perl (0|1)         (default: 0)

Instead of running Pyzor client, use a pure Perl client.

=cut

    push(@cmds, {
      setting => 'pyzor_perl',
      is_admin => 1,
      default => 0,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    });

=item pyzor_timeout n		(default: 5)

How many seconds you wait for Pyzor to complete, before scanning continues
without the Pyzor results. A numeric value is optionally suffixed by a
time unit (s, m, h, d, w, indicating seconds (default), minutes, hours,
days, weeks).

You can configure Pyzor to have its own per-server timeout.  Set this
plugin's timeout with that in mind.  This plugin's timeout is a maximum
ceiling.  If Pyzor takes longer than this to complete its communication
with all servers, no results are used by SpamAssassin.

Pyzor servers do not yet synchronize their servers, so it can be
beneficial to check and report to more than one.  See the pyzor-users
mailing list for alternate servers that are not published via
'pyzor discover'.

If you are using multiple Pyzor servers, a good rule of thumb would be to
set the SpamAssassin plugin's timeout to be the same or just a bit more
than the per-server Pyzor timeout (e.g., 3.5 and 2 for two Pyzor servers).
If more than one of your Pyzor servers is always timing out, consider
removing one of them.

=cut

  push (@cmds, {
    setting => 'pyzor_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION
  });

=item pyzor_options options

Specify additional options to the pyzor(1) command. Please note that only
characters in the range [0-9A-Za-z =,._/-] are allowed for security reasons.

=cut

  push (@cmds, {
    setting => 'pyzor_options',
    is_admin => 1,
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ m{^([0-9A-Za-z =,._/-]+)$}) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{pyzor_options} = $1;
    }
});

=item pyzor_path STRING

This option tells SpamAssassin specifically where to find the C<pyzor>
client instead of relying on SpamAssassin to find it in the current
PATH.  Note that if I<taint mode> is enabled in the Perl interpreter,
you should use this, as the current PATH will have been cleared.

=cut

  push (@cmds, {
    setting => 'pyzor_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = untaint_file_path($value);
      if (!-x $value) {
        info("config: pyzor_path \"$value\" isn't an executable");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{pyzor_path} = $value;
    }
  });

=item pyzor_server_file FILE

Pyzor servers configuration file path, used by Pyzor Perl implementation.
By default Pyzor will connect to public.pyzor.org on port 24441.

=cut

  push (@cmds, {
    setting => 'pyzor_server_file',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (! -f $value) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      } else {
        my $i = 0;
        open(PSF, '<', untaint_file_path($value));
        while(<PSF>) {
          chomp;
          next if (/^#/);
          my ($host, $port) = split(/:/, $_);
          $self->{pyzor_host}[$i] = $host;
          $self->{pyzor_port}[$i] = $port;
          dbg("Setting Pyzor host to $host and port to $port");
          $i++;
        }
        close(PSF);
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub is_pyzor_available {
    my ($self) = @_;

    if($self->{main}->{conf}->{pyzor_perl} and $self->{main}->{conf}->{pyzor_fork}) {
      info("pyzor: pyzor_perl and pyzor_fork cannot be enabled at the same time, Pyzor support will be disabled");
      return 0;
    }
    local $@;
    if($self->{main}->{conf}->{pyzor_perl}) {
      eval {
        require Mail::SpamAssassin::Pyzor::Digest;
        require Mail::SpamAssassin::Pyzor::Client;
      };
      if($@) {
        $self->{pyzor_available} = 0;
        dbg("pyzor: pyzor Perl module is not available");
        return 0;
      } else {
        $self->{pyzor_available} = 1;
        dbg("pyzor: pyzor Perl module is available");
        return 1;
      }
    } else {
      my $pyzor = $self->{main}->{conf}->{pyzor_path} ||
        Mail::SpamAssassin::Util::find_executable_in_env_path('pyzor');
      unless ($pyzor && -x $pyzor) {
        dbg("pyzor: no pyzor executable found");
        $self->{pyzor_available} = 0;
        return 0;
      }

      # remember any found pyzor
      $self->{main}->{conf}->{pyzor_path} = $pyzor;
      dbg("pyzor: pyzor is available: $pyzor");
      return 1;
    }
}

sub finish_parsing_start {
  my ($self, $opts) = @_;

  # If forking, hard adjust priority -100 to launch early
  # Find rulenames from eval_to_rule mappings
  if ($opts->{conf}->{pyzor_fork}) {
    foreach (@{$opts->{conf}->{eval_to_rule}->{check_pyzor}}) {
      dbg("pyzor: adjusting rule $_ priority to -100");
      $opts->{conf}->{priority}->{$_} = -100;
    }
  }
}

sub check_pyzor {
  my ($self, $pms, $full) = @_;

  return 0 if !$self->{pyzor_available};
  return 0 if !$self->{main}->{conf}->{use_pyzor};

  return 0 if $pms->{pyzor_running};
  $pms->{pyzor_running} = 1;

  return 0 if !$self->is_pyzor_available();

  my $timer = $self->{main}->time_method("check_pyzor");

  # initialize valid tags
  $pms->{tag_data}->{PYZOR} = '';

  # create fulltext tmpfile now (before possible forking)
  if(!$self->{main}->{conf}->{pyzor_perl}) {
    $pms->{pyzor_tmpfile} = $pms->create_fulltext_tmpfile();
  }

  ## non-forking method
  if ((!$self->{main}->{conf}->{pyzor_fork}) and (!$self->{main}->{conf}->{pyzor_perl})) {
    my @results = $self->pyzor_lookup($pms);
    return $self->_check_result($pms, \@results);
  }

  ## Pure Perl implementation
  if($self->{main}->{conf}->{pyzor_perl}) {
    my @results = $self->pyzor_lookup($pms, $full);
    return $self->_check_result($pms, \@results);
  }

  ## forking method
  $pms->{pyzor_rulename} = $pms->get_current_eval_rule_name();

  # create socketpair for communication
  $pms->{pyzor_backchannel} = Mail::SpamAssassin::SubProcBackChannel->new();
  my $back_selector = '';
  $pms->{pyzor_backchannel}->set_selector(\$back_selector);
  eval {
    $pms->{pyzor_backchannel}->setup_backchannel_parent_pre_fork();
  } or do {
    dbg("pyzor: backchannel pre-setup failed: $@");
    delete $pms->{pyzor_backchannel};
    return 0;
  };

  my $pid = fork();
  if (!defined $pid) {
    info("pyzor: child fork failed: $!");
    delete $pms->{pyzor_backchannel};
    return 0;
  }
  if (!$pid) {
    $0 = "$0 (pyzor)";
    $SIG{CHLD} = 'DEFAULT';
    $SIG{PIPE} = 'IGNORE';
    $SIG{$_} = sub {
      eval { dbg("pyzor: child process $$ caught signal $_[0]"); };
      force_die(6);  # avoid END and destructor processing
      } foreach am_running_on_windows()?qw(INT HUP TERM QUIT):qw(INT HUP TERM TSTP QUIT USR1 USR2);
    dbg("pyzor: child process $$ forked");
    $pms->{pyzor_backchannel}->setup_backchannel_child_post_fork();
    my @results = $self->pyzor_lookup($pms);
    my $backmsg;
    eval {
      $backmsg = Storable::freeze(\@results);
    };
    if ($@) {
      dbg("pyzor: child return value freeze failed: $@");
      force_die(0); # avoid END and destructor processing
    }
    if (!syswrite($pms->{pyzor_backchannel}->{parent}, $backmsg)) {
      dbg("pyzor: child backchannel write failed: $!");
    }
    force_die(0); # avoid END and destructor processing
  }

  $pms->{pyzor_pid} = $pid;

  eval {
    $pms->{pyzor_backchannel}->setup_backchannel_parent_post_fork($pid);
  } or do {
    dbg("pyzor: backchannel post-setup failed: $@");
    delete $pms->{pyzor_backchannel};
    return 0;
  };

  return; # return undef for async status
}

sub pyzor_lookup {
  my ( $self, $pms, $fulltext ) = @_;
  my $conf = $self->{main}->{conf};
  my $timeout = $conf->{pyzor_timeout};
  my $server_port;
  my @pyzor_hosts;
  my @pyzor_ports;
  if(defined $conf->{pyzor_host}) {
    @pyzor_hosts = @{$conf->{pyzor_host}};
  }
  if(defined $conf->{pyzor_port}) {
    @pyzor_ports = @{$conf->{pyzor_port}};
  }
  $pyzor_hosts[0] //= 'public.pyzor.org';
  $pyzor_ports[0] //= 24441;

  if($self->{main}->{conf}->{pyzor_perl}) {
    my @resp;
    my $cnt = 0;
    my $resp;
    my $ref;

    my $digest = Mail::SpamAssassin::Pyzor::Digest::get( $pms, $fulltext );

    foreach my $server_host ( @pyzor_hosts ) {
      $server_port = $pyzor_ports[$cnt];
      $cnt++;
      my $client = Mail::SpamAssassin::Pyzor::Client->new( 'timeout' => $timeout,
                                                                         'server_host' => $server_host,
                                                                         'server_port' => $server_port );
      local $@;
      $ref = eval { $client->check($digest); };
      # $client reply must be an hash
      return 0 if (not (ref $ref eq ref {}));
      if ($@) {
        my $err = $@;

        $err = eval { $err->get_message() } || $err;

        warn("pyzor: check failed: $err\n");
        return 0;
      }
      # mimic pyzor client reply
      # public.pyzor.org:24441\t(200, 'OK')\t1\t0
      $resp .= "$server_host:$server_port\t($ref->{'Code'}, '" . $ref->{'Diag'} . "')\t$ref->{'Count'}\t$ref->{'WL-Count'}\n";
      undef $ref;
    }
    @resp = split(/^/m, $resp, -1);
    return @resp;
  } else {
    # note: not really tainted, this came from system configuration file
    my $path = untaint_file_path($conf->{pyzor_path});
    my $opts = untaint_var($conf->{pyzor_options}) || '';

    $pms->enter_helper_run_mode();

    my $pid;
    my @resp;
    my $timer = Mail::SpamAssassin::Timeout->new(
             { secs => $timeout, deadline => $pms->{master_deadline} });
    my $err = $timer->run_and_catch(sub {
      local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

      dbg("pyzor: opening pipe: ".
        join(' ', $path, $opts, "check", "<".$pms->{pyzor_tmpfile}));

      $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*PYZOR,
      $pms->{pyzor_tmpfile}, 1, $path, split(' ', $opts), "check");
      $pid or die "$!\n";

      # read+split avoids a Perl I/O bug (Bug 5985)
      my($inbuf, $nread);
      my $resp = '';
      while ($nread = read(PYZOR, $inbuf, 8192)) { $resp .= $inbuf }
      defined $nread  or die "error reading from pipe: $!";
      @resp = split(/^/m, $resp, -1);

      my $errno = 0;
      close PYZOR or $errno = $!;
      if (proc_status_ok($?, $errno)) {
        dbg("pyzor: [%s] finished successfully", $pid);
      } elsif (proc_status_ok($?, $errno, 0, 1)) {  # sometimes it exits with 1
        dbg("pyzor: [%s] finished: %s", $pid, exit_status_str($?, $errno));
      } else {
        info("pyzor: [%s] error: %s", $pid, exit_status_str($?, $errno));
      }

    });

    if (defined(fileno(*PYZOR))) {  # still open
      if ($pid) {
        if (kill('TERM', $pid)) {
          dbg("pyzor: killed stale helper [$pid]");
        } else {
          dbg("pyzor: killing helper application [$pid] failed: $!");
        }
      }
      my $errno = 0;
      close PYZOR or $errno = $!;
      proc_status_ok($?, $errno)
        or info("pyzor: [%s] error: %s", $pid, exit_status_str($?, $errno));
    }

    $pms->leave_helper_run_mode();

    if ($timer->timed_out()) {
      dbg("pyzor: check timed out after $timeout seconds");
      return ();
    } elsif ($err) {
      chomp $err;
      info("pyzor: check failed: $err");
      return ();
    }

    return @resp;
  }
}

sub check_tick {
  my ($self, $opts) = @_;
  $self->_check_forked_result($opts->{permsgstatus}, 0);
}

sub check_cleanup {
  my ($self, $opts) = @_;
  $self->_check_forked_result($opts->{permsgstatus}, 1);
}

sub _check_forked_result {
  my ($self, $pms, $finish) = @_;

  return 0 if !$pms->{pyzor_backchannel};
  return 0 if !$pms->{pyzor_pid};

  my $timer = $self->{main}->time_method("check_pyzor");

  $pms->{pyzor_abort} = $pms->{deadline_exceeded} || $pms->{shortcircuited};

  my $kid_pid = $pms->{pyzor_pid};
  # if $finish, force waiting for the child
  my $pid = waitpid($kid_pid, $finish && !$pms->{pyzor_abort} ? 0 : WNOHANG);
  if ($pid == 0) {
    #dbg("pyzor: child process $kid_pid not finished yet, trying later");
    if ($pms->{pyzor_abort}) {
      dbg("pyzor: bailing out due to deadline/shortcircuit");
      kill('TERM', $kid_pid);
      if (waitpid($kid_pid, WNOHANG) == 0) {
        sleep(1);
        if (waitpid($kid_pid, WNOHANG) == 0) {
          dbg("pyzor: child process $kid_pid still alive, KILL");
          kill('KILL', $kid_pid);
          waitpid($kid_pid, 0);
        }
      }
      delete $pms->{pyzor_pid};
      delete $pms->{pyzor_backchannel};
    }
    return 0;
  } elsif ($pid == -1) {
    # child does not exist?
    dbg("pyzor: child process $kid_pid already handled?");
    delete $pms->{pyzor_backchannel};
    return 0;
  }

  $pms->rule_ready($pms->{pyzor_rulename}); # mark rule ready for metas

  dbg("pyzor: child process $kid_pid finished, reading results");

  my $backmsg;
  my $ret = sysread($pms->{pyzor_backchannel}->{latest_kid_fh}, $backmsg, am_running_on_windows()?512:PIPE_BUF);
  if (!defined $ret || $ret == 0) {
    dbg("pyzor: could not read result from child: ".($ret == 0 ? 0 : $!));
    delete $pms->{pyzor_backchannel};
    return 0;
  }

  delete $pms->{pyzor_backchannel};

  my $results;
  eval {
    $results = Storable::thaw($backmsg);
  };
  if ($@) {
    dbg("pyzor: child return value thaw failed: $@");
    return;
  }

  $self->_check_result($pms, $results);
}

sub _check_result {
  my ($self, $pms, $results) = @_;

  unless ((defined $results) && @$results) {
    dbg("pyzor: no response from server");
    return 0;
  }

  my $count = 0;
  my $count_wl = 0;
  foreach my $res (@$results) {
    chomp($res);
    if ($res =~ /^Traceback/) {
      info("pyzor: internal error, python traceback seen in response: $res");
      return 0;
    }
    dbg("pyzor: got response: $res");
    # this regexp is intended to be a little bit forgiving
    if ($res =~ /^\S+\t.*?\t(\d+)\t(\d+)\s*$/) {
      # until pyzor servers can sync their DBs,
      # sum counts obtained from all servers
      $count += untaint_var($1)+0; # crazy but needs untainting
      $count_wl += untaint_var($2)+0;
    } else {
      # warn on failures to parse
      info("pyzor: failure to parse response \"$res\"");
    }
  }

  my $conf = $self->{main}->{conf};

  my $count_min = $conf->{pyzor_count_min};
  my $wl_min = $conf->{pyzor_welcomelist_min};

  my $wl_limit = $count_wl >= $wl_min ?
  $count * $conf->{pyzor_welcomelist_factor} : 0;

  dbg("pyzor: result: COUNT=$count/$count_min WELCOMELIST=$count_wl/$wl_min/%.1f",
    $wl_limit);
  $pms->set_tag('PYZOR', "Reported $count times, welcomelisted $count_wl times.");

  # Empty body etc results in same hash, we should skip very large numbers..
  if ($count >= 1000000 || $count_wl >= 10000) {
    dbg("pyzor: result exceeded hardcoded limits, ignoring: count/wl 1000000/10000");
    return 0;
  }

  # Welcomelisted?
  if ($wl_limit && $count_wl >= $wl_limit) {
    dbg("pyzor: message welcomelisted");
    return 0;
  }

  if ($count >= $count_min) {
    if ($conf->{pyzor_fork}) {
      # forked needs to run got_hit()
      $pms->got_hit($pms->{pyzor_rulename}, "", ruletype => 'eval');
      return 0;
    }
    return 1;
  }
  return 0;
}

sub plugin_report {
  my ($self, $options) = @_;

  return if !$self->{pyzor_available};
  return if !$self->{main}->{conf}->{use_pyzor};
  return if $options->{report}->{options}->{dont_report_to_pyzor};
  return if !$self->is_pyzor_available();

  if($self->{main}->{conf}->{pyzor_perl}) {
    if (!$options->{report}->{options}->{dont_report_to_pyzor} && $self->is_pyzor_available()) {
      if ($self->pyzor_report($options)) {
        $options->{report}->{report_available} = 1;
        info("reporter: spam reported to Pyzor");
        $options->{report}->{report_return} = 1;
      } else {
        info("reporter: could not report spam to Pyzor");
      }
    }
  } else {
    # use temporary file: open2() is unreliable due to buffering under spamd
    my $tmpf = $options->{report}->create_fulltext_tmpfile($options->{text});
    if ($self->pyzor_report($options, $tmpf)) {
      $options->{report}->{report_available} = 1;
      info("reporter: spam reported to Pyzor");
      $options->{report}->{report_return} = 1;
    }
    else {
      info("reporter: could not report spam to Pyzor");
    }
    $options->{report}->delete_fulltext_tmpfile($tmpf);
  }
  return 1;
}

sub pyzor_report {
  my ( $self, $options, $tmpf ) = @_;

  my $conf = $self->{main}->{conf};

  my $server_port;
  my @pyzor_hosts;
  my @pyzor_ports;
  if(defined $conf->{pyzor_host}) {
    @pyzor_hosts = @{$conf->{pyzor_host}};
  }
  if(defined $conf->{pyzor_port}) {
    @pyzor_ports = @{$conf->{pyzor_port}};
  }
  $pyzor_hosts[0] //= 'public.pyzor.org';
  $pyzor_ports[0] //= 24441;

  my $timeout = $self->{main}->{conf}->{pyzor_timeout};

  if($self->{main}->{conf}->{pyzor_perl}) {
    my $pms =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $options->{msg});

    my $cnt = 0;
    foreach my $server_host ( @pyzor_hosts ) {
      $server_port = $pyzor_ports[$cnt];
      $cnt++;
      my $client = Mail::SpamAssassin::Pyzor::Client->new( 'timeout' => $timeout,
                                                                           'server_host' => $server_host,
                                                                           'server_port' => $server_port );

      my $digest = Mail::SpamAssassin::Pyzor::Digest::get( $pms );

      local $@;
      my $ref = eval { $client->report($digest); };
      if ($@) {
        warn("pyzor: report failed: $@");
        return 0;
      }
      elsif ( $ref->{'Code'} ne 200 ) {
        dbg("pyzor: report failed with invalid code: $ref->{'Code'}: $ref->{'Diag'}");
        return 0;
      }
    }
  } else {
    # note: not really tainted, this came from system configuration file
    my $path = untaint_file_path($options->{report}->{conf}->{pyzor_path});
    my $opts = untaint_var($options->{report}->{conf}->{pyzor_options}) || '';

    my $timeout = $self->{main}->{conf}->{pyzor_timeout};

    $options->{report}->enter_helper_run_mode();

    my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
    my $err = $timer->run_and_catch(sub {

      local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

      dbg("pyzor: opening pipe: " . join(' ', $path, $opts, "report", "< $tmpf"));

      my $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*PYZOR,
  	$tmpf, 1, $path, split(' ', $opts), "report");
      $pid or die "$!\n";

      my($inbuf,$nread,$nread_all); $nread_all = 0;
      # response is ignored, just check its existence
      while ( $nread=read(PYZOR,$inbuf,8192) ) { $nread_all += $nread }
      defined $nread  or die "error reading from pipe: $!";

      dbg("pyzor: empty response")  if $nread_all < 1;

      my $errno = 0;  close PYZOR or $errno = $!;
      # closing a pipe also waits for the process executing on the pipe to
      # complete, no need to explicitly call waitpid
      # my $child_stat = waitpid($pid,0) > 0 ? $? : undef;
      if (proc_status_ok($?,$errno, 0)) {
        dbg("pyzor: [%s] reporter finished successfully", $pid);
      } else {
        info("pyzor: [%s] reporter error: %s", $pid, exit_status_str($?,$errno));
      }

    });

    $options->{report}->leave_helper_run_mode();

    if ($timer->timed_out()) {
      dbg("reporter: pyzor report timed out after $timeout seconds");
      return 0;
    }

    if ($err) {
      chomp $err;
      if ($err eq '__brokenpipe__ignore__') {
        dbg("reporter: pyzor report failed: broken pipe");
      } else {
        warn("reporter: pyzor report failed: $err\n");
      }
      return 0;
    }
  }
  return 1;
}

# Version features
sub has_fork { 1 }
sub has_perl { 1 }

1;

=back

=cut
