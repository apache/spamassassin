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

Mail::SpamAssassin::Plugin::Razor2 - perform Razor check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Razor2

=head1 DESCRIPTION

Vipul's Razor is a distributed, collaborative, spam detection and
filtering network based on user submissions of spam.  Detection is done
with signatures that efficiently spot mutating spam content and user
input is validated through reputation assignments.

See http://razor.sourceforge.net/ for more information about Razor.

=cut

package Mail::SpamAssassin::Plugin::Razor2;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::SubProcBackChannel;
use Mail::SpamAssassin::Util qw(force_die am_running_on_windows);
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

  # figure out if razor is even available or not ...
  $self->{razor2_available} = 0;
  if ($mailsaobject->{local_tests_only}) {
    dbg("razor2: local tests only, skipping Razor");
  }
  else {
    if (eval { require Razor2::Client::Agent; }) {
      $self->{razor2_available} = 1;
      dbg("razor2: razor2 is available, version " . $Razor2::Client::Version::VERSION . "\n");
    }
    else {
      dbg("razor2: razor2 is not available");
    }
  }

  $self->register_eval_rule("check_razor2", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_razor2_range", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 DEPENDENCIES

Razor2 requires the C<Razor2::Client::Agent> Perl module to be installed.

=head1 RULE DEFINITIONS

Razor2 calculates a signature for each part of a multipart message and then
compares those signatures to a database of known spam signatures. The server returns a confidence
value (0-100) for each part of the message. The part with the highest confidence value is used as the confidence value
for the message.

The following eval rules are provided by this plugin:

 full   RULENAME   eval:check_razor2()

    Returns true if the confidence value of the message is greater than or equal to `min_cf` as defined in
    the Razor2 configuration file 'razor-agent.conf(1)'.

 full   RULENAME   eval:check_razor2_range(<engine>,<min>,<max>)

    <engine>  Engine number (4, 8 or '')
    <min>     Minimum confidence value (0-100)
    <max>     Maximum confidence value (0-100)

    Returns true if the spam confidence value for the message is greater than or equal to <min> and
    less than or equal to <max>. If <engine> is not specified, the engine with the highest
    confidence value is used.

=head1 USER SETTINGS

=over 4

=item use_razor2 (0|1)		(default: 1)

Whether to use Razor2, if it is available.

=cut

  push(@cmds, {
    setting => 'use_razor2',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item razor_fork (0|1)		(default: 1)

Instead of running Razor2 synchronously, fork separate process for it and
read the results in later (similar to async DNS lookups). Increases
throughput. Considered experimental on Windows, where default is 0.

=cut

  push(@cmds, {
    setting => 'razor_fork',
    is_admin => 1,
    default => am_running_on_windows()?0:1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item razor_timeout n		(default: 5)

How many seconds you wait for Razor to complete before you go on without
the results

=cut

  push(@cmds, {
    setting => 'razor_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION,
  });

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is left to Razor to decide.

=cut

  push(@cmds, {
    setting => 'razor_config',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub razor2_access {
  my ($self, $fulltext, $type, $deadline) = @_;
  my $timeout = $self->{main}->{conf}->{razor_timeout};
  my $return = 0;
  my @results;

  my $debug = $type eq 'check' ? 'razor2' : 'reporter';

  # razor also debugs to stdout. argh. fix it to stderr...
  if (would_log('dbg', $debug)) {
    open(OLDOUT, ">&STDOUT");
    open(STDOUT, ">&STDERR");
  }

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($self);

  my $rnd = rand(0x7fffffff);  # save entropy before Razor clobbers it

  my $timer = Mail::SpamAssassin::Timeout->new(
               { secs => $timeout, deadline => $deadline });
  my $err = $timer->run_and_catch(sub {

    local ($^W) = 0;    # argh, warnings in Razor

    # everything's in the module!
    my $rc = Razor2::Client::Agent->new("razor-$type");

    if ($rc) {
      $rc->{opt} = {
	debug => (would_log('dbg', $debug) > 1),
	foreground => 1,
	config => $self->{main}->{conf}->{razor_config}
      };
      # no facility prefix on this die
      $rc->do_conf() or die "$debug: " . $rc->errstr;

      # Razor2 requires authentication for reporting
      my $ident;
      if ($type ne 'check') {
	# no facility prefix on this die
	$ident = $rc->get_ident
	    or die("$type requires authentication");
      }

      my @msg = ($fulltext);
      # no facility prefix on this die
      my $objects = $rc->prepare_objects(\@msg)
	  or die "$debug: error in prepare_objects";
      unless ($rc->get_server_info()) {
	my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during get_server_info";
	die $error;
      }

      # let's reset the alarm since get_server_info() calls
      # nextserver() which calls discover() which very likely will
      # reset the alarm for us ... how polite.  :(
      $timer->reset();

      # no facility prefix on this die
      my $sigs = $rc->compute_sigs($objects)
	  or die "$debug: error in compute_sigs";

      # if mail isn't welcomelisted, check it out
      # see 'man razor-whitelist'
      if ($type ne 'check' || ! $rc->local_check($objects->[0])) {
	# provide a better error message when servers are unavailable,
	# than "Bad file descriptor Died".
	$rc->connect() or die "$debug: could not connect to any servers\n";

	# Talk to the Razor server and do work
	if ($type eq 'check') {
	  unless ($rc->check($objects)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during check";
	    die $error;
	  }
	}
	else {
	  unless ($rc->authenticate($ident)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during authenticate";
	    die $error;
	    }
	  unless ($rc->report($objects)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during report";
	    die $error;
	  }
	}

	unless ($rc->disconnect()) {
	  my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during disconnect";
	  die $error;
	}
      }

      # Razor 2.14 says that if we get here, we did ok.
      $return = 1;

      # figure out if we have a log file we need to close...
      if (ref($rc->{logref}) && exists $rc->{logref}->{fd}) {
        # the fd can be stdout or stderr, so we need to find out if it is
        # so we don't close them by accident.  Note: we can't just
        # undef the fd here (like the IO::Handle manpage says we can)
        # because it won't actually close, unfortunately. :(
        my $untie = 1;
        foreach my $log (*STDOUT{IO}, *STDERR{IO}) {
          if ($log == $rc->{logref}->{fd}) {
            $untie = 0;
            last;
          }
        }
        if ($untie) {
          close($rc->{logref}->{fd})  or die "error closing log: $!";
        }
      }

      if ($type eq 'check') {
        # so $objects->[0] is the first (only) message, and ->{spam} is a general yes/no
        push(@results, { result => $objects->[0]->{spam} });

        # great for debugging, but leave this off!
        #use Data::Dumper;
        #print Dumper($objects),"\n";

        # ->{p} is for each part of the message
        # so go through each part, taking the highest cf we find
        # of any part that isn't contested (ct).  This helps avoid false
        # positives.  equals logic_method 4.
        #
        # razor-agents < 2.14 have a different object format, so we now support both.
        # $objects->[0]->{resp} vs $objects->[0]->{p}->[part #]->{resp}
        my $part = 0;
        my $arrayref = $objects->[0]->{p} || $objects;
        if (defined $arrayref) {
          foreach my $cf (@{$arrayref}) {
            if (exists $cf->{resp}) {
              for (my $response=0; $response<@{$cf->{resp}}; $response++) {
                my $tmp = $cf->{resp}->[$response];
                my $tmpcf = $tmp->{cf}; # Part confidence
                my $tmpct = $tmp->{ct}; # Part contested?
                my $engine = $cf->{sent}->[$response]->{e};

                # These should always be set, but just in case ...
                $tmpcf = 0 unless defined $tmpcf;
                $tmpct = 0 unless defined $tmpct;
                $engine = 0 unless defined $engine;

                push(@results,
                      { part => $part, engine => $engine, contested => $tmpct, confidence => $tmpcf });
              }
            }
            else {
              push(@results, { part => $part, noresponse => 1 });
            }
            $part++;
          }
        }
        else {
          # If we have some new $objects format that isn't close to
          # the current razor-agents 2.x version, we won't FP but we
          # should alert in debug.
          dbg("$debug: it looks like the internal Razor object has changed format!");
        }
      }
    }
    else {
      warn "$debug: undefined Razor2::Client::Agent\n";
    }
  
  });

  # OK, that's enough Razor stuff. now, reset all that global
  # state it futzes with :(
  # work around serious brain damage in Razor2 (constant seed)
  $rnd ^= int(rand(0xffffffff));  # mix old acc with whatever came out of razor
  srand;                          # let Perl give it a try ...
  $rnd ^= int(rand(0xffffffff));  # ... and mix-in that too
  srand($rnd & 0x7fffffff);  # reseed, keep it unsigned 32-bit just in case

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($self);

  if ($timer->timed_out()) {
    dbg("$debug: razor2 $type timed out after $timeout seconds");
  }

  if ($err) {
    chomp $err;
    if ($err =~ /(?:could not connect|network is unreachable)/) {
      # make this a dbg(); SpamAssassin will still continue,
      # but without Razor checking.  otherwise there may be
      # DSNs and errors in syslog etc., yuck
      dbg("$debug: razor2 $type could not connect to any servers");
    } elsif ($err =~ /timeout/i) {
      dbg("$debug: razor2 $type timed out connecting to servers");
    } else {
      warn("$debug: razor2 $type failed: $! $err");
    }
  }

  # razor also debugs to stdout. argh. fix it to stderr...
  if (would_log('dbg', $debug)) {
    open(STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  return wantarray ? ($return, @results) : $return;
}

sub plugin_report {
  my ($self, $options) = @_;

  return unless $self->{razor2_available};
  return if $self->{main}->{local_tests_only};
  return unless $self->{main}->{conf}->{use_razor2};
  return if $options->{report}->{options}->{dont_report_to_razor};

  my $timer = $self->{main}->time_method("razor2_report");

  if ($self->razor2_access($options->{text}, 'report', undef)) {
    $options->{report}->{report_available} = 1;
    info('reporter: spam reported to Razor');
    $options->{report}->{report_return} = 1;
  }
  else {
    info('reporter: could not report spam to Razor');
  }
}

sub plugin_revoke {
  my ($self, $options) = @_;

  my $timer = $self->{main}->time_method("razor2_revoke");

  return unless $self->{razor2_available};
  return if $self->{main}->{local_tests_only};
  return unless $self->{main}->{conf}->{use_razor2};
  return if $options->{revoke}->{options}->{dont_report_to_razor};

  if ($self->razor2_access($options->{text}, 'revoke', undef)) {
    $options->{revoke}->{revoke_available} = 1;
    info('reporter: spam revoked from Razor');
    $options->{revoke}->{revoke_return} = 1;
  }
  else {
    info('reporter: could not revoke spam from Razor');
  }
}

sub finish_parsing_start {
  my ($self, $opts) = @_;

  # If forking, hard adjust priority -100 to launch early
  # Find rulenames from eval_to_rule mappings
  if ($opts->{conf}->{razor_fork}) {
    foreach (@{$opts->{conf}->{eval_to_rule}->{check_razor2}}) {
      dbg("razor2: adjusting rule $_ priority to -100");
      $opts->{conf}->{priority}->{$_} = -100;
    }
    foreach (@{$opts->{conf}->{eval_to_rule}->{check_razor2_range}}) {
      dbg("razor2: adjusting rule $_ priority to -100");
      $opts->{conf}->{priority}->{$_} = -100;
    }
  }
}

sub check_razor2 {
  my ($self, $pms, $full) = @_;

  return 0 unless $self->{razor2_available};
  return 0 unless $self->{main}->{conf}->{use_razor2};

  return $pms->{razor2_result} if (defined $pms->{razor2_result});

  return 0 if $pms->{razor2_running};
  $pms->{razor2_running} = 1;

  my $timer = $self->{main}->time_method("check_razor2");

  ## non-forking method

  if (!$self->{main}->{conf}->{razor_fork}) {
    # TODO: check for cache header, set results appropriately
    # do it this way to make it easier to get out the results later from the
    # netcache plugin ... what netcache plugin?
    (undef, my @results) =
      $self->razor2_access($full, 'check', $pms->{master_deadline});
    return $self->_check_result($pms, \@results);
  }

  ## forking method

  $pms->{razor2_rulename} = $pms->get_current_eval_rule_name();

  # create socketpair for communication
  $pms->{razor2_backchannel} = Mail::SpamAssassin::SubProcBackChannel->new();
  my $back_selector = '';
  $pms->{razor2_backchannel}->set_selector(\$back_selector);
  eval {
    $pms->{razor2_backchannel}->setup_backchannel_parent_pre_fork();
  } or do {
    dbg("razor2: backchannel pre-setup failed: $@");
    delete $pms->{razor2_backchannel};
    return 0;
  };

  my $pid = fork();
  if (!defined $pid) {
    info("razor2: child fork failed: $!");
    delete $pms->{razor2_backchannel};
    return 0;
  }
  if (!$pid) {
    $0 = "$0 (razor2)";
    $SIG{CHLD} = 'DEFAULT';
    $SIG{PIPE} = 'IGNORE';
    $SIG{$_} = sub {
      eval { dbg("razor2: child process $$ caught signal $_[0]"); };
      force_die(6);  # avoid END and destructor processing
      } foreach am_running_on_windows()?qw(INT HUP TERM QUIT):qw(INT HUP TERM TSTP QUIT USR1 USR2);
    dbg("razor2: child process $$ forked");
    $pms->{razor2_backchannel}->setup_backchannel_child_post_fork();
    (undef, my @results) =
      $self->razor2_access($full, 'check', $pms->{master_deadline});
    my $backmsg;
    eval {
      $backmsg = Storable::freeze(\@results);
    };
    if ($@) {
      dbg("razor2: child return value freeze failed: $@");
      force_die(0); # avoid END and destructor processing
    }
    if (!syswrite($pms->{razor2_backchannel}->{parent}, $backmsg)) {
      dbg("razor2: child backchannel write failed: $!");
    }
    force_die(0); # avoid END and destructor processing
  }

  $pms->{razor2_pid} = $pid;

  eval {
    $pms->{razor2_backchannel}->setup_backchannel_parent_post_fork($pid);
  } or do {
    dbg("razor2: backchannel post-setup failed: $@");
    delete $pms->{razor2_backchannel};
    return 0;
  };

  return; # return undef for async status
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

  return 0 if !$pms->{razor2_backchannel};
  return 0 if !$pms->{razor2_pid};

  my $timer = $self->{main}->time_method("check_razor2");

  $pms->{razor2_abort} = $pms->{deadline_exceeded} || $pms->{shortcircuited};

  my $kid_pid = $pms->{razor2_pid};
  # if $finish, force waiting for the child
  my $pid = waitpid($kid_pid, $finish && !$pms->{razor2_abort} ? 0 : WNOHANG);
  if ($pid == 0) {
    #dbg("razor2: child process $kid_pid not finished yet, trying later");
    if ($pms->{razor2_abort}) {
      dbg("razor2: bailing out due to deadline/shortcircuit");
      kill('TERM', $kid_pid);
      if (waitpid($kid_pid, WNOHANG) == 0) {
        sleep(1);
        if (waitpid($kid_pid, WNOHANG) == 0) {
          dbg("razor2: child process $kid_pid still alive, KILL");
          kill('KILL', $kid_pid);
          waitpid($kid_pid, 0);
        }
      }
      delete $pms->{razor2_pid};
      delete $pms->{razor2_backchannel};
    }
    return 0;
  } elsif ($pid == -1) {
    # child does not exist?
    dbg("razor2: child process $kid_pid already handled?");
    delete $pms->{razor2_backchannel};
    return 0;
  }

  $pms->rule_ready($pms->{razor2_rulename}); # mark rule ready for metas

  dbg("razor2: child process $kid_pid finished, reading results");

  my $backmsg;
  my $ret = sysread($pms->{razor2_backchannel}->{latest_kid_fh}, $backmsg, am_running_on_windows()?512:PIPE_BUF);
  if (!defined $ret || $ret == 0) {
    dbg("razor2: could not read result from child: ".($ret == 0 ? 0 : $!));
    delete $pms->{razor2_backchannel};
    return 0;
  }

  delete $pms->{razor2_backchannel};

  my $results;
  eval {
    $results = Storable::thaw($backmsg);
  };
  if ($@) {
    dbg("razor2: child return value thaw failed: $@");
    return;
  }

  $self->_check_result($pms, $results);
}

sub _check_result {
  my ($self, $pms, $results) = @_;

  $self->{main}->call_plugins ('process_razor_result',
  	{ results => $results, permsgstatus => $pms }
  );

  foreach my $result (@$results) {
    if (exists $result->{result}) {
      $pms->{razor2_result} = $result->{result} if $result->{result};
    }
    elsif ($result->{noresponse}) {
      dbg('razor2: part=' . $result->{part} . ' noresponse');
    }
    else {
      dbg('razor2: part=' . $result->{part} .
        ' engine=' .  $result->{engine} .
	' contested=' . $result->{contested} .
	' confidence=' . $result->{confidence});

      next if $result->{contested};

      my $cf = $pms->{razor2_cf_score}->{$result->{engine}} || 0;
      if ($result->{confidence} > $cf) {
        $pms->{razor2_cf_score}->{$result->{engine}} = $result->{confidence};
      }
    }
  }

  $pms->{razor2_result} ||= 0;
  $pms->{razor2_cf_score} ||= {};

  dbg("razor2: results: spam? " . $pms->{razor2_result});
  while(my ($engine, $cf) = each %{$pms->{razor2_cf_score}}) {
    dbg("razor2: results: engine $engine, highest cf score: $cf");
  }

  if ($self->{main}->{conf}->{razor_fork}) {
    # forked needs to run got_hit()
    if ($pms->{razor2_rulename} && $pms->{razor2_result}) {
      $pms->got_hit($pms->{razor2_rulename}, "", ruletype => 'eval');
    }
    # forked needs to run range callbacks
    if ($pms->{razor2_range_callbacks}) {
      foreach (@{$pms->{razor2_range_callbacks}}) {
        $self->check_razor2_range($pms, '', @$_);
      }
    }
  }

  return $pms->{razor2_result};
}

# Check the cf value of a given message and return if it's within the
# given range
sub check_razor2_range {
  my ($self, $pms, $body, $engine, $min, $max, $rulename) = @_;

  # If Razor2 isn't available, or the general test is disabled, don't
  # continue.
  return 0 unless $self->{razor2_available};
  return 0 unless $self->{main}->{conf}->{use_razor2};

  # Check if callback overriding rulename
  if (!defined $rulename) {
    $rulename = $pms->get_current_eval_rule_name();
  }

  if ($pms->{razor2_abort}) {
    $pms->rule_ready($rulename); # mark rule ready for metas
    return;
  }

  # If forked, call back later unless results are in
  if ($self->{main}->{conf}->{razor_fork}) {
    if (!defined $pms->{razor2_result}) {
      dbg("razor2: delaying check_razor2_range call for $rulename");
      # array matches check_razor2_range() argument order
      push @{$pms->{razor2_range_callbacks}},
        [$engine, $min, $max, $rulename];
      return; # return undef for async status
    }
  } else {
    # If Razor2 hasn't been checked yet, go ahead and run it.
    # (only if we are non-forking.. forking will handle these in
    # callbacks)
    if (!$pms->{razor2_running}) {
      $self->check_razor2($pms, $body);
    }
  }

  $pms->rule_ready($rulename); # mark rule ready for metas

  my $cf = 0;
  if ($engine) {
    $cf = $pms->{razor2_cf_score}->{$engine};
    return 0 unless defined $cf;
  }
  else {
    # If no specific engine was given to the rule, find the highest cf
    # determined and use that
    while(my ($engine, $ecf) = each %{$pms->{razor2_cf_score}}) {
      if ($ecf > $cf) {
        $cf = $ecf;
      }
    }
  }

  if ($cf >= $min && $cf <= $max) {
    my $cf_str = sprintf("cf: %3d", $cf);
    $pms->test_log($cf_str, $rulename);
    if ($self->{main}->{conf}->{razor_fork}) {
      $pms->got_hit($rulename, "", ruletype => 'eval');
    }
    return 1;
  }

  return 0;
}

# Version features
sub has_fork { 1 }

1;

=back

=cut
