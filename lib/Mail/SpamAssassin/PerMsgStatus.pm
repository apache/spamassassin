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

Mail::SpamAssassin::PerMsgStatus - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = Mail::SpamAssassin->new({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin/user_prefs'
  });
  my $mail = $spamtest->parse();

  my $status = $spamtest->check ($mail);

  my $rewritten_mail;
  if ($status->is_spam()) {
    $rewritten_mail = $status->rewrite_mail ();
  }
  ...


=head1 DESCRIPTION

The Mail::SpamAssassin C<check()> method returns an object of this
class.  This object encapsulates all the per-message state.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PerMsgStatus;

use strict;
use warnings;
use re 'taint';

use Errno qw(ENOENT);
use Time::HiRes qw(time);
use Encode;

use Mail::SpamAssassin::Constants qw(:sa :ip);
use Mail::SpamAssassin::AsyncLoop;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util qw(untaint_var base64_encode idn_to_ascii
                                uri_list_canonicalize reverse_ip_address
                                is_fqdn_valid parse_header_addresses);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Logger;

our @ISA = qw();

# methods defined by the compiled ruleset; deleted in finish()
our @TEMPORARY_METHODS;

# methods defined by register_plugin_eval_glue(); deleted in finish()
our %TEMPORARY_EVAL_GLUE_METHODS;

###########################################################################

our %common_tags;

BEGIN {
  %common_tags = (

    YESNO => sub {
      my $pms = shift;
      $pms->_get_tag_value_for_yesno(@_);
    },

    YESNOCAPS => sub {
      my $pms = shift;
      uc $pms->_get_tag_value_for_yesno(@_);
    },

    SCORE => sub {
      my $pms = shift;
      $pms->_get_tag_value_for_score(@_);
    },

    HITS => sub {
      my $pms = shift;
      $pms->_get_tag_value_for_score(@_);
    },

    REQD => sub {
      my $pms = shift;
      $pms->_get_tag_value_for_required_score(@_);
    },

    VERSION => \&Mail::SpamAssassin::Version,

    SUBVERSION => sub { $Mail::SpamAssassin::SUB_VERSION },

    RULESVERSION => sub {
      my $pms = shift;
      my $conf = $pms->{conf};
      my @fnames;
      @fnames =
        keys %{$conf->{update_version}}  if $conf->{update_version};
      @fnames = sort @fnames  if @fnames > 1;
      join(',', map($conf->{update_version}{$_}, @fnames));
    },

    HOSTNAME => sub {
      my $pms = shift;
      $pms->{conf}->{report_hostname} ||
        Mail::SpamAssassin::Util::fq_hostname();
    },

    REMOTEHOSTNAME => sub {
      my $pms = shift;
      $pms->{tag_data}->{'REMOTEHOSTNAME'} || "localhost";
    },

    REMOTEHOSTADDR => sub {
      my $pms = shift;
      $pms->{tag_data}->{'REMOTEHOSTADDR'} || "127.0.0.1";
    },

    FIRSTTRUSTEDIP => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_trusted}->[-1];
      $lasthop ? $lasthop->{ip} : '';
    },

    FIRSTTRUSTEDREVIP => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_trusted}->[-1];
      $lasthop ? reverse_ip_address($lasthop->{ip}) : '';
    },

    LASTEXTERNALIP => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_external}->[0];
      $lasthop ? $lasthop->{ip} : '';
    },

    LASTEXTERNALREVIP => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_external}->[0];
      $lasthop ? reverse_ip_address($lasthop->{ip}) : '';
    },

    LASTEXTERNALRDNS => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_external}->[0];
      $lasthop ? $lasthop->{rdns} : '';
    },

    LASTEXTERNALHELO => sub {
      my $pms = shift;
      my $lasthop = $pms->{msg}->{metadata}->{relays_external}->[0];
      $lasthop ? $lasthop->{helo} : '';
    },

    CONTACTADDRESS => sub {
      my $pms = shift;
      $pms->{conf}->{report_contact};
    },

    BAYES => sub {
      my $pms = shift;
      defined $pms->{bayes_score} ? sprintf("%3.4f", $pms->{bayes_score})
                                   : "0.5";
    },

    DATE => sub { Mail::SpamAssassin::Util::time_to_rfc822_date() },

    STARS => sub {
      my $pms = shift;
      my $arg = (shift || "*");
      my $length = int($pms->{score});
      $length = 50 if $length > 50;
      # avoid a perl 5.21 warning: "Negative repeat count does nothing"
      $length > 0 ? $arg x $length : '';
    },

    AUTOLEARN => sub {
      my $pms = shift;
      $pms->get_autolearn_status();
    },

    AUTOLEARNSCORE => sub {
      my $pms = shift;
      $pms->get_autolearn_points();
    },

    TESTS => sub {
      my $pms = shift;
      my $arg = (shift || ',');
      join($arg, sort @{$pms->{test_names_hit}}) || "none";
    },

    SUBTESTS => sub {
      my $pms = shift;
      my $arg = (shift || ',');
      join($arg, sort @{$pms->{subtest_names_hit}}) || "none";
    },

    SUBTESTSCOLLAPSED => sub {
      my $pms = shift;
      my $arg = (shift || ',');
      my (@subtests) = $pms->get_names_of_subtests_hit("collapsed");
      join($arg, sort @subtests) || "none";
    },

    TESTSSCORES => sub {
      my $pms = shift;
      my $arg = (shift || ",");
      my $scores = $pms->{conf}->{scores};
      join($arg, map($_ . "=" . ($scores->{$_} || '0'),
                     sort @{$pms->{test_names_hit}})) || "none";
    },

    PREVIEW => sub {
      my $pms = shift;
      $pms->get_content_preview();
    },

    REPORT => sub {
      my $pms = shift;
      "\n" . ($pms->{tag_data}->{REPORT} || "");
    },

    SUBJPREFIX => sub {
      my $pms = shift;
      ($pms->{tag_data}->{SUBJPREFIX} || "");
    },

    HEADER => sub {
      my $pms = shift;
      my $hdr = shift;
      return '' if !$hdr;
      $pms->get($hdr, '');
    },

    TIMING => sub {
      my $pms = shift;
      $pms->{main}->timer_report();
    },

    ADDEDHEADERHAM => sub {
      my $pms = shift;
      $pms->_get_added_headers('headers_ham');
    },

    ADDEDHEADERSPAM => sub {
      my $pms = shift;
      $pms->_get_added_headers('headers_spam');
    },

    ADDEDHEADER => sub {
      my $pms = shift;
      $pms->_get_added_headers(
                $pms->{is_spam} ? 'headers_spam' : 'headers_ham');
    },

  );
}

my $IP_ADDRESS = IP_ADDRESS;

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg, $opts) = @_;

  my $self = {
    'main'              => $main,
    'msg'               => $msg,
    'score'             => 0,
    'test_log_msgs'     => { }, # deprecated since 4.0, renamed to test_logs to prevent conflicts
    'test_logs'         => { },
    'test_names_hit'    => [ ],
    'subtest_names_hit' => [ ],
    'spamd_result_log_items' => [ ],
    'tests_already_hit' => { },
    'get_cache'         => { },
    'tag_data'          => { },
    'rule_errors'       => 0,
    'disable_auto_learning' => 0,
    'auto_learn_status' => undef,
    'auto_learn_force_status' => undef,
    'conf'              => $main->{conf},
    'async'             => Mail::SpamAssassin::AsyncLoop->new($main),
    'master_deadline'   => $msg->{master_deadline},  # dflt inherited from msg
    'deadline_exceeded' => 0,  # time limit exceeded, skipping further tests
    'tmpfiles'          => { },
    'uri_detail_list'   => { },
    'subjprefix'        => undef,
  };

  dbg("check: pms new, time limit in %.3f s",
      $self->{master_deadline} - time)  if $self->{master_deadline};

  if (defined $opts && $opts->{disable_auto_learning}) {
    $self->{disable_auto_learning} = 1;
  }

  # used with "mass-check --loghits"
  if ($self->{main}->{save_pattern_hits}) {
    $self->{save_pattern_hits} = 1;
    $self->{pattern_hits} = { };
  }

  delete $self->{should_log_rule_hits};
  my $dbgcache = would_log('dbg', 'rules');
  if ($dbgcache || $self->{save_pattern_hits}) {
    $self->{should_log_rule_hits} = 1;
  }

  # known valid tags that might not get their entry in pms->{tag_data}
  # in some circumstances
  my $tag_data_ref = $self->{tag_data};
  foreach (qw(SUMMARY REPORT SUBJPREFIX RBL)) { $tag_data_ref->{$_} = '' }
  foreach (qw(ASN ASNCIDR AWL AWLMEAN AWLCOUNT AWLPRESCORE
              DCCB DCCR EXTRACTTEXTCHARS EXTRACTTEXTWORDS
              EXTRACTTEXTTOOLS EXTRACTTEXTTYPES EXTRACTTEXTEXTENSIONS
              EXTRACTTEXTFLAGS EXTRACTTEXTURIS DCCREP
              PYZOR DKIMIDENTITY DKIMDOMAIN DKIMSELECTOR
              BAYESTC BAYESTCLEARNED BAYESTCSPAMMY BAYESTCHAMMY
              HAMMYTOKENS SPAMMYTOKENS TOKENSUMMARY)) {
    $tag_data_ref->{$_} = undef;  # exist, but undefined
  }

  bless ($self, $class);
  $self;
}

sub DESTROY {
  my ($self) = shift;

  # best practices: prevent potential calls to eval and to system routines
  # in code of a DESTROY method from clobbering global variables $@ and $! 
  local($@,$!);  # keep outer error handling unaffected by DESTROY
  # Bug 5808 - cleanup tmpfiles
  foreach my $fn (keys %{$self->{tmpfiles}}) {
    unlink($fn) or dbg("check: cannot unlink $fn: $!");
  }
}

###########################################################################

=item $status-E<gt>check ()

Runs the SpamAssassin rules against the message pointed to by the object.

=cut

sub check {
  my ($self) = shift;
  my $master_deadline = $self->{master_deadline};
  if (!$master_deadline) {
    $self->check_timed(@_);
  } else {
    my $t = Mail::SpamAssassin::Timeout->new({ deadline => $master_deadline });
    my $err = $t->run(sub { $self->check_timed(@_) });
    if (time > $master_deadline && !$self->{deadline_exceeded}) {
      info("check: exceeded time limit in pms check");
      $self->{deadline_exceeded} = 1;
    }
  }
}

sub check_timed {
  my ($self) = @_;
  local ($_);

  $self->{learned_points} = 0;
  $self->{body_only_points} = 0;
  $self->{head_only_points} = 0;
  $self->{score} = 0;

  # flush any old stale DNS responses
  $self->{main}->{resolver}->flush_responses();

  # clear NetSet cache before every check to prevent it growing too large
  foreach my $nset_name (qw(internal_networks trusted_networks msa_networks)) {
    my $netset = $self->{conf}->{$nset_name};
    $netset->ditch_cache()  if $netset;
  }

  $self->{main}->call_plugins ("check_start", { permsgstatus => $self });

  # in order of slowness; fastest first, slowest last.
  # we do ALL the tests, even if a spam triggers lots of them early on.
  # this lets us see ludicrously spammish mails (score: 40) etc., which
  # we can then immediately submit to spamblocking services.
  #
  # TODO: change this to do welcomelist/blocklists first? probably a plan
  # NOTE: definitely need AWL stuff last, for regression-to-mean of score

  # TVD: we may want to do more than just clearing out the headers, but ...
  $self->{msg}->delete_header('X-Spam-.*');

  # Resident Mail::SpamAssassin code will possibly never change score
  # sets, even if bayes becomes available.  So we should do a quick check
  # to see if we should go from {0,1} to {2,3}.  We of course don't need
  # to do this switch if we're already using bayes ... ;)
  my $set = $self->{conf}->get_score_set();
  if (($set & 2) == 0 && $self->{main}->{bayes_scanner} && $self->{main}->{bayes_scanner}->is_scan_available() && $self->{conf}->{use_bayes_rules}) {
    dbg("check: scoreset $set but bayes is available, switching scoresets");
    $self->{conf}->set_score_set ($set|2);
  }
  dbg("check: using scoreset $set in M:S:Pms"); 
  # The primary check functionality occurs via a plugin call.  For more
  # information, please see: Mail::SpamAssassin::Plugin::Check
  if (!$self->{main}->call_plugins ("check_main", { permsgstatus => $self }))
  {
    # did anything happen?  if not, this is fatal
    if (!$self->{main}->have_plugin("check_main")) {
      die "check: no loaded plugin implements 'check_main': cannot scan!\n".
            "Check that the necessary '.pre' files are in the config directory.\n".
              "At a minimum, v320.pre loads the Check plugin which is required.\n";
    }
  }

  # delete temporary storage and memory allocation used during checking
  $self->delete_fulltext_tmpfile();

  # now that we've finished checking the mail, clear out this cache
  # to avoid unforeseen side-effects.
  $self->{get_cache} = { };

  # Round the score to 3 decimal places to avoid rounding issues
  # We assume required_score to be properly rounded already.
  # add 0 to force it back to numeric representation instead of string.
  $self->{score} = (sprintf "%0.3f", $self->{score}) + 0;

  dbg("check: is spam? score=".$self->{score}.
                        " required=".$self->{conf}->{required_score});
  dbg("check: tests=".$self->get_names_of_tests_hit());
  dbg("check: subtests=".$self->get_names_of_subtests_hit("dbg"));
  $self->{is_spam} = $self->is_spam();

  $self->{main}->{resolver}->bgabort();
  $self->{main}->call_plugins ("check_end", { permsgstatus => $self });

  1;
}

# Called from Check.pm after Plugins check_cleanup calls
# Cleanup and finish things before learning/rewrites etc
# TODO: document?
sub check_cleanup {
  my ($self) = shift;

  # Create subjprefix
  if (defined $self->{subjprefix}) {
    $self->{tag_data}->{SUBJPREFIX} = $self->{subjprefix};
  }

  # Create reports
  $self->{tag_data}->{REPORT} = '';
  $self->{tag_data}->{SUMMARY} = '';
  my $test_logs = $self->{test_logs};
  my $scores = $self->{conf}->{scores};
  foreach my $rule (@{$self->{test_names_hit}}) {
    my $score = $scores->{$rule};
    my $area = $test_logs->{$rule}->{area} || '';
    my $desc = $test_logs->{$rule}->{desc} || '';

    if ($score >= 10 || $score <= -10) {
      $score = sprintf("%4.0f", $score);
    } else {
      $score = sprintf("%4.1f", $score);
    }

    my $terse = '';
    my $long = '';
    if (defined $test_logs->{$rule}->{msg}) {
      my @msgs;
      if (($self->{conf}->{tflags}->{$rule}||'') =~ /\bnolog\b/) {
        push(@msgs, '*REDACTED*');
      } else {
        @msgs = @{$test_logs->{$rule}->{msg}};
      }
      local $1;
      foreach my $msg (@msgs) {
        while ($msg =~ s/^(.{30,48})\s//) {
          $terse .= sprintf ("[%s]\n", $1);
          if (length($1) > 47) {
            $long .= sprintf ("%78s\n", "[$1]");
          } else {
            $long .= sprintf ("%27s [%s]\n", "", $1);
          }
        }
        $terse .= sprintf ("[%s]\n", $msg);
        if (length($msg) > 47) {
          $long .= sprintf ("%78s\n", "[$msg]");
        } else {
          $long .= sprintf ("%27s [%s]\n", "", $msg);
        }
      }
    }

    $self->{tag_data}->{REPORT} .= sprintf ("* %s %s %s%s\n%s",
        $score, $rule, $area,
        $self->_wrap_desc($desc,
            4+length($rule)+length($score)+length($area), "*      "),
        ($terse ? "*      " . $terse : ''));

    $self->{tag_data}->{SUMMARY} .= sprintf ("%s %-22s %s%s\n%s",
        $score, $rule, $area,
        $self->_wrap_desc($desc,
            3+length($rule)+length($score)+length($area), " " x 28),
        $long);
  }
}

###########################################################################

=item $status-E<gt>learn()

After a mail message has been checked, this method can be called.  If the score
is outside a certain range around the threshold, ie. if the message is judged
more-or-less definitely spam or definitely non-spam, it will be fed into
SpamAssassin's learning systems (currently the naive Bayesian classifier),
so that future similar mails will be caught.

=cut

sub learn {
  my ($self) = shift;
  my $master_deadline = $self->{master_deadline};
  if (!$master_deadline) {
    $self->learn_timed(@_);
  } else {
    my $t = Mail::SpamAssassin::Timeout->new({ deadline => $master_deadline });
    my $err = $t->run(sub { $self->learn_timed(@_) });
    if (time > $master_deadline && !$self->{deadline_exceeded}) {
      info("learn: exceeded time limit in pms learn");
      $self->{deadline_exceeded} = 1;
    }
  }
}

sub learn_timed {
  my ($self) = @_;

  if (!$self->{conf}->{bayes_auto_learn} ||
      !$self->{conf}->{use_bayes} ||
      $self->{disable_auto_learning})
  {
    $self->{auto_learn_status} = "disabled";
    return;
  }

  my ($isspam, $force_autolearn, $force_autolearn_names, $arrayref);
  $arrayref = $self->{main}->call_plugins ("autolearn_discriminator", {
      permsgstatus => $self
    });

  $isspam = $arrayref->[0];
  $force_autolearn = $arrayref->[1];
  $force_autolearn_names = $arrayref->[2];

  #AUTOLEARN_FORCE FLAG INFORMATION
  if (defined $force_autolearn and $force_autolearn > 0) {
    $self->{auto_learn_force_status} = "yes";
    if (defined $force_autolearn_names) {
      $self->{auto_learn_force_status} .= " ($force_autolearn_names)";
     }
  } else {
    $self->{auto_learn_force_status} = "no";
  }

  if (!defined $isspam) {
    $self->{auto_learn_status} = 'no';
    return;
  }


  my $timer = $self->{main}->time_method("learn");

  $self->{main}->call_plugins ("autolearn", {
      permsgstatus => $self,
      isspam => $isspam
    });

  # bug 3704: temporarily override learn's ability to re-learn a message
  my $orig_learner = $self->{main}->init_learner({ "no_relearn" => 1 });

  my $eval_stat;
  eval {
    my $learnstatus = $self->{main}->learn ($self->{msg}, undef, $isspam, 0);
    if ($learnstatus->did_learn()) {
      $self->{auto_learn_status} = $isspam ? "spam" : "ham";
    }
    # This must wait until the did_learn call.
    $learnstatus->finish();
    $self->{main}->finish_learner();        # for now

    if (exists $self->{main}->{bayes_scanner}) {
      $self->{main}->{bayes_scanner}->force_close();
    }
    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  };

  # reset learner options to their original values
  $self->{main}->init_learner($orig_learner);

  if (defined $eval_stat) {
    dbg("learn: auto-learning failed: $eval_stat");
    $self->{auto_learn_status} = "failed";
  }
}

=item $score = $status-E<gt>get_autolearn_points()

Return the message's score as computed for auto-learning.  Certain tests are
ignored:

  - rules with tflags set to 'learn' (the Bayesian rules)

  - rules with tflags set to 'userconf' (user welcome/block-listing rules, etc)

  - rules with tflags set to 'noautolearn'

Also note that auto-learning occurs using scores from either scoreset 0 or 1,
depending on what scoreset is used during message check.  It is likely that the
message check and auto-learn scores will be different.

=cut

sub get_autolearn_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{autolearn_points};
}

=item $score = $status-E<gt>get_head_only_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for header-based ones.

=cut

sub get_head_only_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{head_only_points};
}

=item $score = $status-E<gt>get_learned_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for learning-based ones.

=cut

sub get_learned_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{learned_points};
}

=item $score = $status-E<gt>get_body_only_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for body-based ones.

=cut

sub get_body_only_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{body_only_points};
}

=item $score = $status-E<gt>get_autolearn_force_status()

Return whether a message's score included any rules that are flagged as
autolearn_force.

=cut

sub get_autolearn_force_status {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{autolearn_force};
}

=item $rule_names = $status-E<gt>get_autolearn_force_names()

Return a list of comma separated list of rule names if a message's
score included any rules that are flagged as autolearn_force.

=cut

sub get_autolearn_force_names {
  my ($self) = @_;
  my ($names);

  $self->_get_autolearn_points();
  $names = $self->{autolearn_force_names};

  if (defined $names) {
    #remove trailing comma
    $names =~ s/,$//;
  } else {
    $names = "";
  }

  return $names;
}

sub _get_autolearn_testtype {
  my ($self, $test) = @_;
  return '' unless defined $test;
  return 'head' if $test == $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS
                || $test == $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS;
  return 'body' if $test == $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS
                || $test == $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS
                || $test == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS
                || $test == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS
                || $test == $Mail::SpamAssassin::Conf::TYPE_URI_TESTS
                || $test == $Mail::SpamAssassin::Conf::TYPE_URI_EVALS;
  return 'meta' if $test == $Mail::SpamAssassin::Conf::TYPE_META_TESTS;
  return '';
}

sub _get_autolearn_points {
  my ($self) = @_;

  return if (exists $self->{autolearn_points});
  # ensure it only gets computed once, even if we return early
  $self->{autolearn_points} = 0;

  my $conf = $self->{conf};

  # This function needs to use use sum($score[scoreset % 2]) not just {score}.
  # otherwise we shift what we autolearn on and it gets really weird.  - tvd
  my $orig_scoreset = $conf->get_score_set();
  my $new_scoreset = $orig_scoreset;
  my $scores = $conf->{scores};

  if (($orig_scoreset & 2) == 0) { # we don't need to recompute
    dbg("learn: auto-learn: currently using scoreset $orig_scoreset");
  }
  else {
    $new_scoreset = $orig_scoreset & ~2;
    dbg("learn: auto-learn: currently using scoreset $orig_scoreset, recomputing score based on scoreset $new_scoreset");
    $scores = $conf->{scoreset}->[$new_scoreset];
  }

  my $tflags = $conf->{tflags};
  my $points = 0;

  # Just in case this function is called multiple times, clear out the
  # previous calculated values
  $self->{learned_points} = 0;
  $self->{body_only_points} = 0;
  $self->{head_only_points} = 0;
  $self->{autolearn_force} = 0;

  foreach my $test (@{$self->{test_names_hit}}) {
    my $force_type = '';
    # According to the documentation, noautolearn, userconf, and learn
    # rules are ignored for autolearning.
    if (exists $tflags->{$test}) {
      next if $tflags->{$test} =~ /\bnoautolearn\b/;
      next if $tflags->{$test} =~ /\buserconf\b/;

      # Keep track of the learn points for an additional autolearn check.
      # Use the original scoreset since it'll be 0 in sets 0 and 1.
      if ($tflags->{$test} =~ /\blearn\b/) {
	# we're guaranteed that the score will be defined
        $self->{learned_points} += $conf->{scoreset}->[$orig_scoreset]->{$test};
	next;
      }

      #IF ANY RULES ARE AUTOLEARN FORCE, SET THAT FLAG
      if ($tflags->{$test} =~ /\bautolearn_force\b/) {
        $self->{autolearn_force}++;
        #ADD RULE NAME TO LIST
        $self->{autolearn_force_names}.="$test,";
      }

      # Bug 7907
      local $1;
      if ($tflags->{$test} =~ /\bautolearn_(body|header)\b/) {
        $force_type = $1;
      }
    }

    # ignore tests with 0 score (or undefined) in this scoreset
    next if !$scores->{$test};

    # Go ahead and add points to the proper locations
    # Changed logic because in testing, I was getting both head and body. Bug 5503
    # Cleanup logic, Bug 7905/7906
    my $type = $self->_get_autolearn_testtype($conf->{test_types}->{$test});
    if ($force_type eq 'header' || ($force_type eq '' && $type eq 'head')) {
      $self->{head_only_points} += $scores->{$test};
      dbg("learn: auto-learn: adding header points $scores->{$test} ($test)");
    }
    elsif ($force_type eq 'body' || ($force_type eq '' && $type eq 'body')) {
      $self->{body_only_points} += $scores->{$test};
      dbg("learn: auto-learn: adding body points $scores->{$test} ($test)");
    }
    elsif ($type eq 'meta') {
      if ($conf->{meta_dependencies}->{$test}) {
        my $dep_head = 0;
        my $dep_body = 0;
        foreach my $deptest (@{$conf->{meta_dependencies}->{$test}}) {
          my $deptype = $self->_get_autolearn_testtype($conf->{test_types}->{$deptest});
          if ($deptype eq 'head') { $dep_head++; }
          elsif ($deptype eq 'body') { $dep_body++; }
        }
        if ($dep_head || $dep_body) {
          my $dep_total = $dep_head + $dep_body;
          my $p_head = sprintf "%0.3f", $scores->{$test} * ($dep_head / $dep_total);
          my $p_body = sprintf "%0.3f", $scores->{$test} * ($dep_body / $dep_total);
          $self->{head_only_points} += $p_head;
          $self->{body_only_points} += $p_body;
          dbg("learn: auto-learn: adding $p_head header and $p_body body points, $dep_head/$dep_body ratio ($test)");
        } else {
          dbg("learn: auto-learn: not considered as header or body points, no header/body deps ($test)");
        }
      } else {
          dbg("learn: auto-learn: not considered as header or body points, no meta deps ($test)");
      }
    }
    else {
      dbg("learn: auto-learn: not considered as header or body points, ignored ruletype ($test)");
    }

    $points += $scores->{$test};
  }

  # Figure out the final value we'll use for autolearning
  $points = (sprintf "%0.3f", $points) + 0;
  dbg("learn: auto-learn: message score: ".$self->{score}.", computed score for autolearn: $points");

  $self->{autolearn_points} = $points;
}

###########################################################################

=item $isspam = $status-E<gt>is_spam ()

After a mail message has been checked, this method can be called.  It will
return 1 for mail determined likely to be spam, 0 if it does not seem
spam-like.

=cut

sub is_spam {
  my ($self) = @_;
  # changed to test this so sub-tests can ask "is_spam" during a run
  return ($self->{score} >= $self->{conf}->{required_score});
}

###########################################################################

=item $list = $status-E<gt>get_names_of_tests_hit ()

After a mail message has been checked, this method can be called. It will
return a comma-separated string, listing all the symbolic test names
of the tests which were triggered by the mail.

=cut

sub get_names_of_tests_hit {
  my ($self) = @_;

  return join(',', sort @{$self->{test_names_hit}});
}

=item $list = $status-E<gt>get_names_of_tests_hit_with_scores_hash ()

After a mail message has been checked, this method can be called. It will
return a pointer to a hash for rule & score pairs for all the symbolic
test names and individual scores of the tests which were triggered by the mail.

=cut

sub get_names_of_tests_hit_with_scores_hash {
  my ($self) = @_;

  #BASED ON CODE FOR TESTSSCORES TAG
  my $scores = $self->{conf}->{scores};
  my %testsscores;
  $testsscores{$_} = $scores->{$_} || '0'  for @{$self->{test_names_hit}};
  return \%testsscores;
}

=item $list = $status-E<gt>get_names_of_tests_hit_with_scores ()

After a mail message has been checked, this method can be called. It will
return a comma-separated string of rule=score pairs for all the symbolic
test names and individual scores of the tests which were triggered by the mail.

=cut

sub get_names_of_tests_hit_with_scores {
  my ($self) = @_;

  #BASED ON CODE FOR TESTSSCORES TAG
  my $scores = $self->{conf}->{scores};
  return join(',', map($_ . '=' . ($scores->{$_} || '0'),
                       sort @{$self->{test_names_hit}})) || "none";
}


###########################################################################

=item $list = $status-E<gt>get_names_of_subtests_hit ()

After a mail message has been checked, this method can be called.  It will
return a comma-separated string, listing all the symbolic test names of the
meta-rule sub-tests which were triggered by the mail.  Sub-tests are the
normally-hidden rules, which score 0 and have names beginning with two
underscores, used in meta rules.

If a parameter of collapsed or dbg is passed, the output will be a condensed 
array of sub-tests with multiple hits reduced to one entry.  

If the parameter of dbg is passed, the output will be a condensed string of
sub-tests with multiple hits reduced to one entry with the number of hits 
in parentheses. Some information is also added at the end regarding the 
multiple hits.

=cut

sub get_names_of_subtests_hit {
  my ($self, $mode) = @_;

  if (defined $mode && ($mode eq 'dbg' || $mode eq 'collapsed')) {
    # This routine prints only one instance of a subrule hit with a count of how many times it hit if greater than 1
    my $total_hits = scalar(@{$self->{subtest_names_hit}});
    return '' if !$total_hits;

    my %subtest_names_hit;
    $subtest_names_hit{$_}++ foreach @{$self->{subtest_names_hit}};

    my @subtests = sort keys %subtest_names_hit;
    my $deduplicated_hits = scalar(@subtests);

    my @result;
    foreach my $rule (@subtests) {
      if ($subtest_names_hit{$rule} > 1) {
        push @result, "$rule($subtest_names_hit{$rule})";
      } else {
        push @result, $rule;
      }
    }

    if ($mode eq 'dbg') {
      return join(',', @result)." (Total Subtest Hits: $total_hits / Deduplicated Total Hits: $deduplicated_hits)";
    } else {
      return join(',', @result);
    }
  } else {
    # Return the simpler string with duplicates and commas
    return join(',', sort @{$self->{subtest_names_hit}});
  }
}

###########################################################################

=item $num = $status-E<gt>get_score ()

After a mail message has been checked, this method can be called.  It will
return the message's score.

=cut

sub get_score {
  my ($self) = @_;
  return $self->{score};
}

# left as backward compatibility
sub get_hits {
  my ($self) = @_;
  return $self->{score};
}

###########################################################################

=item $num = $status-E<gt>get_required_score ()

After a mail message has been checked, this method can be called.  It will
return the score required for a mail to be considered spam.

=cut

sub get_required_score {
  my ($self) = @_;
  return $self->{conf}->{required_score};
}

# left as backward compatibility
sub get_required_hits {
  my ($self) = @_;
  return $self->{conf}->{required_score};
}

###########################################################################

=item $num = $status-E<gt>get_autolearn_status ()

After a mail message has been checked, this method can be called.  It will
return one of the following strings depending on whether the mail was
auto-learned or not: "ham", "no", "spam", "disabled", "failed", "unavailable".

It also returns is flagged with auto_learn_force, it will also include the status
and the rules hit.  For example: "autolearn_force=yes (AUTOLEARNTEST_BODY)"

=cut

sub get_autolearn_status {
  my ($self) = @_;
  my ($status) = $self->{auto_learn_status} || "unavailable";

  if (defined $self->{auto_learn_force_status}) {
    $status .= " autolearn_force=".$self->{auto_learn_force_status};
  }

  return $status;
}

###########################################################################

=item $report = $status-E<gt>get_report ()

Deliver a "spam report" on the checked mail message.  This contains details of
how many spam detection rules it triggered.

The report is returned as a multi-line string, with the lines separated by
C<\n> characters.

=cut

sub get_report {
  my ($self) = @_;

  if (!exists $self->{'report'}) {
    my $report;

    my $timer = $self->{main}->time_method("get_report");
    $report = $self->{conf}->{report_template};
    $report ||= '(no report template found)';

    $report = $self->_replace_tags($report);

    $report =~ s/\n*$/\n\n/s;
    $self->{report} = $report;
  }

  return $self->{report};
}

###########################################################################

=item $preview = $status-E<gt>get_content_preview ()

Give a "preview" of the content.

This is returned as a multi-line string, with the lines separated by C<\n>
characters, containing a fully-decoded, safe, plain-text sample of the first
few lines of the message body.

=cut

sub get_content_preview {
  my ($self) = @_;

  my $str = '';
  my @ary = @{$self->get_decoded_stripped_body_text_array()};
  shift @ary;                # drop the subject line

  my $numlines = 3;
  while (length ($str) < 200 && @ary && $numlines-- > 0) {
    $str .= shift @ary;
  }

  # in case the last line was huge, trim it back to around 200 chars
  local $1;
  $str =~ s/^(.{200}).+$/$1 [...]/gm;
  chomp ($str); $str .= "\n";

  # now, some tidy-ups that make things look a bit prettier
  $str =~ s/-----Original Message-----.*$//gm;
  $str =~ s/This is a multi-part message in MIME format\.//gs;
  $str =~ s/[-_*.]{10,}//gs;
  $str =~ s/\s+/ /gs;

  # add "Content preview:" ourselves, so that the text aligns
  # correctly with the template -- then trim it off.  We don't
  # have to get this *exactly* right, but it's nicer if we
  # make a bit of an effort ;)
  $str = Mail::SpamAssassin::Util::wrap($str, "  ", "Content preview:  ", 75, 1);
  $str =~ s/^Content preview:\s+//gs;

  return $str;
}

###########################################################################

=item $msg = $status-E<gt>get_message()

Return the object representing the message being scanned.

=cut

sub get_message {
  my ($self) = @_;
  return $self->{msg};
}

###########################################################################

=item $status-E<gt>rewrite_mail ()

Rewrite the mail message.  This will at minimum add headers, and at
maximum MIME-encapsulate the message text, to reflect its spam or not-spam
status.  The function will return a scalar of the rewritten message.

The actual modifications depend on the configuration (see
C<Mail::SpamAssassin::Conf> for more information).

The possible modifications are as follows:

=over 4

=item To:, From: and Subject: modification on spam mails

Depending on the configuration, the To: and From: lines can have a
user-defined RFC 2822 comment appended for spam mail. The subject line
may have a user-defined string prepended to it for spam mail.

=item X-Spam-* headers for all mails

Depending on the configuration, zero or more headers with names
beginning with C<X-Spam-> will be added to mail depending on whether
it is spam or ham.

=item spam message with report_safe

If report_safe is set to true (1), then spam messages are encapsulated
into their own message/rfc822 MIME attachment without any modifications
being made.

If report_safe is set to false (0), then the message will only have the
above headers added/modified.

=back

=cut

sub rewrite_mail {
  my ($self) = @_;

  my $timer = $self->{main}->time_method("rewrite_mail");
  my $msg = $self->{msg}->get_mbox_separator() || '';

  if ($self->{is_spam} && $self->{conf}->{report_safe}) {
    $msg .= $self->rewrite_report_safe();
  }
  else {
    $msg .= $self->rewrite_no_report_safe();
  }

  return $msg;
}

# Make the line endings in the passed string reference appropriate
# for the original mail.   Callers must note bug 5250: don't rewrite
# the message body, since that will corrupt 8bit attachments/MIME parts.
#
sub _fixup_report_line_endings {
  my ($self, $strref) = @_;
  if ($self->{msg}->{line_ending} ne "\n") {
    $$strref =~ s/\r?\n/$self->{msg}->{line_ending}/gs;
  }
}

sub _get_added_headers {
  my ($self, $which) = @_;
  my $str = '';
  # use string appends to put this back together -- I finally benchmarked it.
  # join() is 56% of the speed of just using string appends. ;)
  foreach my $hf_ref (@{$self->{conf}->{$which}}) {
    my($hfname, $hfbody) = @$hf_ref;
    my $line = $self->_process_header($hfname,$hfbody);
    $line = $self->mime_encode_header($line);
    $str .= "X-Spam-$hfname: $line\n";
  }
  return $str;
};

# rewrite the message in report_safe mode
# should not be called directly, use rewrite_mail instead
#
sub rewrite_report_safe {
  my ($self) = @_;

  my $tag;

  # This is the original message.  We do not want to make any modifications so
  # we may recover it if necessary.  It will be put into the new message as a
  # message/rfc822 MIME part.
  my $original = $self->{msg}->get_pristine();

  # This is the new message.
  my $newmsg = '';

  # the character set of a report
  my $report_charset = $self->{conf}->{report_charset} || "UTF-8";

  # the SpamAssassin report
  my $report = $self->get_report();

  if (!utf8::is_utf8($report)) {
    # already in octets
  } else {
    # encode to octets
    if (uc $report_charset eq 'UTF-8') {
      dbg("check: encoding report to $report_charset");
      utf8::encode($report);  # very fast
    } else {
      dbg("check: encoding report to $report_charset. Slow, to be avoided!");
      $report = Encode::encode($report_charset, $report);  # slow
    }
  }

  # get original headers, "pristine" if we can do it
  my $from = $self->{msg}->get_pristine_header("From");
  my $to = $self->{msg}->get_pristine_header("To");
  my $cc = $self->{msg}->get_pristine_header("Cc");
  my $subject = $self->{msg}->get_pristine_header("Subject");
  my $msgid = $self->{msg}->get_pristine_header('Message-Id');
  my $date = $self->{msg}->get_pristine_header("Date");

  # It'd be nice to do this with a foreach loop, but with only three
  # possibilities right now, it's easier not to...

  if (defined $self->{conf}->{rewrite_header}->{Subject}) {
    # Add a prefix to the subject if needed
    $subject = "\n" if !defined $subject;
    if (defined $self->{subjprefix}) {
      $tag = $self->_replace_tags($self->{subjprefix});
      $tag =~ s/\n/ /gs;
      $subject = $tag . $subject;
    }
    # Add a **SPAM** prefix
    $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{Subject});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $subject =~ s/^(?:\Q${tag}\E )?/${tag} /g; # For some reason the tag may already be there!?
  }

  if (defined $self->{conf}->{rewrite_header}->{To}) {
    $to = "\n" if !defined $to;
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{To});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $to =~ s/(?:\t\Q(${tag})\E)?$/\t(${tag})/;
  }

  if (defined $self->{conf}->{rewrite_header}->{From}) {
    $from = "\n" if !defined $from;
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{From});
    $tag =~ s/\n+//gs; # strip tag's newlines
    $from =~ s/(?:\t\Q(${tag})\E)?$/\t(${tag})/;
  }

  # add report headers to message
  $newmsg .= "From: $from" if defined $from;
  $newmsg .= "To: $to" if defined $to;
  $newmsg .= "Cc: $cc" if defined $cc;
  $newmsg .= "Subject: $subject" if defined $subject;
  $newmsg .= "Date: $date" if defined $date;
  $newmsg .= "Message-Id: $msgid" if defined $msgid;
  $newmsg .= $self->_get_added_headers('headers_spam');

  if (defined $self->{conf}->{report_safe_copy_headers}) {
    my %already_added = map { $_ => 1 } qw/from to cc subject date message-id/;

    foreach my $hdr (@{$self->{conf}->{report_safe_copy_headers}}) {
      next if exists $already_added{lc $hdr};
      my @hdrtext = $self->{msg}->get_pristine_header($hdr);
      $already_added{lc $hdr}++;

      if (lc $hdr eq "received") { # add Received at the top ...
          my $rhdr = "";
          foreach (@hdrtext) {
            $rhdr .= "$hdr: $_";
          }
          $newmsg = "$rhdr$newmsg";
      }
      else {
        foreach (@hdrtext) {
          $newmsg .= "$hdr: $_";
        }
      }
    }
  }

  # jm: add a SpamAssassin Received header to note markup time etc.
  # emulates the fetchmail style.
  # tvd: do this after report_safe_copy_headers so Received will be done correctly
  $newmsg = "Received: from localhost by " .
              Mail::SpamAssassin::Util::fq_hostname() . "\n" .
            "\twith SpamAssassin (version " .
              Mail::SpamAssassin::Version() . ");\n" .
            "\t" . Mail::SpamAssassin::Util::time_to_rfc822_date() . "\n" .
            $newmsg;

  # MIME boundary
  my $boundary = "----------=_" . sprintf("%08X.%08X",time,int(rand(2 ** 32)));

  # ensure it's unique, so we can't be attacked this way
  while ($original =~ /^\Q${boundary}\E(?:--)?$/m) {
    $boundary .= "/".sprintf("%08X",int(rand(2 ** 32)));
  }

  # determine whether Content-Disposition should be "attachment" or "inline"
  my $disposition;
  my $ct = $self->{msg}->get_header("Content-Type");
  if (defined $ct && $ct ne '' && $ct !~ m{text/plain}i) {
    $disposition = "attachment";
    $report .= $self->_replace_tags($self->{conf}->{unsafe_report_template});
    # if we wanted to defang the attachment, this would be the place
  }
  else {
    $disposition = "inline";
  }

  my $type = "message/rfc822";
  $type = "text/plain" if $self->{conf}->{report_safe} > 1;

  my $description = $self->{conf}->{'encapsulated_content_description'};

  # Note: the message should end in blank line since mbox format wants
  # blank line at end and messages may be concatenated!  In addition, the
  # x-spam-type parameter is fixed since we will use it later to recognize
  # original messages that can be extracted.
  $newmsg .= <<"EOM";
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="$boundary"

This is a multi-part message in MIME format.

--$boundary
Content-Type: text/plain; charset=$report_charset
Content-Disposition: inline
Content-Transfer-Encoding: 8bit

$report

--$boundary
Content-Type: $type; x-spam-type=original
Content-Description: $description
Content-Disposition: $disposition
Content-Transfer-Encoding: 8bit

EOM

  my $newmsgtrailer = "\n--$boundary--\n\n";

  # now fix line endings in both headers, report_safe body parts,
  # and new MIME boundaries and structure
  $self->_fixup_report_line_endings(\$newmsg);
  $self->_fixup_report_line_endings(\$newmsgtrailer);
  $newmsg .= $original.$newmsgtrailer;

  return $newmsg;
}

# rewrite the message in non-report_safe mode (just headers)
# should not be called directly, use rewrite_mail instead
#
sub rewrite_no_report_safe {
  my ($self) = @_;

  my $ntag;
  my $pref_subject = 0;

  # put the pristine headers into an array
  # skip the X-Spam- headers, but allow the X-Spam-Prev headers to remain.
  # since there may be a missing header/body
  #
  my @pristine_headers = split(/^/m, $self->{msg}->get_pristine_header());
  for (my $line = 0; $line <= $#pristine_headers; $line++) {
    next unless ($pristine_headers[$line] =~ /^X-Spam-(?!Prev-)/i);
    splice @pristine_headers, $line, 1 while ($pristine_headers[$line] =~ /^(?:X-Spam-(?!Prev-)|[ \t])/i);
    $line--;
  }
  my $separator = '';
  if (@pristine_headers && $pristine_headers[$#pristine_headers] =~ /^\s*$/) {
    $separator = pop @pristine_headers;
  }

  my $addition = 'headers_ham';

  if($self->{is_spam})
  {
      # special-case: Subject lines.  ensure one exists, if we're
      # supposed to mark it up.
      my $created_subject = 0;
      my $subject = $self->{msg}->get_pristine_header('Subject');
      if (!defined($subject) && $self->{is_spam}
            && exists $self->{conf}->{rewrite_header}->{'Subject'})
      {
        push(@pristine_headers, "Subject: \n");
        $created_subject = 1;
      }

      # Deal with header rewriting
      foreach (@pristine_headers) {
        # if we're not going to do a rewrite, skip this header!
        next if (!/^(From|Subject|To):/i);
	my $hdr = ucfirst(lc($1));
	next if (!defined $self->{conf}->{rewrite_header}->{$hdr});

	# pop the original version onto the end of the header array
        if ($created_subject) {
          push(@pristine_headers, "X-Spam-Prev-Subject: (nonexistent)\n");
        } else {
          push(@pristine_headers, "X-Spam-Prev-$_");
        }

	# Figure out the rewrite piece
        my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{$hdr});
        $tag =~ s/\n/ /gs;

	# The tag should be a comment for this header ...
	$tag = "($tag)" if ($hdr =~ /^(?:From|To)$/);

	if (defined $self->{subjprefix}) {
	  $ntag = $self->_replace_tags($self->{subjprefix});
	  $ntag =~ s/\n/ /gs;
	  $ntag =~ s/\s+$//;
	  local $1;
	  s/^([^:]+:)[ \t]*(?:\Q${ntag}\E )?/$1 ${ntag} /i;
	}
	s/^([^:]+:)[ \t]*(?:\Q${tag}\E )?/$1 ${tag} /i;
      }

      $addition = 'headers_spam';
  } else {
      # special-case: Subject lines.  ensure one exists, if we're
      # supposed to mark it up.
      my $created_subject = 0;
      my $subject = $self->{msg}->get_pristine_header('Subject');
      if (!defined($subject)
            && exists $self->{conf}->{rewrite_header}->{'Subject'})
      {
        push(@pristine_headers, "Subject: \n");
        $created_subject = 1;
      }

      # Deal with header rewriting
      foreach (@pristine_headers) {
        # if we're not going to do a rewrite, skip this header!
        next if (!/^(Subject):/i);
	my $hdr = ucfirst(lc($1));
	next if (!defined $self->{conf}->{rewrite_header}->{$hdr});

        if (defined $self->{subjprefix}) {
          $ntag = $self->_replace_tags($self->{subjprefix});
          $ntag =~ s/\n/ /gs;
          $ntag =~ s/\s+$//;
          local $1;
          s/^([^:]+:)[ \t]*(?:\Q${ntag}\E )?/$1 ${ntag} /i;
        }
      }
  }

  # Break the pristine header set into two blocks; $new_hdrs_pre is the stuff
  # that we want to ensure comes before any SpamAssassin markup headers,
  # like the Return-Path header (see bug 3409).
  #
  # all the rest of the message headers (as left in @pristine_headers), is
  # to be placed after the SpamAssassin markup hdrs. Once one of those headers
  # is seen, all further headers go into that set; it's assumed that it's an
  # old copy of the header, or attempted spoofing, if it crops up halfway
  # through the headers.

  my $new_hdrs_pre = '';
  if (@pristine_headers && $pristine_headers[0] =~ /^Return-Path:/i) {
    $new_hdrs_pre .= shift(@pristine_headers);
    while (@pristine_headers && $pristine_headers[0] =~ /^[ \t]/) {
      $new_hdrs_pre .= shift(@pristine_headers);
    }
  }
  $new_hdrs_pre .= $self->_get_added_headers($addition);

  # fix up line endings appropriately
  my $newmsg = $new_hdrs_pre . join('',@pristine_headers) . $separator;
  $self->_fixup_report_line_endings(\$newmsg);

  return $newmsg.$self->{msg}->get_pristine_body();
}

# encode a header field body into ASCII as per RFC 2047
#
sub mime_encode_header {
  my ($self, $text) = @_;

  utf8::encode($text)  if utf8::is_utf8($text);

  my $result = '';
  for my $line (split(/^/, $text)) {

    if ($line =~ /^[\x09\x20-\x7E]*\r?\n\z/s) {
      $result .= $line;  # no need for encoding

    } else {
      my $prefix = '';
      my $suffix = '';

      local $1;
      if ($line =~ s/( (?: ^ | [ \t] ) [\x09\x20-\x7E]* (?: \r?\n )? ) \z//xs) {
        $suffix = $1;
      } elsif ($line =~ s/(\r?\n)\z//s) {
        $suffix = $1;
      }

      if ($line =~ s/^ ( [\x09\x20-\x7E]* (?: [ \t] | \z ) )//xs) {
        $prefix = $1;
      }

      if ($line eq '') {
        $result .= $prefix . $suffix;
      } else {
        my $qp_enc_count = $line =~ tr/=?_\x00-\x1F\x7F-\xFF//;
        if (length($line) + $qp_enc_count*2 <= 4 * int(length($line)+2)/3) {
          # RFC 2047: Upper case should be used for hex digits A through F
          $line =~ s{ ( [=?_\x00-\x20\x7F-\xFF] ) }
                    { $1 eq ' ' ? '_' : sprintf("=%02X", ord $1) }xges;
          $result .= $prefix . '=?UTF-8?Q?' . $line;
        } else {
          $result .= $prefix . '=?UTF-8?B?' . base64_encode($line);
        }
        $result .= '?=' . $suffix;
      }
    }
  }

  dbg("markup: mime_encode_header: %s", $result);
  return $result;
}

sub _process_header {
  my ($self, $hdr_name, $hdr_data) = @_;

  $hdr_data = $self->_replace_tags($hdr_data);  # as octets
  $hdr_data =~ s/(?:\r?\n)+$//; # make sure there are no trailing newlines ...

  if ($self->{conf}->{fold_headers}) {
    if ($hdr_data =~ /\n/) {
      $hdr_data =~ s/\s*\n\s*/\n\t/g;
      return $hdr_data;
    }
    else {
      # use '!!' instead of ': ' so it doesn't wrap on the space
      my $hdr = "X-Spam-$hdr_name!!$hdr_data";
      $hdr = Mail::SpamAssassin::Util::wrap($hdr, "\t", "", 79, 0, '(?<=[\s,])');
      # make sure there are no blank lines in headers
      # buggy wrap might not prefix blank lines with \t, so use \s* (bug 7672)
      $hdr =~ s/^\s*\n//gm;
      return (split (/!!/, $hdr, 2))[1]; # just return the data part
    }
  }
  else {
    $hdr_data =~ s/\n/ /g; # Can't have newlines in headers, unless folded
    return $hdr_data;
  }
}

sub _replace_tags {
  my $self = shift;
  my $text = shift;

  # default to leaving the original string in place, if we cannot find
  # a tag for it (bug 4793)
  local($1);
  $text =~ s{_([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*(?:\(.*?\))?)_}{
        my $tag = $1;
        my $result;
        if ($tag =~ /^ADDEDHEADER(?:HAM|SPAM|)\z/) {
          # Bug 6278: break infinite recursion through _get_added_headers and
          # _get_tag on an attempt to use such tag in add_header template
        } else {
          $result = $self->get_tag_raw($tag);
          if (!ref $result) {
            utf8::encode($result) if utf8::is_utf8($result);
          } elsif (ref $result eq 'ARRAY') {
            my @values = @$result;  # avoid modifying referenced array
            for (@values) { utf8::encode($_) if utf8::is_utf8($_) }
            $result = join(' ', @values);
          }
        }
        defined $result ? $result : "_${tag}_";
      }ge;

  return $text;
}

###########################################################################

# public API for plugins

=item $status-E<gt>action_depends_on_tags($tags, $code, @args)

Enqueue the supplied subroutine reference C<$code>, to become runnable when
all the specified tags become available. The C<$tags> may be a simple
scalar - a tag name, or a listref of tag names. The subroutine C<&$code>
when called will be passed a C<permessagestatus> object as its first argument,
followed by the supplied (optional) list C<@args> .

=cut

sub action_depends_on_tags {
  my($self, $tags, $code, @args) = @_;

  ref $code eq 'CODE'
    or die "action_depends_on_tags: argument must be a subroutine ref";

  # tag names on which the given action depends
  my @dep_tags = !ref $tags ? $tags : @$tags;

  # uppercase tag, but not args, f.e. HEADER(foo)
  local($1,$2);
  foreach (@dep_tags) {
    if (/^ ([^\(]+) (\(.*)? $/x) {
      $_ = uc($1).(defined $2 ? $2 : '');
    }
  }

  # list dependency tag names which are not already satisfied
  my @blocking_tags;
  foreach (@dep_tags) {
    my $data = $self->get_tag($_);
    if (!defined $data || $data eq '') {
      push @blocking_tags, $_;
    }
  }

  if (!@blocking_tags) {
    dbg("check: tagrun - tag %s was ready, runnable immediately: %s",
        join(', ',@dep_tags), join(', ',$code,@args));
    &$code($self, @args);
  } else {
    # @{$self->{tagrun_subs}}            list of all submitted subroutines
    # @{$self->{tagrun_actions}{$tag}}   bitmask of action indices blocked by tag
    # $self->{tagrun_tagscnt}[$action_ind]  count of tags still pending

    # store action details, obtain its index
    push(@{$self->{tagrun_subs}}, [$code,@args]);
    my $action_ind = $#{$self->{tagrun_subs}};

    $self->{tagrun_tagscnt}[$action_ind] = scalar @blocking_tags;
    $self->{tagrun_actions}{$_}[$action_ind] = 1  for @blocking_tags;

    dbg("check: tagrun - action %s blocking on tags %s",
        $action_ind, join(', ',@blocking_tags));
  }
}

# tag_is_ready() will be called by set_tag(), indicating that a given
# tag just received its value, possibly unblocking an action routine
# as declared by action_depends_on_tags().
#
# Well-behaving plugins should call set_tag() once when a tag is fully
# assembled and ready. Multiple calls to set the same tag value are handled
# gracefully, but may result in premature activation of a pending action.
# Setting tag values by plugins should not be done directly but only through
# the public API set_tag(), otherwise a pending action release may be missed.
#
sub tag_is_ready {
  my($self, $tag) = @_;
  $tag = uc $tag;

  if (would_log('dbg', 'check')) {
    my $tag_val = $self->{tag_data}->{$tag};
    dbg("check: tagrun - tag %s is now ready, value: %s",
         $tag, !defined $tag_val ? '<UNDEF>'
               : ref $tag_val ne 'ARRAY' ? $tag_val
               : 'ARY:[' . join(',',@$tag_val) . ']' );
  }
  if (ref $self->{tagrun_actions}{$tag}) {  # any action blocking on this tag?
    my $action_ind = 0;
    foreach my $action_pending (@{$self->{tagrun_actions}{$tag}}) {
      if ($action_pending) {
        $self->{tagrun_actions}{$tag}[$action_ind] = 0;
        if ($self->{tagrun_tagscnt}[$action_ind] <= 0) {
          # should not happen, warn and ignore
          warn "tagrun error: count for $action_ind is ".
                $self->{tagrun_tagscnt}[$action_ind]."\n";
        } elsif (! --($self->{tagrun_tagscnt}[$action_ind])) {
          my($code,@args) = @{$self->{tagrun_subs}[$action_ind]};
          dbg("check: tagrun - tag %s unblocking the action %s: %s",
              $tag, $action_ind, join(', ',$code,@args));
          &$code($self, @args);
        }
      }
      $action_ind++;
    }
  }
}

# debugging aid: show actions that are still pending, waiting for their
# tags to receive a value
#
sub report_unsatisfied_actions {
  my($self) = @_;
  my @tags;
  @tags = keys %{$self->{tagrun_actions}}  if ref $self->{tagrun_actions};
  for my $tag (@tags) {
    my @pending_actions = grep($self->{tagrun_actions}{$tag}[$_],
                               (0 .. $#{$self->{tagrun_actions}{$tag}}));
    dbg("check: tagrun - tag %s is still blocking action %s",
        $tag, join(', ', @pending_actions))  if @pending_actions;
  }
}

=item $status-E<gt>set_tag($tagname, $value)

Set a template tag, as used in C<add_header>, report templates, etc.  This
API is intended for use by plugins.  Tag names will be converted to an
all-uppercase representation internally.  Tag names must consist only of
[A-Z0-9_] characters and must not contain consecutive underscores.  Also the
name must not start or end in an underscore, as that is the template tagging
format.

C<$value> can be a simple scalar (string or number), or a reference to an
array, in which case the public method get_tag will join array elements
using a space as a separator, returning a single string for backward
compatibility.

C<$value> can also be a subroutine reference, which will be evaluated
each time the template is expanded. The first argument passed by get_tag
to a called subroutine will be a PerMsgStatus object (this module's object),
followed by optional arguments provided by a caller to get_tag.

Note that perl supports closures, which means that variables set in the
caller's scope can be accessed inside this C<sub>. For example:

    my $text = "hello world!";
    $status->set_tag("FOO", sub {
              my $pms = shift;
              return $text;
            });

See C<Mail::SpamAssassin::Conf>'s C<TEMPLATE TAGS> and C<CAPTURING TAGS
USING REGEX NAMED CAPTURE GROUPS> sections for more details on how template
tags are used.

=cut

sub set_tag {
  my($self,$tag,$val) = @_;
  $self->{tag_data}->{uc $tag} = $val;
  $self->tag_is_ready($tag);
}

# public API for plugins

=item $string = $status-E<gt>get_tag($tagname)

Get the current value of a template tag, as used in C<add_header>, report
templates, etc. This API is intended for use by plugins.  Tag names will be
converted to an all-uppercase representation internally.

See C<Mail::SpamAssassin::Conf>'s C<TEMPLATE TAGS> and C<CAPTURING TAGS
USING REGEX NAMED CAPTURE GROUPS> sections for more details on how template
tags are used.

C<undef> will be returned if a tag by that name has not been defined.

=cut

sub get_tag {
  my($self, $tag, @args) = @_;

  return if !defined $tag;

  # handle TAGNAME(args) format
  local($1);
  if ($tag =~ s/\((.*?)\)$//) {
    @args = ($1);
  }
  $tag = uc $tag;

  my $data;
  if (exists $common_tags{$tag}) {
    # tag data from traditional pre-defined tag subroutines
    $data = $common_tags{$tag};
    $data = $data->($self,@args)  if ref $data eq 'CODE';
    $data = join(' ',@$data)  if ref $data eq 'ARRAY';
    $data = ""  if !defined $data;
  } elsif (exists $self->{tag_data}->{$tag}) {
    # tag data comes from $self->{tag_data}->{TAG}, typically from plugins
    $data = $self->{tag_data}->{$tag};
    $data = $data->($self,@args)  if ref $data eq 'CODE';
    $data = join(' ',@$data)  if ref $data eq 'ARRAY';
    $data = ""  if !defined $data;
  }
  return $data;
}

=item $string = $status-E<gt>get_tag_raw($tagname, @args)

Similar to C<get_tag>, but keeps a tag name unchanged (does not uppercase it),
and does not convert arrayref tag values into a single string.

=cut

sub get_tag_raw {
  my($self, $tag, @args) = @_;

  return if !defined $tag;

  # handle TAGNAME(args) format
  local($1);
  if ($tag =~ s/\((.*?)\)$//) {
    @args = ($1);
  }

  my $data;
  if (exists $common_tags{$tag}) {
    # tag data from traditional pre-defined tag subroutines
    $data = $common_tags{$tag};
    $data = $data->($self,@args)  if ref $data eq 'CODE';
    $data = ""  if !defined $data;
  } elsif (exists $self->{tag_data}->{$tag}) {
    # tag data comes from $self->{tag_data}->{TAG}, typically from plugins
    $data = $self->{tag_data}->{$tag};
    $data = $data->($self,@args)  if ref $data eq 'CODE';
    $data = ""  if !defined $data;
  }
  return $data;
}

###########################################################################

# public API for plugins

=item $status-E<gt>set_spamd_result_item($subref)

Set an entry for the spamd result log line.  C<$subref> should be a code
reference for a subroutine which will return a string in C<'name=VALUE'>
format, similar to the other entries in the spamd result line:

  Jul 17 14:10:47 radish spamd[16670]: spamd: result: Y 22 - ALL_NATURAL,
  DATE_IN_FUTURE_03_06,DIET_1,DRUGS_ERECTILE,DRUGS_PAIN,
  TEST_FORGED_YAHOO_RCVD,TEST_INVALID_DATE,TEST_NOREALNAME,
  TEST_NORMAL_HTTP_TO_IP,UNDISC_RECIPS scantime=0.4,size=3138,user=jm,
  uid=1000,required_score=5.0,rhost=localhost,raddr=127.0.0.1,
  rport=33153,mid=<9PS291LhupY>,autolearn=spam

C<name> and C<VALUE> must not contain C<=> or C<,> characters, as it
is important that these log lines are easy to parse.

The code reference will be called by spamd after the message has been scanned,
and the C<PerMsgStatus::check()> method has returned.

=cut

sub set_spamd_result_item {
  my ($self, $ref) = @_;
  push @{$self->{spamd_result_log_items}}, $ref;
}

# called by spamd
sub get_spamd_result_log_items {
  my ($self) = @_;
  my @ret;
  foreach my $ref (@{$self->{spamd_result_log_items}}) {
    push @ret, &$ref;
  }
  return @ret;
}

###########################################################################

sub _get_tag_value_for_yesno {
  my($self, $arg) = @_;
  my($arg_spam, $arg_ham);
  ($arg_spam, $arg_ham) = split(/,/, $arg, 2)  if defined $arg;
  return $self->{is_spam} ? (defined $arg_spam ? $arg_spam : 'Yes')
                          : (defined $arg_ham  ? $arg_ham  : 'No');
}

sub _get_tag_value_for_score {
  my ($self, $pad) = @_;

  my $score  = sprintf("%2.1f", $self->{score});
  my $rscore = $self->_get_tag_value_for_required_score();

  #Change due to bug 6419 to use Util function for consistency with spamd
  #and PerMessageStatus
  $score = Mail::SpamAssassin::Util::get_tag_value_for_score($score, $rscore, $self->{is_spam});

  #$pad IS PROVIDED BY THE _SCORE(PAD)_ tag
  if (defined $pad && $pad =~ /^(0+| +)$/) {
    my $count = length($1) + 3 - length($score);
    $score = (substr($pad, 0, $count) . $score) if $count > 0;
  }
  return $score;

}

sub _get_tag_value_for_required_score {
  my $self = shift;
  return sprintf("%2.1f", $self->{conf}->{required_score});
}


###########################################################################

=item $status-E<gt>finish ()

Indicate that this C<$status> object is finished with, and can be destroyed.

If you are using SpamAssassin in a persistent environment, or checking many
mail messages from one C<Mail::SpamAssassin> factory, this method should be
called to ensure Perl's garbage collection will clean up old status objects.

=cut

sub finish {
  my ($self) = @_;

  $self->{main}->call_plugins ("per_msg_finish", {
	  permsgstatus => $self
	});

  $self->report_unsatisfied_actions();

  # Clean up temporary methods
  foreach my $method (@TEMPORARY_METHODS) {
    if (defined &{$method}) {
      undef &{$method};
    }
  }
  @TEMPORARY_METHODS = ();      # clear for next time
  %TEMPORARY_EVAL_GLUE_METHODS = ();

  # Delete out all of the members of $self.  This will remove any direct
  # circular references and let the memory get reclaimed while also being more
  # efficient than a foreach() loop over the keys.
  %{$self} = ();
}

# Deprecated for clarity, only Plugins have this function
sub finish_tests {}

###########################################################################

=item $name = $status-E<gt>get_current_eval_rule_name()

Return the name of the currently-running eval rule.  C<undef> is
returned if no eval rule is currently being run.  Useful for plugins
to determine the current rule name while inside an eval test function
call.

=cut

sub get_current_eval_rule_name {
  my ($self) = @_;
  return $self->{current_rule_name};
}

###########################################################################

sub extract_message_metadata {
  my ($self) = @_;

  my $timer = $self->{main}->time_method("extract_message_metadata");
  $self->{msg}->extract_message_metadata($self);

  foreach my $item (qw(
	relays_trusted relays_trusted_str num_relays_trusted
	relays_untrusted relays_untrusted_str num_relays_untrusted
	relays_internal relays_internal_str num_relays_internal
	relays_external relays_external_str num_relays_external
	num_relays_unparseable last_trusted_relay_index
	last_internal_relay_index
	))
  {
    $self->{$item} = $self->{msg}->{metadata}->{$item};
  }

  # International domain names (UTF-8) must be converted to ASCII-compatible
  # encoding (ACE) for the purpose of setting the SENDERDOMAIN and AUTHORDOMAIN
  # tags (explicitly required for DMARC, RFC 7489)
  #
  { local $1;
    my $host = ($self->get('EnvelopeFrom:first:addr:host'))[0];
    # collect a FQDN, ignoring potential trailing WSP
    if (defined $host) {
      my $d = idn_to_ascii($host);
      $self->set_tag('SENDERDOMAIN', $d);
      $self->{msg}->put_metadata("X-SenderDomain", $d);
      dbg("metadata: X-SenderDomain: %s", $d);
    }
    my @from_doms;
    my %seen;
    foreach ($self->get('From:addr:host')) {
      next if $seen{$_}++;
      my $d = idn_to_ascii($_);
      push @from_doms, $d;
    }
    if (@from_doms) {
      $self->set_tag('AUTHORDOMAIN', @from_doms > 1 ? \@from_doms : $from_doms[0]);
      my $d = join(" ", @from_doms);
      $self->{msg}->put_metadata("X-AuthorDomain", $d);
      dbg("metadata: X-AuthorDomain: %s", $d);
    }
  }

  $self->set_tag('RELAYSTRUSTED',   $self->{relays_trusted_str});
  $self->set_tag('RELAYSUNTRUSTED', $self->{relays_untrusted_str});
  $self->set_tag('RELAYSINTERNAL',  $self->{relays_internal_str});
  $self->set_tag('RELAYSEXTERNAL',  $self->{relays_external_str});
  $self->set_tag('LANGUAGES', $self->{msg}->get_metadata("X-Languages"));

  # This should happen before we get called, but just in case.
  if (!defined $self->{msg}->{metadata}->{html}) {
    $self->get_decoded_stripped_body_text_array();
  }
  $self->{html} = $self->{msg}->{metadata}->{html};
  $self->{html_all} = $self->{msg}->{metadata}->{html_all};

  # allow plugins to add more metadata, read the stuff that's there, etc.
  $self->{main}->call_plugins ("parsed_metadata", { permsgstatus => $self });
}

###########################################################################

=item $status-E<gt>get_decoded_body_text_array ()

Returns the message body, with B<base64> or B<quoted-printable> encodings
decoded, and non-text parts or non-inline attachments stripped.

This is the same result text as used in 'rawbody' rules.

It is returned as an array of strings, with each string being a 2-4kB chunk
of the body, split from boundaries if possible.

=cut

sub get_decoded_body_text_array {
  return $_[0]->{msg}->get_decoded_body_text_array();
}

=item $status-E<gt>get_decoded_stripped_body_text_array ()

Returns the message body, decoded (as described in
get_decoded_body_text_array()), with HTML rendered, and with whitespace
normalized.

This is the same result text as used in 'body' rules.

It will always render text/html.

It is returned as an array of strings, with each string representing one
'paragraph'.  Paragraphs, in plain-text mails, are double-newline-separated
blocks of multi-line text.

=cut

sub get_decoded_stripped_body_text_array {
  return $_[0]->{msg}->get_rendered_body_text_array();
}

###########################################################################

=item $status-E<gt>get (header_name [, default_value])

Returns message headers, pseudo-headers, names, email-addresses or some
other parsed values set by modifiers.  C<header_name> is the name of a mail
header such as 'Subject', 'To' etc, or a pseudo/metadata-header like 'ALL',
'X-Spam-Relays-Untrusted' etc.

Should be called in list context since SpamAssassin 4.0.  This supports
returning multiple values for all header and modifier types.

If called in scalar context (pre-4.0 style), only first value is returned
for modifiers like C<:addr> or C<:name>.

If C<default_value> is given, it will be used if the requested
C<header_name> does not exist.  This is mainly useful when called in scalar
context to set 'undef' instead of legacy '' return value when header does
not exist.

Appending C<:raw> modifier to the header name will inhibit decoding of
quoted-printable or base-64 encoded strings.

Appending C<:addr> modifier to the header name will return all
email-addresses found in the header.  It is mainly applicable to header
fields 'From', 'Sender', 'To', 'Cc' along with their 'Resent-*'
counterparts, and the 'Return-Path'.  For example, all of the following will
result in "example@foo" (and "example@bar"):

=over 4

=item example@foo

=item example@foo (Foo Blah), E<lt>example@barE<gt>

=item example@foo, example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah E<lt>example@fooE<gt>

=item "Foo Blah" E<lt>example@fooE<gt>

=item "'Foo Blah'" E<lt>example@fooE<gt>

=back

Appending C<:name> modifier to the header name will return all "display
names" from the header field.  As with C<:addr>, it is mainly applicable to
header fields 'From', 'Sender', 'To', 'Cc' along with their 'Resent-*'
counterparts, and the 'Return-Path'.  For example, all of the following will
result in "Foo Blah" (and "Bar Baz").  One level of single quotes is
stripped too, as it is often seen.

=over 4

=item example@foo (Foo Blah)

=item example@foo (Foo Blah), "Bar Baz" E<lt>example@barI<gt>

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah E<lt>example@fooE<gt>

=item "Foo Blah" E<lt>example@fooE<gt>

=item "'Foo Blah'" E<lt>example@fooE<gt>

=back

Appending C<:host> to the header name will return the first hostname-looking
string that ends with a valid TLD.  First it tries to find a match after @
character (possible email), then from any part of the header.  Normal use of
this would be for example 'From:addr:host' to return the hostname portion of
a From-address.

Appending C<:domain> to the header name implies C<:host>, but will return
only domain part of the hostname, as returned by
RegistryBoundaries::trim_domain().

Appending C<:ip> to the header name, will return the first IPv4 or IPv6
address string found.  Could be used for example as 'X-Originating-IP:ip'.

Appending C<:revip> to the header name implies C<:ip>, but will return the
found IP in reverse (usually for DNSBL usage).

Appending C<:first> modifier to the header name will return only the first
(topmost) header, in case there are multiple ones.  Similarly C<:last> will
select the last one.  These affect only the physical header line selection. 
If selected header is parsed further with C<:addr> or similar, it may return
multiple results, if the selected header contains multiple addresses.

There are several special pseudo-headers that can be specified:

=over 4

=item C<ALL> can be used to mean the text of all the message's headers.
Each header is decoded and unfolded to single line, unless called with :raw.

=item C<ALL-TRUSTED> can be used to mean the text of all the message's headers
that could only have been added by trusted relays.

=item C<ALL-INTERNAL> can be used to mean the text of all the message's headers
that could only have been added by internal relays.

=item C<ALL-UNTRUSTED> can be used to mean the text of all the message's
headers that may have been added by untrusted relays.  To make this
pseudo-header more useful for header rules the 'Received' header that was added
by the last trusted relay is included, even though it can be trusted.

=item C<ALL-EXTERNAL> can be used to mean the text of all the message's headers
that may have been added by external relays.  Like C<ALL-UNTRUSTED> the
'Received' header added by the last internal relay is included.

=item C<ToCc> can be used to mean the contents of both the 'To' and 'Cc'
headers.

=item C<EnvelopeFrom> is the address used in the 'MAIL FROM:' phase of the SMTP
transaction that delivered this message, if this data has been made available
by the SMTP server.

=item C<MESSAGEID> is a symbol meaning all Message-Id's found in the
message; some mailing list software moves the real 'Message-Id' to
'Resent-Message-Id' or 'X-Message-Id' or 'X-Original-Message-ID', then uses
its own one in the 'Message-Id' header.  The value returned for this symbol
is the text from all 4 headers.

=item C<X-Spam-Relays-Untrusted> is the generated metadata of untrusted relays
the message has passed through

=item C<X-Spam-Relays-Trusted> is the generated metadata of trusted relays
the message has passed through

=item C<X-Spam-Relays-External> is the generated metadata of external relays
the message has passed through

=item C<X-Spam-Relays-Internal> is the generated metadata of internal relays
the message has passed through

=back

=cut

# only uses two arguments, ignores $defval
sub _get {
  my ($self, $request) = @_;

  my @results;
  my $getaddr = 0;
  my $getname = 0;
  my $getraw = 0;
  my $needraw = 0;
  my $gethost = 0;
  my $getdomain = 0;
  my $getip = 0;
  my $getrevip = 0;
  my $getfirst = 0;
  my $getlast = 0;

  # special queries - process and strip modifiers
  if (index($request,':') >= 0) {  # triage
    local $1;
    while ($request =~ s/:([^:]*)//) {
      if    ($1 eq 'raw')    { $getraw  = 1 }
      elsif ($1 eq 'addr')   { $getaddr = $needraw = 1 }
      elsif ($1 eq 'name')   { $getname = $needraw = 1 }
      elsif ($1 eq 'host')   { $gethost = 1 }
      elsif ($1 eq 'domain') { $gethost = $getdomain = 1 }
      elsif ($1 eq 'ip')     { $getip = 1 }
      elsif ($1 eq 'revip')  { $getip = $getrevip = 1 }
      elsif ($1 eq 'first')  { $getfirst = 1 }
      elsif ($1 eq 'last')   { $getlast = 1 }
    }
  }
  my $request_lc = lc $request;

  # ALL: entire pristine or semi-raw headers
  if ($request eq 'ALL') {
    if ($getraw) {
      @results = $self->{msg}->get_pristine_header() =~ /^([^ \t].*?\n)(?![ \t])/smgi;
    } else {
      @results = $self->{msg}->get_all_headers(0);
    }
    return \@results;
  }
  # ALL-TRUSTED: entire trusted raw headers
  elsif ($request eq 'ALL-TRUSTED') {
    # '+1' since we added the received header even though it's not considered
    # trusted, so we know that those headers can be trusted too
    @results = $self->get_all_hdrs_in_rcvd_index_range(
			undef, $self->{last_trusted_relay_index}+1,
			undef, undef, $getraw);
    return \@results;
  }
  # ALL-INTERNAL: entire internal raw headers
  elsif ($request eq 'ALL-INTERNAL') {
    # '+1' for the same reason as in ALL-TRUSTED above
    @results = $self->get_all_hdrs_in_rcvd_index_range(
			undef, $self->{last_internal_relay_index}+1,
			undef, undef, $getraw);
    return \@results;
  }
  # ALL-UNTRUSTED: entire untrusted raw headers
  elsif ($request eq 'ALL-UNTRUSTED') {
    # '+1' for the same reason as in ALL-TRUSTED above
    @results = $self->get_all_hdrs_in_rcvd_index_range(
			$self->{last_trusted_relay_index}+1, undef,
			undef, undef, $getraw);
    return \@results;
  }
  # ALL-EXTERNAL: entire external raw headers
  elsif ($request eq 'ALL-EXTERNAL') {
    # '+1' for the same reason as in ALL-TRUSTED above
    @results = $self->get_all_hdrs_in_rcvd_index_range(
			$self->{last_internal_relay_index}+1, undef,
			undef, undef, $getraw);
    return \@results;
  }
  # EnvelopeFrom: the SMTP MAIL FROM: address
  elsif ($request_lc eq "\LEnvelopeFrom") {
    push @results, $self->get_envelope_from();
  }
  # untrusted relays list, as string
  elsif ($request_lc eq "\LX-Spam-Relays-Untrusted") {
    push @results, $self->{relays_untrusted_str};
  }
  # trusted relays list, as string
  elsif ($request_lc eq "\LX-Spam-Relays-Trusted") {
    push @results, $self->{relays_trusted_str};
  }
  # external relays list, as string
  elsif ($request_lc eq "\LX-Spam-Relays-External") {
    push @results, $self->{relays_external_str};
  }
  # internal relays list, as string
  elsif ($request_lc eq "\LX-Spam-Relays-Internal") {
    push @results, $self->{relays_internal_str};
  }
  # ToCc: the combined recipients list
  elsif ($request_lc eq "\LToCc") {
    push @results, $self->{msg}->get_header('To', $getraw);
    push @results, $self->{msg}->get_header('Cc', $getraw);
  }
  # MESSAGEID: handle lists which move the real message-id to another
  # header for resending.
  elsif ($request eq 'MESSAGEID') {
    push @results, grep { defined($_) && $_ ne '' } (
		   $self->{msg}->get_header('X-Message-Id', $getraw),
		   $self->{msg}->get_header('Resent-Message-Id', $getraw),
		   $self->{msg}->get_header('X-Original-Message-ID', $getraw),
		   $self->{msg}->get_header('Message-Id', $getraw));
  }
  # a conventional header
  else {
    my @res = $getraw||$needraw ? $self->{msg}->raw_header($request)
                                : $self->{msg}->get_header($request);
    if (!@res) {
      if (defined(my $m = $self->{msg}->get_metadata($request))) {
        push @res, $m;
      }
    }
    push @results, @res if @res;
  }

  # Nothing found to process further, bail out quick
  if (!@results) {
    return \@results;
  }

  # Continue processing only first (topmost) or last header
  if ($getfirst) {
    @results = ($results[0]);
  } elsif ($getlast) {
    @results = ($results[-1]);
  }

  # special addr/name
  if ($getaddr || $getname) {
    my @res;
    foreach my $line (@results) {
      next unless defined $line;
      # Note: parse_header_addresses always called with raw undecoded value
      # Skip invalid addresses here
      my @addrs = parse_header_addresses($line);
      if (@addrs) {
        if ($getaddr) {
          foreach my $addr (@addrs) {
            push @res, $addr->{address} if defined $addr->{address};
          }
        }
        elsif ($getname) {
          foreach my $addr (@addrs) {
            next unless defined $addr->{phrase};
            if ($getraw) {
              # phrase=name, could also be username or comment unless name found
              push @res, $addr->{phrase};
            } else {
              # If :raw was not specifically asked, decode mimewords
              # TODO: silly call to Node module, should probably be in Util
              my $decoded = Mail::SpamAssassin::Message::Node::_decode_header(
                              $addr->{phrase}, "PMS:get:$request");
              # Normalize whitespace, unless it's all white-space
              if ($decoded =~ /\S/) {
                $decoded =~ s/\s+/ /gs;
                $decoded =~ s/^\s+//;
                $decoded =~ s/\s+$//;
                $decoded =~ s/^'(.*?)'$/$1/; # remove single quotes
              }
              push @res, $decoded if defined $decoded;
            }
          }
        }
      }
    }
    @results = @res;
  }

  # special host/domain
  if (@results && ($gethost || $getdomain || $getip)) {
    my @res;
    if ($gethost) {
      # TODO: IDN matching needs honing
      my $tldsRE = $self->{main}->{registryboundaries}->{valid_tlds_re};
      #my $hostRE = qr/(?<![._-])\b([a-z\d][a-z\d._-]{0,251}\.${tldsRE})\b(?![._-])/i;
      my $hostRE = qr/(?<![._-])(\S{1,251}\.${tldsRE})(?![._-])/i;
      foreach my $line (@results) {
        next unless defined $line;
        my $host;
        if ($getaddr) {
          # If :addr already preparsed the line, just grab domain liberally
          if ($line =~ /.*\@(\S+)/) {
            $host = $1;
          }
        }
        else {
          # try grabbing email/msgid domain first, because user part might look like
          # a valid host..
          if ($line =~ /.*\@${hostRE}/i) {
            if (is_fqdn_valid(idn_to_ascii($1), 1)) {
              $host = $1;
            }
          }
          # otherwise try hard to find a valid host
          if (!$host) {
            while ($line =~ /${hostRE}/ig) {
              if (is_fqdn_valid(idn_to_ascii($1), 1)) {
                $host = $1;
                last;
              }
            }
          }
        }
        if ($host) {
          if ($getdomain) {
            $host = $self->{main}->{registryboundaries}->trim_domain($host, 1);
          }
          push @res, $host;
        }
      }
    } else {
      my $ipRE = qr/(?<!\.)\b(${IP_ADDRESS})\b(?!\.)/;
      foreach my $line (@results) {
        next unless defined $line;
        my $host;
        if ($line =~ $ipRE) {
          $host = $getrevip ? reverse_ip_address($1) : $1;
        }
        push @res, $host  if defined $host;
      }
    }
    @results = @res;
  }

  return \@results;
}

# optimized for speed
# $_[0] is self
# $_[1] is request
# $_[2] is defval
sub get {
  my $cache = $_[0]->{get_cache};
  my $found = [];
  if (exists $cache->{$_[1]}) {
    # return cache entry if it is known
    # (measured hit/attempts rate on a production mailer is about 47%)
    $found = $cache->{$_[1]};
  } else {
    # fill in a cache entry
    $found = _get(@_);
    # filter out undefined
    @$found = grep { defined } @$found;
    $cache->{$_[1]} = $found;
  }
  # if the requested header wasn't found, we should return a default value
  # as specified by the caller: if defval argument is present it represents
  # a default value even if undef; if defval argument is absent a default
  # value is an empty string for upwards compatibility
  if (@$found) {
    # new list context usage in 4.0, return all values always
    if (wantarray) {
      return @$found;
    }
    # legacy scalar context expected only single return value for some
    # queries, without a newline
    if ($_[1] =~ /:(?:addr|name|host|domain|ip|revip)\b/ ||
        $_[1] eq 'EnvelopeFrom') {
      my $res = $found->[0];
      $res =~ s/\n\z//;
      return $res;
    } else {
      return join('', @$found);
    }
  } elsif (@_ > 2) {
    return wantarray ? ($_[2]) : $_[2];
  } else {
    return wantarray ? () : '';
  }
}

###########################################################################

# uri parsing from plain text:
# The goals are to find URIs in plain text spam that are intended to be clicked on or copy/pasted, but
# ignore random strings that might look like URIs, for example in uuencoded files, and to ignore
# URIs that spammers might seed in spam in ways not visible or clickable to add work to spam filters.
# When we extract a domain and look it up in an RBL, an FP on deciding that the text is a URI is not much
# of a problem, as the only cost is an extra RBL lookup. The same FP is worse if the URI is used in matching rule
# because it could lead to a rule FP, as in bug 5780 with WIERD_PORT matching random uuencoded strings.
# The principles of the following code are 1) if ThunderBird or Outlook Express would linkify a string,
# then we should attempt to parse it as a URI; 2) Where TBird and OE parse differently, choose to do what is most
# likely to find a domain for the RBL tests; 3) If it begins with a scheme or www\d*\. or ftp\. assume that
# it is a URI; 4) If it does not then require that the start of the string looks like a FQDN with a valid TLD;
# 5) Reject strings that after parsing, URLDecoding, and redirection processing don't have a valid TLD
#
# We get the entire URI that would be linkified before dealing with it, in order to do the right thing
# with URI-encodings and redirecting URIs.
#
# The delimiters for start of a URI in TBird are @(`{|[\"'<>,\s   in OE they are ("<\s
#
# Tbird allows .,?';-! in a URI but ignores [.,?';-!]* at the end.
# TBird's end delimiters are )`{}|[]"<>\s but ) is only an end delmiter if there is no ( in the URI
# OE only uses space as a delimiter, but ignores [~!@#^&*()_+`-={}|[]:";'<>?,.]* at the end.
#
# Both TBird and OE decide that a URI is an email address when there is '@' character embedded in it.
# TBird has some additional restrictions on email URIs: They cannot contain non-ASCII characters and their end
# delimiters include ( and '
#
# bug 4522: ISO2022 format mail, most commonly Japanese SHIFT-JIS, inserts a three character escape sequence  ESC ( .

sub _tbirdurire {
  my ($self) = @_;

  # Cached?
  return $self->{tbirdurire} if exists $self->{tbirdurire};

  # a hybrid of tbird and oe's  version of uri parsing
  my $tbirdstartdelim = '><"\'`,{[(|\s'  . "\x1b\xa0";  # The \x1b as per bug 4522 # \xa0 (nbsp) added 7/2019
  my $iso2022shift = "\x1b" . '\(.';  # bug 4522
  my $tbirdenddelim = '><"`}\]{[|\s' . "\x1b\xa0";  # The \x1b as per bug 4522 # \xa0 (nbsp) added 7/2019
  my $nonASCII    = '\x80-\xff';

  # schemeless uri start delimiter, combo of most punctuations and delims above
  my $scstartdelim = qr/[\!\"\#\$\&\'\(\)\*\+\,\/\:\;\<\=\>\?\@\[\\\]\^\`\{\|\}\~\s\x1b\xa0]/;

  # bug 7100: we allow a comma to delimit the end of an email address because it will never appear in a domain name, and
  # it's a common thing to find in text
  my $tbirdenddelimemail = $tbirdenddelim . ',(\'' . $nonASCII;  # tbird ignores non-ASCII mail addresses for now, until RFC changes
  my $tbirdenddelimplusat = $tbirdenddelimemail . '@';

  # valid TLDs
  my $tldsRE = $self->{main}->{registryboundaries}->{valid_tlds_re};

  # knownscheme regexp looks for either a https?: or ftp: scheme, or www\d*\. or ftp\. prefix, i.e., likely to start a URL
  # schemeless regexp looks for a valid TLD at the end of what may be a FQDN, followed by optional ., optional :portnum, optional /rest_of_uri
  my $urischemeless = qr/([a-z\d][a-z\d._-]{0,251}\.${tldsRE})\.?(?::\d{1,5})?(?:\/[^$tbirdenddelim]{1,2048})?/i;
  my $uriknownscheme = qr/(?:(?:https?|ftp):\/\/|(?:www\d{0,2}|ftp)\.)[^$tbirdenddelim]{1,2048}/i;
  my $urimailscheme = qr/(?:mailto:[^$tbirdenddelimemail]{1,2048}|[^$tbirdenddelimplusat]{1,251}\@[^$tbirdenddelimemail]{1,251})/i;

  $self->{tbirdurire} = qr/(?:\b|(?<=$iso2022shift)|(?<=[$tbirdstartdelim]))
                        (?:(?:($uriknownscheme)(?=(?:[$tbirdenddelim]|\z))) |
                        (?:($urimailscheme)(?=(?:[$tbirdenddelimemail]|\z))) |
                        (?:(?:^|(?<=$scstartdelim))($urischemeless)(?=(?:[$tbirdenddelim]|\z))))/ix;

  return $self->{tbirdurire};
}

=item $status-E<gt>get_uri_list ()

Returns an array of all unique URIs found in the message.  It takes
a combination of the URIs found in the rendered (decoded and HTML
stripped) body and the URIs found when parsing the HTML in the message.
Will also set $status-E<gt>{uri_list} (the array as returned by this function).

The returned array will include the "raw" URI as well as
"slightly cooked" versions.  For example, the single URI
'http://%77&#00119;%77.example.com/' will get turned into:
( 'http://%77&#00119;%77.example.com/', 'http://www.example.com/' )

=cut

sub get_uri_list {
  my ($self) = @_;

  # use cached answer if available
  if (exists $self->{uri_list}) {
    return @{$self->{uri_list}};
  }

  my %uris;
  # $self->{redirect_num} = 0;

  # get URIs from text/HTML parsing
  while(my($uri, $info) = each %{ $self->get_uri_detail_list() }) {
    if ($info->{cleaned}) {
      foreach (@{$info->{cleaned}}) {
        $uris{$_} = 1;

        # count redirection attempts and log it
        # if (my @http = m{\b(https?:/{0,2})}gi) {
        # $self->{redirect_num} = $#http if ($#http > $self->{redirect_num});
        # }
      }
    }
  }

  @{$self->{uri_list}} = keys %uris;
# $self->set_tag('URILIST', @uris == 1 ? $uris[0] : \@uris)  if @uris;

  return @{$self->{uri_list}};
}

=item $status-E<gt>get_uri_detail_list ()

Returns a hash reference of all unique URIs found in the message and
various data about where the URIs were found in the message.  It takes a
combination of the URIs found in the rendered (decoded and HTML stripped)
body and the URIs found when parsing the HTML in the message.  Will also
set $status-E<gt>{uri_detail_list} (the hash reference as returned by this
function).

The hash format looks something like this:

  raw_uri => {
    types => { a => 1, img => 1, parsed => 1, domainkeys => 1,
               unlinked => 1, schemeless => 1 },
    cleaned => [ canonicalized_uri ],
    anchor_text => [ "click here", "no click here" ],
    domains => { domain1 => 1, domain2 => 1 },
    hosts => { host1 => domain1, host2 => domain2 },
  }

C<raw_uri> is whatever the URI was in the message itself
(http://spamassassin.apache%2Eorg/).  Uris parsed from text will be prefixed
with scheme if missing (http://, mailto: etc).  HTML uris are as found.

C<types> is a hash of the HTML tags (lowercase) which referenced the
raw_uri.  I<parsed> is a faked type which specifies that the raw_uri was
seen in the rendered text.  I<domainkeys> is defined when raw_uri was found
from DK/DKIM d= field.  I<unlinked> is defined when it's assumed that MUA
will not linkify uri (found in body without scheme or www. prefix). 
I<schemeless> is always added for uris without scheme, regardless of
linkifying (i.e. email address found in body without mailto:).

C<cleaned> is an array of the raw and canonicalized version of the raw_uri
(http://spamassassin.apache%2Eorg/, https://spamassassin.apache.org/).

C<anchor_text> is an array of the anchor text (text between E<lt>aE<gt> and
E<lt>/aE<gt>), if any, which linked to the URI.

C<domains> is a hash of the domains found in the canonicalized URIs.

C<hosts> is a hash of unstripped hostnames found in the canonicalized URIs
as hash keys, with their domain part stored as a value of each hash entry.

=cut

sub get_uri_detail_list {
  my ($self) = @_;

  # process only once, use unique uri_detail_list_run flag,
  # in case add_uri_detail_list has already been called
  if ($self->{uri_detail_list_run}) {
    return $self->{uri_detail_list};
  }
  $self->{uri_detail_list_run} = 1;

  my $timer = $self->{main}->time_method("get_uri_detail_list");

  # process text parsed uris
  $self->_process_text_uri_list();
  # process html uris
  $self->_process_html_uri_list();
  # process dkim uris
  $self->_process_dkim_uri_list();

  return $self->{uri_detail_list};
}

sub _process_text_uri_list {
  my ($self) = @_;

  # Use decoded stripped body, which does not contain HTML
  my $textary = $self->get_decoded_stripped_body_text_array();
  my $tbirdurire = $self->_tbirdurire;
  my %seen;
  my $would_log_uri_all = would_log('dbg', 'uri-all') == 2; # cache

  foreach my $text (@$textary) {
    # a workaround for [perl #69973] bug:
    # Invalid and tainted utf-8 char crashes perl 5.10.1 in regexp evaluation
    # Bug 6225, regexp and string should both be utf8, or none of them;
    # untainting string also seems to avoid the crash
    #
    # Bug 6225: untaint the string in an attempt to work around a perl crash
    local $_ = untaint_var($text);

    local($1,$2,$3);
    while (/$tbirdurire/igo) {
      my $rawuri = $1||$2||$3;
      my $schost = $4;
      my $rawtype = defined $1 ? 'scheme' : defined $2 ? 'mail' : 'schemeless';
      $rawuri =~ s/(^[^(]*)\).*$/$1/;  # as per ThunderBird, ) is an end delimiter if there is no ( preceding it
      $rawuri =~ s/[-~!@#^&*()_+=:;\'?,.]*$//; # remove trailing string of punctuations that TBird ignores

      next if exists $seen{$rawuri};
      $seen{$rawuri} = 1;

      # Ignore bogus mail captures (@ might have been trimmed from the end above..)
      next if $rawtype eq 'mail' && index($rawuri, '@') == -1;

      dbg("uri: found rawuri from text ($rawtype): $rawuri") if $would_log_uri_all;

      # Quick ignore if schemeless host not valid
      next if defined $schost && !is_fqdn_valid($schost, 1);

      # Ignore cid: mid: as they can be mistaken for emails,
      # these should not be parsed from stripped body in any case.
      # Example: [cid:image001.png@01D4986E.E3459640]
      next if $rawuri =~ /^[cm]id:/i;

      # Ignore empty uris
      next if $rawuri =~ /^\w+:\/{0,2}$/i;

      my $types = {parsed => 1};

      # If it's a hostname that was just sitting out in the
      # open, without a protocol, and not inside of an HTML tag,
      # the we should add the proper protocol in front, rather
      # than using the base URI.
      my $uri = $rawuri;
      if ($uri !~ /^(?:https?|ftp|mailto):/i) {
        if ($uri =~ /^ftp\./i) {
          $uri = "ftp://$uri";
        }
        elsif ($uri =~ /^www\d{0,2}\./i) {
          $uri = "http://$uri";
        }
        elsif ($uri =~ /\/.+\@/) {
          # if a "/" is found before @ it cannot be a valid email address
          $uri = "http://$uri";
        }
        elsif (index($uri, '@') != -1) {
          # This is not linkified by MUAs: foo@bar%2Ecom
          # This IS linkified: foo@bar%2Ebar.com
          # And this is linkified: foo@bar%2Ecom?foo.com&bar  (woot??)
          # And this is linkified with Outlook: foo@bar%2Ecom&foo  (woot??)
          # ...
          # Skip if no dot found after @, tested without urldecoding,
          # quick skip for crap like Vi@gra.
          next unless $uri =~ /\@.+?\./;
          next if index($uri, '&nbsp;') != -1; # ignore garbled
          $uri =~ s/^(?:skype|e?-?mail)?:+//i; # strip common misparses
          $uri = "mailto:$uri";
        }
        else {
          # some spammers are using unschemed URIs to escape filters
          # flag that this is a URI that MUAs don't linkify so only use for RBLs
          # (TODO: why only use for RBLs?? why not uri rules? Use tflags to choose?)
          next if index($uri, '.') == -1; # skip unless dot found, garbage
          $uri = "http://$uri";
          $types->{unlinked} = 1;
        }
        # Mark any of those schemeless
        $types->{schemeless} = 1;
      }

      if ($uri =~ /^mailto:/i) {
        # MUAs linkify and urldecode mailto:foo%40bar%2Fcom
        $uri = Mail::SpamAssassin::Util::url_encode($uri) if $uri =~ /\%[0-9a-f]{2}/i;
        # Skip unless @ found after decoding, then check tld is valid
        next unless $uri =~ /\@([^?&>]*)/;
        my $host = $1; $host =~ s/(?:\%20)+$//; # strip trailing %20 from host
        next unless $self->{main}->{registryboundaries}->is_domain_valid($host);
      }

      dbg("uri: parsed uri from text ($rawtype): $uri") if $would_log_uri_all;

      $self->add_uri_detail_list($uri, $types, 'parsed', 1);
    }
  }
}

sub _process_html_uri_list {
  my ($self) = @_;

  # get URIs from HTML parsing
  # use the metadata version since $self->{html_all} may not be setup
  foreach my $html (@{$self->{msg}->{metadata}->{html_all}}) {
    my $detail = $html->{uri_detail} || { };
    $self->{'uri_truncated'} = 1 if $html->{uri_truncated};

    # canonicalize the HTML parsed URIs
    while(my($uri, $info) = each %{ $detail }) {
      if ($self->add_uri_detail_list($uri, $info->{types}, 'html', 0)) {
        # Need also to copy and uniq anchor text
        if (exists $info->{anchor_text}) {
          my %seen;
          foreach (grep { !$seen{$_}++ } @{$info->{anchor_text}}) {
            push @{$self->{uri_detail_list}->{$uri}->{anchor_text}}, $_;
          }
        }
      }
    }
  }
}

sub _process_dkim_uri_list {
  my ($self) = @_;

  # This parses of DKIM for URIs disagrees with documentation and bug 6700 votes to disable
  # this functionality
  # 2013-01-07
  # This functionality is re-enabled as a configuration option disabled by
  # default (bug 7087)
  # 2014-10-06

  # Look for the domain in DK/DKIM headers
  if ($self->{conf}->{parse_dkim_uris}) {
    foreach my $dk ( $self->get('DomainKey-Signature'),
                     $self->get('DKIM-Signature') ) {
      while ($dk =~ /\bd\s*=\s*([^;]+)/g) {
        my $d = $1;
        $d =~ s/\s+//g;
        # prefix with domainkeys: so it doesn't merge with identical keys
        $self->add_uri_detail_list("domainkeys:$d",
          {'domainkeys'=>1, 'nocanon'=>1, 'noclean'=>1},
          'domainkeys', 1);
      }
    }
  }
}

=item $status-E<gt>add_uri_detail_list ($raw_uri, $types, $source, $valid_domain)

Adds values to internal uri_detail_list.  When used from Plugins, recommended
to call from parsed_metadata (along with register_method_priority, -10) so
other Plugins calling get_uri_detail_list() will see it.

C<raw_uri> is the URI to be added. The only required parameter.

C<types> is an optional hash reference, contents are added to
uri_detail_list-E<gt>{types} (see get_uri_detail_list for known keys). 
I<parsed> is default is no hash given.  I<nocanon> does not run
uri_list_canonicalize (no redirector, uri fixing).  I<noclean> skips adding
uri_detail_list-E<gt>{cleaned}, so it would not be used in "uri" rule checks,
but domain/hosts would still be used for URIBL/RBL purposes.

C<source> is an optional simple string, only used for debug logging purposes
to identify where uri originates from (default: "parsed").

C<valid_domain> is an optional boolean (0/1).  If true, uri will not be
added unless hostname/domain is in valid format and contains a valid TLD. 
(default: 0)

=cut

sub add_uri_detail_list {
  my ($self, $uri, $types, $source, $valid_domain) = @_;

  $types = {'parsed' => 1} unless defined $types;
  $source ||= 'parsed';

  my (%domains, %hosts, %cleaned);
  my $udl = $self->{uri_detail_list};

  dbg("uri: canonicalizing $source uri: $uri");

  my @uris;
  if ($types->{nocanon}) {
    push @uris, $uri;
  } else {
    @uris = uri_list_canonicalize($self->{conf}->{redirector_patterns}, [$uri], $self->{main}->{registryboundaries});
  }
  foreach my $cleanuri (@uris) {
    # Make sure all the URIs are nice and short
    if (length($cleanuri) > MAX_URI_LENGTH) {
      $self->{'uri_truncated'} = 1;
      $cleanuri = substr($cleanuri, 0, MAX_URI_LENGTH);
    }
    dbg("uri: cleaned uri: $cleanuri");
    $cleaned{$cleanuri} = 1;
    my ($domain, $host) = $self->{main}->{registryboundaries}->uri_to_domain($cleanuri);
    if (defined $domain) {
      dbg("uri: added host: $host domain: $domain");
      $domains{$domain} = 1;
      $hosts{$host} = $domain;
    }
  }

  # Bail out if no good uri found
  return unless %cleaned;

  # Bail out if no domains/hosts found?
  return if $valid_domain && !%domains;

  # Merge cleaned
  if (!$types->{noclean}) {
    if ($udl->{$uri}->{cleaned}) {
      $cleaned{$_} = 1 foreach (@{$udl->{$uri}->{cleaned}});
    }
    @{$udl->{$uri}->{cleaned}} = keys %cleaned;
  }

  # Domains/hosts (there might not be any)
  $udl->{$uri}->{domains}->{$_} = 1 foreach keys %domains;
  $udl->{$uri}->{hosts}->{$_} = $hosts{$_} foreach keys %hosts;

  # Types
  $udl->{$uri}->{types}->{$_} = 1 foreach keys %$types;

  # Invalidate uri_list cache
  delete $self->{uri_list};

  return 1;
}

###########################################################################

# Deprecated since 4.0, meta rules do not depend on priorities anymore
sub ensure_rules_are_complete {}

###########################################################################

# use a separate sub here, for brevity
# called out of generated eval
sub handle_eval_rule_errors {
  my ($self, $rulename) = @_;
  warn "rules: failed to run $rulename test, skipping:\n\t($@)\n";
  $self->{rule_errors}++;
}

sub register_plugin_eval_glue {
  my ($self, $function) = @_;

  if (!$function) {
    warn "rules: empty function name";
    return;
  }

  # only need to call this once per fn (globally)
  return if exists $TEMPORARY_EVAL_GLUE_METHODS{$function};
  $TEMPORARY_EVAL_GLUE_METHODS{$function} = undef;

  # return if it's not an eval_plugin function
  return if (!exists $self->{conf}->{eval_plugins}->{$function});

  # return if it's been registered already
  return if ($self->can ($function) &&
        defined &{'Mail::SpamAssassin::PerMsgStatus::'.$function});

  my $evalstr = <<"ENDOFEVAL";
{
    package Mail::SpamAssassin::PerMsgStatus;

	sub $function {
	  my (\$self) = shift;
	  my \$plugin = \$self->{conf}->{eval_plugins}->{$function};
	  return \$plugin->$function (\$self, \@_);
	}

	1;
}
ENDOFEVAL
  eval $evalstr . '; 1'   ## no critic
  or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "rules: failed to compile method '$function': $eval_stat\n";
    $self->{rule_errors}++;
  };

  # ensure this method is deleted if finish() is called
  push (@TEMPORARY_METHODS, $function);
}

###########################################################################

=item $status-E<gt>clear_test_state()

DEPRECATED, UNNEEDED SINCE 4.0

=cut

sub clear_test_state {}

###########################################################################

# internal API, called only by got_hit()
# TODO: refactor and merge this into that function
sub _handle_hit {
    my ($self, $rule, $score, $area, $ruletype, $desc) = @_;

    $self->{main}->call_plugins ("hit_rule", {
        permsgstatus => $self,
        rulename => $rule,
        ruletype => $ruletype,
        score => $score
      });

    # ignore meta-match sub-rules.
    if (index($rule, '__') == 0) { push(@{$self->{subtest_names_hit}}, $rule); return; }

    # this should not happen; warn about it
    if (!defined $score) {
      warn "rules: score undef for rule '$rule' in '$area' '$desc'";
      return;
    }

    # this should not happen; warn about NaN (bug 3364)
    if ($score != $score) {
      warn "rules: score '$score' for rule '$rule' in '$area' '$desc'";
      return;
    }

    # Add the rule hit to the score
    $self->{score} += $score;

    push(@{$self->{test_names_hit}}, $rule);

    # Save for report processing
    $self->{test_logs}->{$rule}->{area} = $area;
    $self->{test_logs}->{$rule}->{desc} = $desc;
}

sub _wrap_desc {
  my ($self, $desc, $firstlinelength, $prefix) = @_;

  my $firstline = " " x $firstlinelength;
  my $wrapped = Mail::SpamAssassin::Util::wrap($desc, $prefix, $firstline, $self->{conf}->{report_wrap_width}, 0);
  $wrapped =~ s/^\s+//s;
  $wrapped;
}

###########################################################################

=item $status-E<gt>got_hit ($rulename, $desc_prepend [, name =E<gt> value, ...])

Register a hit against a rule in the ruleset.

There are two mandatory arguments. These are C<$rulename>, the name of the rule
that fired, and C<$desc_prepend>, which is a short string that will be
prepended to the rules C<describe> string in output reports.

In addition, callers can supplement that with the following optional
data:

=over 4

=item score =E<gt> $num

Optional: the score to use for the rule hit.  If unspecified,
the value from the C<Mail::SpamAssassin::Conf> object's C<{scores}>
hash will be used (a configured score), and in its absence the
C<defscore> option value.

=item defscore =E<gt> $num

Optional: the score to use for the rule hit if neither the
option C<score> is provided, nor a configured score value is provided.

=item value =E<gt> $num

Optional: the value to assign to the rule; the default value is C<1>.
I<tflags multiple> rules use values of greater than 1 to indicate
multiple hits.  This value is accessible to meta rules.

=item ruletype =E<gt> $type

Optional, but recommended: the rule type string.  This is used in the
C<hit_rule> plugin call, called by this method.  If unset, I<'unknown'> is
used.

=item tflags =E<gt> $string

Optional: a string, i.e. a space-separated list of additional tflags
to be appended to an existing list of flags in $self-E<gt>{conf}-E<gt>{tflags},
such as: "nice noautolearn multiple". No syntax checks are performed.

=item description =E<gt> $string

Optional: a custom rule description string.  This is used in the
C<hit_rule> plugin call, called by this method. If unset, the static
description is used.

=back

Backward compatibility: the two mandatory arguments have been part of this API
since SpamAssassin 2.x. The optional C<name=E<gt>value> pairs, however, are a
new addition in SpamAssassin 3.2.0.

=cut

sub got_hit {
  my ($self, $rule, $area, %params) = @_;

  my $conf_ref = $self->{conf};

  my $dynamic_score_provided;
  my $score = $params{score};
  if (defined $score) {  # overrides any configured scores
    $dynamic_score_provided = 1;
  } else {
    $score = $conf_ref->{scores}->{$rule};
    $score = $params{defscore}  if !defined $score;
  }

  # adding a hit does nothing if we don't have a score -- we probably
  # shouldn't have run it in the first place
  if (!$score) {
    return;
  }

  # ensure that rule values always result in an *increase*
  # of $self->{tests_already_hit}->{$rule}:
  my $value = $params{value};
  if (!$value || $value <= 0) { $value = 1 }

  my $tflags_ref = $conf_ref->{tflags};
  my $tflags_add = $params{tflags};
  if (defined $tflags_add && $tflags_add ne '') {
    $_ = (!defined $_ || $_ eq '') ? $tflags_add : ($_ . ' ' . $tflags_add)
           for $tflags_ref->{$rule};
  };

  my $already_hit = $self->{tests_already_hit}->{$rule} || 0;
  # don't count hits multiple times, unless 'tflags multiple' is on
  if ($already_hit && ($tflags_ref->{$rule}||'') !~ /\bmultiple\b/) {
    return;
  }

  $self->rule_ready($rule, 1); # mark ready for metas
  $self->{tests_already_hit}->{$rule} = $already_hit + $value;

  # default ruletype, if not specified:
  $params{ruletype} ||= 'unknown';

  if ($dynamic_score_provided) {  # copy it to static for proper reporting
    $conf_ref->{scoreset}->[$_]->{$rule} = $score  for (0..3);
    $conf_ref->{scores}->{$rule} = $score;
  }

  my $rule_descr = $params{description};
  if (defined $rule_descr) {
    $conf_ref->{descriptions}->{$rule} = $rule_descr;  # save dynamic descr.
  } else {
    $rule_descr = $conf_ref->get_description_for_rule($rule);  # static
  }
  # Bug 6880 Set Rule Description to something that says no rule
  #$rule_descr = $rule  if !defined $rule_descr || $rule_descr eq '';
  $rule_descr = "No description available." if !defined $rule_descr || $rule_descr eq '';

  if (defined $self->{conf}->{rewrite_header}->{Subject}) {
    my $rule_subjprefix = $conf_ref->{subjprefix}->{$rule};
    if (defined $rule_subjprefix) {
      dbg("subjprefix: setting Subject prefix to $rule_subjprefix");
      $self->{subjprefix} ||= '';
      if (index($self->{subjprefix}, $rule_subjprefix) == -1) {
        $self->{subjprefix} .= $rule_subjprefix . " ";  # save dynamic subject prefix.
      }
    }
  }

  $self->_handle_hit($rule,
            $score,
            $area,
            $params{ruletype},
            $rule_descr);

  return 1;
}

=item $status-E<gt>rule_ready ($rulename [, $no_async])

Mark an asynchronous rule ready, so it can be considered for meta rule
evaluation.  Asynchronous rule is a rule whose eval-function returns undef,
marking that it's not ready yet, expecting results later. 
$status-E<gt>rule_ready() must be called later to mark it ready, alternatively
$status-E<gt>got_hit() also does this.  If neither is called, then any meta rule
that depends on this rule might not evaluate.

Optional boolean $no_async skips checking if there are pending async DNS
lookups for the rule.

=cut

sub rule_ready {
  my ($self, $rule, $no_async) = @_;

  # Ready already?
  return if exists $self->{tests_already_hit}->{$rule};

  if (!$no_async && $self->get_async_pending_rules($rule)) {
    # Can't be ready if there are pending DNS lookups, ignore for now.
    return;
  }

  # record rules that depend on this, so do_meta_tests will be run
  foreach (keys %{$self->{conf}->{meta_deprules}->{$rule}}) {
    $self->{meta_check_ready}->{$_} = 1;
  }

  # mark ready
  $self->{tests_already_hit}->{$rule} ||= 0;
}

###########################################################################

=item $status-E<gt>test_log ($text [, $rulename])

Add $text log entry for a hit rule in final message REPORT/SUMMARY.

Usually called just before got_hit(), to describe for example what URI the
rule matched on.  Optional C<$rulename> argument is recommended to make sure
log is written to correct rule.  If rulename is not provided,
get_current_eval_rule_name() is used as fallback.

Can be called multiple times per rule for additional entries.

=cut

sub test_log {
  my ($self, $msg, $rulename) = @_;
  $rulename ||= $self->get_current_eval_rule_name();
  return if !defined $rulename;
  push @{$self->{test_logs}->{$rulename}->{msg}}, $msg;
}

###########################################################################

# helper for get()
sub get_envelope_from {
  my ($self) = @_;

  # Cached?
  return $self->{envelopefrom} if exists $self->{envelopefrom};

  # bug 2142:
  # Get the SMTP MAIL FROM:, aka. the "envelope sender", if our
  # calling app has helpfully marked up the source message
  # with it.  Various MTAs and calling apps each have their
  # own idea of what header to use for this!   see

  my $envf;

  # Rely on the 'envelope-sender-header' header if the user has configured one.
  # Assume that because they have configured it, their MTA will always add it.
  # This will prevent us falling through and picking up inappropriate headers.
  if (defined $self->{conf}->{envelope_sender_header}) {
    # get the most recent (topmost) copy - there can be only one EnvelopeSender.
    $envf = ($self->get($self->{conf}->{envelope_sender_header}.":first:addr"))[0];
    # ok if it contains an "@" sign, or is "" (ie. "<>" without the < and >)
    if (defined $envf && (index($envf, '@') > 0 || $envf eq '')) {
      dbg("message: using envelope_sender_header '%s' as EnvelopeFrom: '%s'",
          $self->{conf}->{envelope_sender_header}, $envf);
      $self->{envelopefrom} = $envf;
      return $envf;
    }
    # Warn them if it's configured, but not there or not usable.
    if (defined $envf) {
      dbg("message: envelope_sender_header '%s': '%s' is not valid, ignoring",
          $self->{conf}->{envelope_sender_header}, $envf);
    } else {
      dbg("message: envelope_sender_header '%s' not found in message",
          $self->{conf}->{envelope_sender_header});
    }
    # Couldn't get envelope-sender using the configured header.
    $self->{envelopefrom} = undef;
    return;
  }

  # User hasn't given us a header to trust, so try to guess the sender.

  # use the "envelope-sender" string found in the Received headers,
  # if possible... use the last untrusted header, in case there's
  # trusted headers.
  my $lasthop = $self->{relays_untrusted}->[0];
  my $lasthop_str = 'last untrusted';
  if (!defined $lasthop) {
    # no untrusted headers?  in that case, the message is ALL_TRUSTED.
    # use the first trusted header (ie. the oldest, originating one).
    $lasthop = $self->{relays_trusted}->[-1];
    $lasthop_str = 'first trusted';
  }

  if (defined $lasthop) {
    $envf = $lasthop->{envfrom};
    # ok if it contains an "@" sign, or is "" (ie. "<>" without the < and >)
    if (defined $envf && (index($envf, '@') > 0 || $envf eq '')) {
      dbg("message: using $lasthop_str relay envelope-from as EnvelopeFrom: '$envf'");
      $self->{envelopefrom} = $envf;
      return $envf;
    }
  }

  # WARNING: a lot of list software adds an X-Sender for the original env-from
  # (including Yahoo! Groups).  Unfortunately, fetchmail will pick it up and
  # reuse it as the env-from for *its* delivery -- even though the list
  # software had used a different env-from in the intervening delivery.  Hence,
  # if this header is present, and there's a fetchmail sig in the Received
  # lines, we cannot trust any Envelope-From headers, since they're likely to
  # be incorrect fetchmail guesses.

  my $x_sender = ($self->get("X-Sender:first:addr"))[0];
  if (defined $x_sender && index($x_sender, '@') != -1) {
    foreach ($self->get("Received")) {
      if (index($_, '(fetchmail') != -1) {
        dbg("message: X-Sender and fetchmail signatures found, cannot trust envelope-from");
        $self->{envelopefrom} = undef;
        return;
      }
    }
  }

  # procmailrc notes this (we now recommend adding it to Received instead)
  if (defined($envf = ($self->get("X-Envelope-From:first:addr"))[0])) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get("ALL") =~ /^Received:.*?^X-Envelope-From:/smi) {
      dbg("message: X-Envelope-From header found after 1 or more Received lines, cannot trust envelope-from");
      $self->{envelopefrom} = undef;
      return;
    } else {
      dbg("message: using X-Envelope-From header as EnvelopeFrom: '$envf'");
      $self->{envelopefrom} = $envf;
      return $envf;
    }
  }

  # qmail, new-inject(1)
  if (defined($envf = ($self->get("Envelope-Sender:first:addr"))[0])) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get("ALL") =~ /^Received:.*?^Envelope-Sender:/smi) {
      dbg("message: Envelope-Sender header found after 1 or more Received lines, cannot trust envelope-from");
    } else {
      dbg("message: using Envelope-Sender header as EnvelopeFrom: '$envf'");
      $self->{envelopefrom} = $envf;
      return $envf;
    }
  }

  # Postfix, sendmail, amavisd-new, ...
  # RFC 2821 requires it:
  #   When the delivery SMTP server makes the "final delivery" of a
  #   message, it inserts a return-path line at the beginning of the mail
  #   data.  This use of return-path is required; mail systems MUST support
  #   it.  The return-path line preserves the information in the <reverse-
  #   path> from the MAIL command.
  if (defined($envf = ($self->get("Return-Path:first:addr"))[0])) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get("ALL") =~ /^Received:.*?^Return-Path:/smi) {
      dbg("message: Return-Path header found after 1 or more Received lines, cannot trust envelope-from");
    } else {
      dbg("message: using Return-Path header as EnvelopeFrom: '$envf'");
      $self->{envelopefrom} = $envf;
      return $envf;
    }
  }

  # give up.
  $self->{envelopefrom} = undef;
  return;
}

###########################################################################

# helper for get(ALL-*).  get() caches its results, so don't call this
# directly unless you need a range of headers not covered by the ALL-*
# psuedo-headers!

# Get all the headers found between an index range of received headers, the
# index doesn't care if we could parse the received headers or not.
# Use undef for the $start_rcvd or $end_rcvd numbers to start/end with the
# first/last header in the message, otherwise indicate the index number you
# want to start/end at.  Set $include_start_rcvd or $include_end_rcvd to 0 to
# indicate you don't want to include the received header found at the start or
# end indexes... basically toggles between [s,e], [s,e), (s,e], (s,e).
sub get_all_hdrs_in_rcvd_index_range {
  my ($self, $start_rcvd, $end_rcvd, $include_start_rcvd, $include_end_rcvd, $getraw) = @_;

  # prevent bad input causing us to return the first header found
  return if (defined $end_rcvd && $end_rcvd < 0);

  $include_start_rcvd = 1 unless defined $include_start_rcvd;
  $include_end_rcvd = 1 unless defined $include_end_rcvd;

  my $cur_rcvd_index = -1;  # none found yet
  my @results;

  my @hdrs;
  if ($getraw) {
    @hdrs = $self->{msg}->get_pristine_header() =~ /^([^ \t].*?\n)(?![ \t])/smgi;
  } else {
    @hdrs = split(/^/m, $self->{msg}->get_all_headers(0));
  }

  foreach my $hdr (@hdrs) {
    if ($hdr =~ /^Received:/i) {
      $cur_rcvd_index++;
      next if (defined $start_rcvd && !$include_start_rcvd &&
		$start_rcvd == $cur_rcvd_index);
      last if (defined $end_rcvd && !$include_end_rcvd &&
		$end_rcvd == $cur_rcvd_index);
    }
    if ((!defined $start_rcvd || $start_rcvd <= $cur_rcvd_index) &&
	(!defined $end_rcvd || $cur_rcvd_index < $end_rcvd)) {
      push @results, $hdr;
    }
    elsif (defined $end_rcvd && $cur_rcvd_index == $end_rcvd) {
      push @results, $hdr;
      last;
    }
  }

  if (wantarray) {
    return @results;
  } else {
    my $result = join('', @results);
    return ($result eq '' ? undef : $result);
  }
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

=item $status-E<gt>create_fulltext_tmpfile (fulltext_ref)

This function creates a temporary file containing the passed scalar
reference data.  If no scalar is passed, full/pristine message text is
assumed.  This is typically used by external programs like pyzor and
dccproc, to avoid hangs due to buffering issues.

All tempfiles are automatically cleaned up by PerMsgStatus destructor.

=cut

sub create_fulltext_tmpfile {
  my ($self, $fulltext) = @_;

  my $pristine;
  if (!defined $fulltext) {
    if (defined $self->{fulltext_tmpfile}) {
      return $self->{fulltext_tmpfile};
    }
    $fulltext = \$self->{msg}->get_pristine();
    $pristine = 1;
  }

  my ($tmpf, $tmpfh) = Mail::SpamAssassin::Util::secure_tmpfile();
  $tmpfh  or die "failed to create a temporary file";

  # record all created files so we can remove on DESTROY
  $self->{tmpfiles}->{$tmpf} = 1;

  # PerlIO's buffered print writes in 8 kB chunks - which can be slow.
  #   print $tmpfh $$fulltext  or die "error writing to $tmpf: $!";
  #
  # reducing the number of writes and bypassing extra buffering in PerlIO
  # speeds up writing of larger text by a factor of 2
  my $nwrites;
  for (my $ofs = 0; $ofs < length($$fulltext); $ofs += $nwrites) {
    $nwrites = $tmpfh->syswrite($$fulltext, length($$fulltext)-$ofs, $ofs);
    defined $nwrites  or die "error writing to $tmpf: $!";
  }
  close $tmpfh  or die "error closing $tmpf: $!";

  $self->{fulltext_tmpfile} = $tmpf  if $pristine;

  dbg("check: create_fulltext_tmpfile, written %d bytes to file %s",
      length($$fulltext), $tmpf);

  return $tmpf;
}

=item $status-E<gt>delete_fulltext_tmpfile (tmpfile)

Will cleanup after a $status-E<gt>create_fulltext_tmpfile() call.  Deletes the
temporary file and uncaches the filename.  Generally there no need to call
this, PerMsgStatus destructor cleans up all tmpfiles.

=cut

sub delete_fulltext_tmpfile {
  my ($self, $tmpfile) = @_;

  $tmpfile = $self->{fulltext_tmpfile} if !defined $tmpfile;
  if (defined $tmpfile && $self->{tmpfiles}->{$tmpfile}) {
    unlink($tmpfile) or dbg("cannot unlink $tmpfile: $!");
    if ($self->{fulltext_tmpfile} &&
          $tmpfile eq $self->{fulltext_tmpfile}) {
      delete $self->{fulltext_tmpfile};
    }
    delete $self->{tmpfiles}->{$tmpfile};
  }
}

###########################################################################

sub all_from_addrs {
  my ($self) = @_;

  if (exists $self->{all_from_addrs}) { return @{$self->{all_from_addrs}}; }

  my @addrs;

  # Resent- headers take priority, if present. see bug 672
  my @resent = $self->get('Resent-From:first:addr');
  if (@resent) {
    @addrs = @resent;
  }
  else {
    # bug 2292: Used to use find_all_addrs_in_line() with the same headers,
    # but the would catch addresses in comments which caused FNs for things
    # like welcomelist_from.  Since all of these are From headers, there
    # should only be 1 address in each anyway (not exactly true, RFC 2822
    # allows multiple addresses in a From header field)
    # *** since 4.0 all addresses are returned from Header correctly ***
    # bug 3366: some addresses come in as 'foo@bar...', which is invalid.
    # so deal with the multiple periods.
    # TODO: 4.0 need :first:addr here ? Why check so many headers ?
    ## no critic
    @addrs = map { tr/././s; $_ } grep { $_ ne '' }
      ($self->get('From:addr'),            # std
       $self->get('Envelope-Sender:addr'), # qmail: new-inject(1)
       $self->get('Resent-Sender:addr'),   # procmailrc manpage
       $self->get('X-Envelope-From:addr'), # procmailrc manpage
       $self->get('EnvelopeFrom:addr'));   # SMTP envelope
    # http://www.cs.tut.fi/~jkorpela/headers.html is useful here
  }

  # Remove duplicate addresses
  my %addrs = map { $_ => 1 } @addrs;
  @addrs = keys %addrs;

  dbg("eval: all '*From' addrs: " . join(" ", @addrs));
  $self->{all_from_addrs} = \@addrs;
  return @addrs;
}

=item all_from_addrs_domains

This function returns all the various from addresses in a message using all_from_addrs()
and then returns only the domain names.

=cut

sub all_from_addrs_domains {
  my ($self) = @_;

  if (exists $self->{all_from_addrs_domains}) {
    return @{$self->{all_from_addrs_domains}};
  }

  #TEST POINT - my @addrs = ("test.voipquotes2.net","test.voipquotes2.co.uk");
  #Start with all the normal from addrs
  my @addrs = all_from_addrs($self);

  dbg("eval: all '*From' addrs domains (before): " . join(" ", @addrs));

  #Take just the domain with a dummy localpart
  #removing invalid and duplicate domains
  my(%addrs_seen, @addrs_filtered);
  foreach my $a (@addrs) {
    my $domain = $self->{main}->{registryboundaries}->uri_to_domain($a);
    next if !defined $domain || $addrs_seen{lc $domain}++;
    push(@addrs_filtered, 'dummy@'.$domain);
  }

  dbg("eval: all '*From' addrs domains (after uri to domain): " .
      join(" ", @addrs_filtered));

  $self->{all_from_addrs_domains} = \@addrs_filtered;

  return @addrs_filtered;
}

sub all_to_addrs {
  my ($self) = @_;

  if (exists $self->{all_to_addrs}) { return @{$self->{all_to_addrs}}; }

  my @addrs;

  # Resent- headers take priority, if present. see bug 672
  my @resent = ( $self->get('Resent-To:first:addr'),
                 $self->get('Resent-Cc:first:addr') );
  if (@resent) {
    @addrs = @resent;
  } else {
    # OK, a fetchmail trick: try to find the recipient address from
    # the most recent 3 Received lines.  This is required for sendmail,
    # since it does not add a helpful header like exim, qmail
    # or Postfix do.
    #
    my @rcvd = ($self->get('Received'))[0 .. 2];
    my @rcvdaddrs;
    foreach my $line (@rcvd) {
      next unless defined $line;
      if ($line =~ / for <?(\S+\@(\S+?))>?;/) {
        if (is_fqdn_valid(idn_to_ascii($2), 1)) {
          push @rcvdaddrs, $1;
        }
      }
    }

    # TODO: 4.0 use :first:addr ? Why so many headers ?
    @addrs = (
      @rcvdaddrs,
      $self->get('To:addr'),                   # std
      $self->get('Apparently-To:addr'),        # sendmail, from envelope
      $self->get('Delivered-To:addr'),         # Postfix, poss qmail
      $self->get('Envelope-Recipients:addr'),  # qmail: new-inject(1)
      $self->get('Apparently-Resent-To:addr'), # procmailrc manpage
      $self->get('X-Envelope-To:addr'),        # procmailrc manpage
      $self->get('Envelope-To:addr'),          # exim
      $self->get('X-Delivered-To:addr'),       # procmail quick start
      $self->get('X-Original-To:addr'),        # procmail quick start
      $self->get('X-Rcpt-To:addr'),            # procmail quick start
      $self->get('X-Real-To:addr'),            # procmail quick start
      $self->get('Cc:addr'));                  # std
    # those are taken from various sources; thanks to Nancy McGough, who
    # noted some in <http://www.ii.com/internet/robots/procmail/qs/#envelope>
  }

  my %seen;
  my @result = grep { !$seen{$_}++ } @addrs;

  dbg("eval: all '*To' addrs: " . join(" ", @result));
  $self->{all_to_addrs} = \@result;
  return @result;

# http://www.cs.tut.fi/~jkorpela/headers.html is useful here, also
# http://www.exim.org/pipermail/exim-users/Week-of-Mon-20001009/021672.html
}

###########################################################################

# Save and tag regex named captures, $captures is ref to %- results
sub set_captures {
  my ($self, $captures) = @_;

  foreach my $cname (keys %$captures) {
    next unless $cname =~ /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/; # safety check
    my @cvals = do { my %seen; grep { !$seen{$_}++ } @{$captures->{$cname}} };
    $self->set_tag($cname, @cvals == 1 ? $cvals[0] : \@cvals);
  }
}

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

Mail::SpamAssassin(3)
spamassassin(1)

