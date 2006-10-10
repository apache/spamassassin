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

  my $spamtest = new Mail::SpamAssassin ({
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
use bytes;

use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::EvalTests;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;

use vars qw{
  @ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg, $opts) = @_;

  my $self = {
    'main'              => $main,
    'msg'               => $msg,
    'score'             => 0,
    'test_logs'         => '',
    'test_names_hit'    => [ ],
    'subtest_names_hit' => [ ],
    'tests_already_hit' => { },
    'hdr_cache'         => { },
    'rule_errors'       => 0,
    'disable_auto_learning' => 0,
    'auto_learn_status' => undef,
    'conf'                => $main->{conf},
  };

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

  bless ($self, $class);
  $self;
}

###########################################################################

=item $status->check ()

Runs the SpamAssassin rules against the message pointed to by the object.

=cut

sub check {
  my ($self) = @_;
  local ($_);

  $self->{learned_points} = 0;
  $self->{body_only_points} = 0;
  $self->{head_only_points} = 0;
  $self->{score} = 0;

  $self->{main}->call_plugins ("check_start", { permsgstatus => $self });

  # in order of slowness; fastest first, slowest last.
  # we do ALL the tests, even if a spam triggers lots of them early on.
  # this lets us see ludicrously spammish mails (score: 40) etc., which
  # we can then immediately submit to spamblocking services.
  #
  # TODO: change this to do whitelist/blacklists first? probably a plan
  # NOTE: definitely need AWL stuff last, for regression-to-mean of score

  # TVD: we may want to do more than just clearing out the headers, but ...
  $self->{msg}->delete_header('X-Spam-.*');

  # Resident Mail::SpamAssassin code will possibly never change score
  # sets, even if bayes becomes available.  So we should do a quick check
  # to see if we should go from {0,1} to {2,3}.  We of course don't need
  # to do this switch if we're already using bayes ... ;)
  my $set = $self->{conf}->get_score_set();
  if (($set & 2) == 0 && $self->{main}->{bayes_scanner}->is_scan_available()) {
    dbg("check: scoreset $set but bayes is available, switching scoresets");
    $self->{conf}->set_score_set ($set|2);
  }

  {
    # bug 4353:
    # Do this before the RBL tests are kicked off.  The metadata parsing
    # will figure out the (un)trusted relays and such, which are used in the
    # rbl calls.
    $self->extract_message_metadata();

    # Here, we launch all the DNS RBL queries and let them run while we
    # inspect the message
    $self->run_rbl_eval_tests ($self->{conf}->{rbl_evals});
    my $needs_dnsbl_harvest_p = 1; # harvest needs to be run

    my $decoded = $self->get_decoded_stripped_body_text_array();
    my $bodytext = $self->get_decoded_body_text_array();
    my $fulltext = $self->{msg}->get_pristine();

    my @uris = $self->get_uri_list();

    foreach my $priority (sort { $a <=> $b } keys %{$self->{conf}->{priorities}}) {
      # no need to run if there are no priorities at this level.  This can
      # happen in Conf.pm when we switch a rules from one priority to another
      next unless ($self->{conf}->{priorities}->{$priority} > 0);

      dbg("check: running tests for priority: $priority");

      # only harvest the dnsbl queries once priority HARVEST_DNSBL_PRIORITY
      # has been reached and then only run once
      if ($priority >= HARVEST_DNSBL_PRIORITY && $needs_dnsbl_harvest_p) {
	# harvest the DNS results
	$self->harvest_dnsbl_queries();
	$needs_dnsbl_harvest_p = 0;

	# finish the DNS results
	$self->rbl_finish();
	$self->{main}->call_plugins ("check_post_dnsbl", { permsgstatus => $self });
       $self->{resolver}->finish_socket() if $self->{resolver};
      }

      # since meta tests must have a priority of META_TEST_MIN_PRIORITY or
      # higher then there is no reason to even call the do_meta_tests method
      # if we are less than that.
      if ($priority >= META_TEST_MIN_PRIORITY) {
	$self->do_meta_tests($priority);
      }

      # do head tests
      $self->do_head_tests($priority);
      $self->do_head_eval_tests($priority);

      $self->do_body_tests($priority, $decoded);
      $self->do_body_uri_tests($priority, @uris);
      $self->do_body_eval_tests($priority, $decoded);
  
      $self->do_rawbody_tests($priority, $bodytext);
      $self->do_rawbody_eval_tests($priority, $bodytext);
  
      $self->do_full_tests($priority, \$fulltext);
      $self->do_full_eval_tests($priority, \$fulltext);

      # we may need to call this more often than once through the loop, but
      # it needs to be done at least once, either at the beginning or the end.
      $self->{main}->call_plugins ("check_tick", { permsgstatus => $self });
    }

    # sanity check, it is possible that no rules >= HARVEST_DNSBL_PRIORITY ran so the harvest
    # may not have run yet.  Check, and if so, go ahead and harvest here.
    if ($needs_dnsbl_harvest_p) {
      # harvest the DNS results
      $self->harvest_dnsbl_queries();

      # finish the DNS results
      $self->rbl_finish();
      $self->{main}->call_plugins ("check_post_dnsbl", { permsgstatus => $self });
      $self->{resolver}->finish_socket() if $self->{resolver};
    }

    # finished running rules
    delete $self->{current_rule_name};
    undef $decoded;
    undef $bodytext;
    undef $fulltext;

    # auto-learning
    $self->learn();
    $self->{main}->call_plugins ("check_post_learn", { permsgstatus => $self });
  }

  # delete temporary storage and memory allocation used during checking
  $self->delete_fulltext_tmpfile();

  # now that we've finished checking the mail, clear out this cache
  # to avoid unforeseen side-effects.
  $self->{hdr_cache} = { };

  # Round the score to 3 decimal places to avoid rounding issues
  # We assume required_score to be properly rounded already.
  # add 0 to force it back to numeric representation instead of string.
  $self->{score} = (sprintf "%0.3f", $self->{score}) + 0;
  
  dbg("check: is spam? score=".$self->{score}.
                        " required=".$self->{conf}->{required_score});
  dbg("check: tests=".$self->get_names_of_tests_hit());
  dbg("check: subtests=".$self->get_names_of_subtests_hit());
  $self->{is_spam} = $self->is_spam();

  $self->{main}->call_plugins ("check_end", { permsgstatus => $self });

  1;
}

###########################################################################

=item $status->learn()

After a mail message has been checked, this method can be called.  If the score
is outside a certain range around the threshold, ie. if the message is judged
more-or-less definitely spam or definitely non-spam, it will be fed into
SpamAssassin's learning systems (currently the naive Bayesian classifier),
so that future similar mails will be caught.

=cut

sub learn {
  my ($self) = @_;

  if (!$self->{conf}->{bayes_auto_learn} ||
      !$self->{conf}->{use_bayes} ||
      $self->{disable_auto_learning})
  {
    $self->{auto_learn_status} = "disabled";
    return;
  }

  my $isspam = $self->{main}->call_plugins ("autolearn_discriminator", {
      permsgstatus => $self
    });

  if (!defined $isspam) {
    $self->{auto_learn_status} = 'no';
    return;
  }

  $self->{main}->call_plugins ("autolearn", {
      permsgstatus => $self,
      isspam => $isspam
    });

  # bug 3704: temporarily override learn's ability to re-learn a message
  my $orig_learner = $self->{main}->init_learner({ "no_relearn" => 1 });

  eval {
    my $learnstatus = $self->{main}->learn ($self->{msg}, undef, $isspam, 0);
    $learnstatus->finish();
    if ($learnstatus->did_learn()) {
      $self->{auto_learn_status} = $isspam ? "spam" : "ham";
    }
    $self->{main}->finish_learner();        # for now

    if (exists $self->{main}->{bayes_scanner}) {
      $self->{main}->{bayes_scanner}->sanity_check_is_untied();
    }
  };

  # reset learner options to their original values
  $self->{main}->init_learner($orig_learner);

  if ($@) {
    dbg("learn: auto-learning failed: $@");
    $self->{auto_learn_status} = "failed";
  }
}

=item $score = $status->get_autolearn_points()

Return the message's score as computed for auto-learning.  Certain tests are
ignored:

  - rules with tflags set to 'learn' (the Bayesian rules)

  - rules with tflags set to 'userconf' (user white/black-listing rules, etc)

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

=item $score = $status->get_head_only_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for header-based ones.

=cut

sub get_head_only_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{head_only_points};
}

=item $score = $status->get_learned_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for learning-based ones.

=cut

sub get_learned_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{learned_points};
}

=item $score = $status->get_body_only_points()

Return the message's score as computed for auto-learning, ignoring
all rules except for body-based ones.

=cut

sub get_body_only_points {
  my ($self) = @_;
  $self->_get_autolearn_points();
  return $self->{body_only_points};
}

sub _get_autolearn_points {
  my ($self) = @_;

  return if (exists $self->{autolearn_points});
  # ensure it only gets computed once, even if we return early
  $self->{autolearn_points} = 0;

  # This function needs to use use sum($score[scoreset % 2]) not just {score}.
  # otherwise we shift what we autolearn on and it gets really wierd.  - tvd
  my $orig_scoreset = $self->{conf}->get_score_set();
  my $new_scoreset = $orig_scoreset;
  my $scores = $self->{conf}->{scores};

  if (($orig_scoreset & 2) == 0) { # we don't need to recompute
    dbg("learn: auto-learn: currently using scoreset $orig_scoreset");
  }
  else {
    $new_scoreset = $orig_scoreset & ~2;
    dbg("learn: auto-learn: currently using scoreset $orig_scoreset, recomputing score based on scoreset $new_scoreset");
    $scores = $self->{conf}->{scoreset}->[$new_scoreset];
  }

  my $tflags = $self->{conf}->{tflags};
  my $points = 0;

  # Just in case this function is called multiple times, clear out the
  # previous calculated values
  $self->{learned_points} = 0;
  $self->{body_only_points} = 0;
  $self->{head_only_points} = 0;

  foreach my $test (@{$self->{test_names_hit}}) {
    # According to the documentation, noautolearn, userconf, and learn
    # rules are ignored for autolearning.
    if (exists $tflags->{$test}) {
      next if $tflags->{$test} =~ /\bnoautolearn\b/;
      next if $tflags->{$test} =~ /\buserconf\b/;

      # Keep track of the learn points for an additional autolearn check.
      # Use the original scoreset since it'll be 0 in sets 0 and 1.
      if ($tflags->{$test} =~ /\blearn\b/) {
	# we're guaranteed that the score will be defined
        $self->{learned_points} += $self->{conf}->{scoreset}->[$orig_scoreset]->{$test};
	next;
      }
    }

    # ignore tests with 0 score in this scoreset
    next if ($scores->{$test} == 0);

    # Go ahead and add points to the proper locations
    if (!$self->{conf}->maybe_header_only ($test)) {
      $self->{body_only_points} += $scores->{$test};
    }
    if (!$self->{conf}->maybe_body_only ($test)) {
      $self->{head_only_points} += $scores->{$test};
    }

    $points += $scores->{$test};
  }

  # Figure out the final value we'll use for autolearning
  $points = (sprintf "%0.3f", $points) + 0;
  dbg("learn: auto-learn: message score: ".$self->{score}.", computed score for autolearn: $points");

  $self->{autolearn_points} = $points;
}

###########################################################################

=item $isspam = $status->is_spam ()

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

=item $list = $status->get_names_of_tests_hit ()

After a mail message has been checked, this method can be called. It will
return a comma-separated string, listing all the symbolic test names
of the tests which were trigged by the mail.

=cut

sub get_names_of_tests_hit {
  my ($self) = @_;

  return join(',', sort(@{$self->{test_names_hit}}));
}

###########################################################################

=item $list = $status->get_names_of_subtests_hit ()

After a mail message has been checked, this method can be called.  It will
return a comma-separated string, listing all the symbolic test names of the
meta-rule sub-tests which were trigged by the mail.  Sub-tests are the
normally-hidden rules, which score 0 and have names beginning with two
underscores, used in meta rules.

=cut

sub get_names_of_subtests_hit {
  my ($self) = @_;

  return join(',', sort(@{$self->{subtest_names_hit}}));
}

###########################################################################

=item $num = $status->get_score ()

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

=item $num = $status->get_required_score ()

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

=item $num = $status->get_autolearn_status ()

After a mail message has been checked, this method can be called.  It will
return one of the following strings depending on whether the mail was
auto-learned or not: "ham", "no", "spam", "disabled", "failed", "unavailable".

=cut

sub get_autolearn_status {
  my ($self) = @_;
  return ($self->{auto_learn_status} || "unavailable");
}

###########################################################################

=item $report = $status->get_report ()

Deliver a "spam report" on the checked mail message.  This contains details of
how many spam detection rules it triggered.

The report is returned as a multi-line string, with the lines separated by
C<\n> characters.

=cut

sub get_report {
  my ($self) = @_;

  if (!exists $self->{'report'}) {
    my $report;
    $report = $self->{conf}->{report_template};
    $report ||= '(no report template found)';

    $report = $self->_replace_tags($report);

    $report =~ s/\n*$/\n\n/s;
    $self->{report} = $report;
  }

  return $self->{report};
}

###########################################################################

=item $preview = $status->get_content_preview ()

Give a "preview" of the content.

This is returned as a multi-line string, with the lines separated by C<\n>
characters, containing a fully-decoded, safe, plain-text sample of the first
few lines of the message body.

=cut

sub get_content_preview {
  my ($self) = @_;

  my $str = '';
  my $ary = $self->get_decoded_stripped_body_text_array();
  shift @{$ary};                # drop the subject line

  my $numlines = 3;
  while (length ($str) < 200 && @{$ary} && $numlines-- > 0) {
    $str .= shift @{$ary};
  }
  undef $ary;
  chomp ($str); $str .= " [...]\n";

  # in case the last line was huge, trim it back to around 200 chars
  $str =~ s/^(.{,200}).*$/$1/gs;

  # now, some tidy-ups that make things look a bit prettier
  $str =~ s/-----Original Message-----.*$//gs;
  $str =~ s/This is a multi-part message in MIME format\.//gs;
  $str =~ s/[-_\*\.]{10,}//gs;
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

=item $msg = $status->get_message()

Return the object representing the message being scanned.

=cut

sub get_message {
  my ($self) = @_;
  return $self->{msg};
}

###########################################################################

=item $status->rewrite_mail ()

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

  my $msg = $self->{msg}->get_mbox_separator() || '';

  if ($self->{is_spam} && $self->{conf}->{report_safe}) {
    $msg .= $self->rewrite_report_safe();
  }
  else {
    $msg .= $self->rewrite_no_report_safe();
  }

  # Make the line endings appropriate for the situation
  if ($self->{msg}->{line_ending} ne "\n") {
    $msg =~ s/\r?\n/$self->{msg}->{line_ending}/g;
  }

  return $msg;
}

# rewrite the message in report_safe mode
# should not be called directly, use rewrite_mail instead
#
sub rewrite_report_safe {
  my ($self) = @_;

  # This is the original message.  We do not want to make any modifications so
  # we may recover it if necessary.  It will be put into the new message as a
  # message/rfc822 MIME part.
  my $original = $self->{msg}->get_pristine();

  # This is the new message.
  my $newmsg = '';

  # the report charset
  my $report_charset = "";
  if ($self->{conf}->{report_charset}) {
    $report_charset = "; charset=" . $self->{conf}->{report_charset};
  }

  # the SpamAssassin report
  my $report = $self->get_report();

  # get original headers, "pristine" if we can do it
  my $from = $self->{msg}->get_pristine_header("From");
  my $to = $self->{msg}->get_pristine_header("To");
  my $cc = $self->{msg}->get_pristine_header("Cc");
  my $subject = $self->{msg}->get_pristine_header("Subject");
  my $msgid = $self->{msg}->get_pristine_header('Message-Id');
  my $date = $self->{msg}->get_pristine_header("Date");

  # It'd be nice to do this with a foreach loop, but with only three
  # possibilities right now, it's easier not to...

  if ($self->{conf}->{rewrite_header}->{Subject}) {
    $subject ||= "\n";
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{Subject});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $subject =~ s/^(?:\Q${tag}\E )?/${tag} /g; # For some reason the tag may already be there!?
  }

  if ($self->{conf}->{rewrite_header}->{To}) {
    $to ||= "\n";
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{To});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $to =~ s/(?:\t\Q(${tag})\E)?$/\t(${tag})/
  }

  if ($self->{conf}->{rewrite_header}->{From}) {
    $from ||= "\n";
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{From});
    $tag =~ s/\n+//gs; # strip tag's newlines
    $from =~ s/(?:\t\Q(${tag})\E)?$/\t(${tag})/
  }

  # add report headers to message
  $newmsg .= "From: $from" if $from;
  $newmsg .= "To: $to" if $to;
  $newmsg .= "Cc: $cc" if $cc;
  $newmsg .= "Subject: $subject" if $subject;
  $newmsg .= "Date: $date" if $date;
  $newmsg .= "Message-Id: $msgid" if $msgid;

  foreach my $header (keys %{$self->{conf}->{headers_spam}}) {
    my $data = $self->{conf}->{headers_spam}->{$header};
    my $line = $self->_process_header($header,$data);
    $line = $self->qp_encode_header($line);
    $newmsg .= "X-Spam-$header: $line\n" # add even if empty
  }

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

  my $description = $self->{main}->{'encapsulated_content_description'};

  # Note: the message should end in blank line since mbox format wants
  # blank line at end and messages may be concatenated!  In addition, the
  # x-spam-type parameter is fixed since we will use it later to recognize
  # original messages that can be extracted.
  $newmsg .= <<"EOM";
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="$boundary"

This is a multi-part message in MIME format.

--$boundary
Content-Type: text/plain$report_charset
Content-Disposition: inline
Content-Transfer-Encoding: 8bit

$report

--$boundary
Content-Type: $type; x-spam-type=original
Content-Description: $description
Content-Disposition: $disposition
Content-Transfer-Encoding: 8bit

$original
--$boundary--

EOM
  
  return $newmsg;
}

# rewrite the message in non-report_safe mode (just headers)
# should not be called directly, use rewrite_mail instead
#
sub rewrite_no_report_safe {
  my ($self) = @_;

  # put the pristine headers into an array
  # skip the X-Spam- headers, but allow the X-Spam-Prev headers to remain.
  # since there may be a missing header/body 
  #
  my @pristine_headers = split(/^/m, $self->{msg}->get_pristine_header());
  for (my $line = 0; $line <= $#pristine_headers; $line++) {
    next unless ($pristine_headers[$line] =~ /^X-Spam-(?!Prev-)/i);
    splice @pristine_headers, $line, 1 while ($pristine_headers[$line] =~ /^(?:X-Spam-(?!Prev-)|\s+\S)/i);
    $line--;
  }
  my $separator = '';
  if ($pristine_headers[$#pristine_headers] =~ /^\s*$/) {
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

        s/^([^:]+:)[ \t]*(?:\Q${tag}\E )?/$1 ${tag} /i;
      }

      $addition = 'headers_spam';
  }

  # Break the pristine header set up into two blocks; "pre" is the stuff that
  # we want to ensure comes before any SpamAssassin markup headers, like the
  # Return-Path header (see bug 3409).
  #
  # "post" is all the rest of the message headers, placed after the
  # SpamAssassin markup hdrs. Once one of those headers is seen, all further
  # headers go into that set; it's assumed that it's an old copy of the
  # header, or attempted spoofing, if it crops up halfway through the
  # headers.

  my $new_hdrs_pre = '';
  my $new_hdrs_post = '';
  foreach my $hdr (@pristine_headers) {
    if ($new_hdrs_post eq '' && $hdr =~ /^Return-Path:/i) {
      $new_hdrs_pre .= $hdr;
    } else {
      $new_hdrs_post .= $hdr;
    }
  }

  # use string appends to put this back together -- I finally benchmarked it.
  # join() is 56% of the speed of just using string appends. ;)
  while (my ($header, $data) = each %{$self->{conf}->{$addition}}) {
    my $line = $self->_process_header($header,$data);
    $line = $self->qp_encode_header($line);
    $new_hdrs_pre .= "X-Spam-$header: $line\n";
  }

  return $new_hdrs_pre.$new_hdrs_post.$separator.
            $self->{msg}->get_pristine_body();
}

sub qp_encode_header {
  my ($self, $text) = @_;

  # do nothing unless there's an 8-bit char
  return $text unless ($text =~ /[\x80-\xff]/);

  my $cs = 'ISO-8859-1';
  if ($self->{report_charset}) {
    $cs = $self->{report_charset};
  }

  my @hexchars = split('', '0123456789abcdef');
  my $ord;
  $text =~ s{([\x80-\xff])}{
		$ord = ord $1;
		'='.$hexchars[($ord & 0xf0) >> 4].$hexchars[$ord & 0x0f]
	}ges;

  $text = '=?'.$cs.'?Q?'.$text.'?=';

  dbg("markup: encoding header in $cs: $text");
  return $text;
}

sub _process_header {
  my ($self, $hdr_name, $hdr_data) = @_;

  $hdr_data = $self->_replace_tags($hdr_data);
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
      $hdr =~ s/^\t\n//gm;
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
  $text =~ s{(_(\w+?)(?:\((.*?)\))?_)}{
	my $full = $1;
        my $tag = $2;
        my $result = $self->_get_tag($tag,$3);
        (defined $result) ? $result : $full;
      }ge;

  return $text;
}

sub bayes_report_make_list {
  my $self = shift;
  my $info = shift;
  my $param = shift || "5";
  my ($limit,$fmt_arg,$more) = split /,/, $param;

  return "Tokens not available." unless defined $info;

  my %formats =
    ( short => '$t',
      Short => 'Token: \"$t\"',
      compact => '$p-$D--$t',
      Compact => 'Probability $p -declassification distance $D (\"+\" means > 9) --token: \"$t\"',
      medium => '$p-$D-$N--$t',
      long => '$p-$d--${h}h-${s}s--${a}d--$t',
      Long => 'Probability $p -declassification distance $D --in ${h} ham messages -and ${s} spam messages --$a} days old--token:\"$t\"'
                );

  my $allow_user_defined = 0;
  my $raw_fmt =   !$fmt_arg ? '$p-$D--$t'
                : $allow_user_defined && $fmt_arg =~ m/^\"([^"]+)\"/ ? $1
                : $formats{$fmt_arg};

  return "Invalid format, must be one of: ".join(",",keys %formats)
    unless defined $raw_fmt;

  my $fmt = '"'.$raw_fmt.'"';
  my $amt = $limit < @$info ? $limit : @$info;
  return "" unless $amt;

  my $Bayes = $self->{main}{bayes_scanner};
  my $ns = $self->{bayes_nspam};
  my $nh = $self->{bayes_nham};
  my $digit = sub { $_[0] > 9 ? "+" : $_[0] };
  my $now = time;

  join ', ', map {
    my($t,$prob,$s,$h,$u) = @$_;
    my $a = int(($now - $u)/(3600 * 24));
    my $d = $Bayes->compute_declassification_distance($ns,$nh,$s,$h,$prob);
    my $p = sprintf "%.3f", $prob;
    my $n = $s + $h;
    my ($c,$o) = $prob < 0.5 ? ($h,$s) : ($s,$h);
    my ($D,$S,$H,$C,$O,$N) = map &$digit($_), ($d,$s,$h,$c,$o,$n);
    eval $fmt;
  } @{$info}[0..$amt-1];
}

###########################################################################

# public API for plugins

=item $status->set_tag($tagname, $value)

Set a template tag, as used in C<add_header>, report templates, etc. This API
is intended for use by plugins.   Tag names will be converted to an
all-uppercase representation internally.

C<$value> can be a subroutine reference, which will be evaluated each time
the template is expanded.  Note that perl supports closures, which means
that variables set in the caller's scope can be accessed inside this C<sub>.
For example:

    my $text = "hello world!";
    $status->set_tag("FOO", sub {
              return $text;
            });

See C<Mail::SpamAssassin::Conf>'s C<TEMPLATE TAGS> section for more details on
how template tags are used.

=cut

sub set_tag {
  my $self = shift;
  my $tag  = uc shift;
  my $val  = shift;

  $self->{tag_data}->{$tag} = $val;
}

# public API for plugins

=item $string = $status->get_tag($tagname)

Get the current value of a template tag, as used in C<add_header>, report
templates, etc. This API is intended for use by plugins.  Tag names will be
converted to an all-uppercase representation internally.  See
C<Mail::SpamAssassin::Conf>'s C<TEMPLATE TAGS> section for more details on
tags.

C<undef> will be returned if a tag by that name has not been defined.

=cut

sub get_tag {
  # expose this previously-private API
  return shift->_get_tag(uc shift);
}

###########################################################################

sub _get_tag_value_for_yesno {
  my $self   = shift;
  
  return $self->{is_spam} ? "Yes" : "No";
}

sub _get_tag_value_for_score {
  my ($self, $pad) = @_;

  my $score  = sprintf("%2.1f", $self->{score});
  my $rscore = $self->_get_tag_value_for_required_score();

  # padding
  if (defined $pad && $pad =~ /^(0+| +)$/) {
    my $count = length($1) + 3 - length($score);
    $score = (substr($pad, 0, $count) . $score) if $count > 0;
  }

  # bug 2607: Do some rounding tricks to avoid the 5.0!=5.0-phenomenon,
  return $score if $self->{is_spam} or $score < $rscore;
  return $rscore - 0.1;
}

sub _get_tag_value_for_required_score {
  my $self  = shift;
  return sprintf("%2.1f", $self->{conf}->{required_score});
}

sub _get_tag {
  my $self = shift;
  my $tag = shift;
  my %tags;

  # tag data also comes from $self->{tag_data}->{TAG}

  $tag = "" unless defined $tag; # can be "0", so use defined test

  %tags = ( YESNO     => sub {    $self->_get_tag_value_for_yesno() },
  
            YESNOCAPS => sub { uc $self->_get_tag_value_for_yesno() },

            SCORE => sub { $self->_get_tag_value_for_score(shift) },
            HITS  => sub { $self->_get_tag_value_for_score(shift) },

            REQD  => sub { $self->_get_tag_value_for_required_score() },

            VERSION => \&Mail::SpamAssassin::Version,

            SUBVERSION => sub { $Mail::SpamAssassin::SUB_VERSION },

            HOSTNAME => sub {
	      $self->{conf}->{report_hostname} ||
	      Mail::SpamAssassin::Util::fq_hostname();
	    },

	    REMOTEHOSTNAME => sub {
	      $self->{tag_data}->{'REMOTEHOSTNAME'} ||
	      "localhost";
	    },
	    REMOTEHOSTADDR => sub {
	      $self->{tag_data}->{'REMOTEHOSTADDR'} ||
	      "127.0.0.1";
	    },

            CONTACTADDRESS => sub { $self->{conf}->{report_contact}; },

            BAYES => sub {
              defined($self->{bayes_score}) ?
                        sprintf("%3.4f", $self->{bayes_score}) : "0.5"
            },

            HAMMYTOKENS => sub {
              $self->bayes_report_make_list
                ( $self->{bayes_token_info_hammy}, shift );
            },

            SPAMMYTOKENS => sub {
              $self->bayes_report_make_list
                ( $self->{bayes_token_info_spammy}, shift );
            },

            TOKENSUMMARY => sub {
              if( defined $self->{tag_data}{BAYESTC} )
                {
                  my $tcount_neutral = $self->{tag_data}{BAYESTCLEARNED}
                    - $self->{tag_data}{BAYESTCSPAMMY}
                    - $self->{tag_data}{BAYESTCHAMMY};
                  my $tcount_new = $self->{tag_data}{BAYESTC}
                    - $self->{tag_data}{BAYESTCLEARNED};
                  "Tokens: new, $tcount_new; "
                    ."hammy, $self->{tag_data}{BAYESTCHAMMY}; "
                    ."neutral, $tcount_neutral; "
                    ."spammy, $self->{tag_data}{BAYESTCSPAMMY}."
                } else {
                  "Bayes not run.";
                }
            },

            DATE => \&Mail::SpamAssassin::Util::time_to_rfc822_date,

            STARS => sub {
              my $arg = (shift || "*");
              my $length = int($self->{score});
              $length = 50 if $length > 50;
              return $arg x $length;
            },

            AUTOLEARN => sub { return $self->get_autolearn_status(); },

            TESTS => sub {
              my $arg = (shift || ',');
              return (join($arg, sort(@{$self->{test_names_hit}})) || "none");
            },

            TESTSSCORES => sub {
              my $arg = (shift || ",");
              my $line = '';
              foreach my $test (sort @{$self->{test_names_hit}}) {
                if (!$line) {
                  $line .= $test . "=" . $self->{conf}->{scores}->{$test};
                } else {
                  $line .= $arg . $test . "=" . $self->{conf}->{scores}->{$test};
                }
              }
              return $line ? $line : 'none';
            },

            PREVIEW => sub { $self->get_content_preview() },

            REPORT => sub {
              return "\n" . ($self->{tag_data}->{REPORT} || "");
            },

          );

  my $data;
  if (exists $tags{$tag}) {
    $data = $tags{$tag}->(@_);
  }
  elsif (exists($self->{tag_data}->{$tag})) {
    $data = $self->{tag_data}->{$tag};
    if (ref $data eq 'CODE') {
      $data = $data->(@_);
    }
  }
  # known valid tags that might not get defined in some circumstances
  elsif ($tag !~ /^(?:BAYESTC(?:|LEARNED|SPAMMY|HAMMY)|RBL)$/) {
    return;
  }
  $data = "" unless defined $data;
  return $data;
}

###########################################################################

=item $status->finish ()

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

  foreach(keys %{$self}) {
    delete $self->{$_};
  }
}

sub finish_tests {
  my ($conf) = @_;

  foreach my $priority (keys %{$conf->{priorities}}) {
    # clean up priority value so it can be used in a subroutine name
    my $clean_priority;
    ($clean_priority = $priority) =~ s/-/neg/;

    if (defined &{'_head_tests_'.$clean_priority}) {
      undef &{'_head_tests_'.$clean_priority};
    }
    if (defined &{'_body_tests_'.$clean_priority}) {
      undef &{'_body_tests_'.$clean_priority};
    }
    if (defined &{'_body_uri_tests_'.$clean_priority}) {
      undef &{'_body_uri_tests_'.$clean_priority};
    }
    if (defined &{'_rawbody_tests_'.$clean_priority}) {
      undef &{'_rawbody_tests_'.$clean_priority};
    }
    if (defined &{'_full_tests_'.$clean_priority}) {
      undef &{'_full_tests_'.$clean_priority};
    }
    if (defined &{'_meta_tests_'.$clean_priority}) {
      undef &{'_meta_tests_'.$clean_priority};
    }
  }
}


=item $name = $status->get_current_eval_rule_name()

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
  
  $self->{msg}->extract_message_metadata($self->{main});

  foreach my $item (qw(
	relays_trusted relays_trusted_str num_relays_trusted
	relays_untrusted relays_untrusted_str num_relays_untrusted
	relays_internal relays_internal_str num_relays_internal
	relays_external relays_external_str num_relays_external
        num_relays_unparseable
	))
  {
    $self->{$item} = $self->{msg}->{metadata}->{$item};
  }

  $self->{tag_data}->{RELAYSTRUSTED} = $self->{relays_trusted_str};
  $self->{tag_data}->{RELAYSUNTRUSTED} = $self->{relays_untrusted_str};
  $self->{tag_data}->{RELAYSINTERNAL} = $self->{relays_internal_str};
  $self->{tag_data}->{RELAYSEXTERNAL} = $self->{relays_external_str};
  $self->{tag_data}->{LANGUAGES} = $self->{msg}->get_metadata("X-Languages");

  # This should happen before we get called, but just in case.
  if (!defined $self->{msg}->{metadata}->{html}) {
    $self->get_decoded_stripped_body_text_array();
  }
  $self->{html} = $self->{msg}->{metadata}->{html};

  # allow plugins to add more metadata, read the stuff that's there, etc.
  $self->{main}->call_plugins ("parsed_metadata", { permsgstatus => $self });
}

###########################################################################

sub get_decoded_body_text_array {
  return $_[0]->{msg}->get_decoded_body_text_array();
}

sub get_decoded_stripped_body_text_array {
  return $_[0]->{msg}->get_rendered_body_text_array();
}

###########################################################################

=item $status->get (header_name [, default_value])

Returns a message header, pseudo-header, real name or address.
C<header_name> is the name of a mail header, such as 'Subject', 'To',
etc.  If C<default_value> is given, it will be used if the requested
C<header_name> does not exist.

Appending C<:raw> to the header name will inhibit decoding of quoted-printable
or base-64 encoded strings.

Appending C<:addr> to the header name will cause everything except
the first email address to be removed from the header.  For example,
all of the following will result in "example@foo":

=over 4

=item example@foo

=item example@foo (Foo Blah)

=item example@foo, example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah <example@foo>

=item "Foo Blah" <example@foo>

=item "'Foo Blah'" <example@foo>

=back

Appending C<:name> to the header name will cause everything except
the first real name to be removed from the header.  For example,
all of the following will result in "Foo Blah"

=over 4

=item example@foo (Foo Blah)

=item example@foo (Foo Blah), example@bar

=item display: example@foo (Foo Blah), example@bar ;

=item Foo Blah <example@foo>

=item "Foo Blah" <example@foo>

=item "'Foo Blah'" <example@foo>

=back

There are several special pseudo-headers that can be specified:

=over 4

=item C<ALL> can be used to mean the text of all the message's headers.

=item C<ToCc> can be used to mean the contents of both the 'To' and 'Cc'
headers.

=item C<EnvelopeFrom> is the address used in the 'MAIL FROM:' phase of the SMTP
transaction that delivered this message, if this data has been made available
by the SMTP server.

=item C<MESSAGEID> is a symbol meaning all Message-Id's found in the message;
some mailing list software moves the real 'Message-Id' to 'Resent-Message-Id'
or 'X-Message-Id', then uses its own one in the 'Message-Id' header.  The value
returned for this symbol is the text from all 3 headers, separated by newlines.

=item C<X-Spam-Relays-Untrusted> is the generated metadata of untrusted relays
the message has passed through

=item C<X-Spam-Relays-Trusted> is the generated metadata of trusted relays
the message has passed through

=back

=cut

# only uses two arguments, ignores $defval
sub _get {
  my ($self, $request) = @_;

  my $result;
  my $getaddr = 0;
  my $getname = 0;
  my $getraw = 0;

  # special queries
  if (index($request, ':') != -1) {
    $getaddr = ($request =~ s/:addr$//);
    $getname = ($request =~ s/:name$//);
    $getraw = ($request =~ s/:raw$//);
  }

  # ALL: entire raw headers
  if ($request eq 'ALL') {
    $result = $self->{msg}->get_all_headers(1);
  }
  # EnvelopeFrom: the SMTP MAIL FROM: address
  elsif ($request eq 'EnvelopeFrom') {
    $result = $self->get_envelope_from();
  }
  # untrusted relays list, as string
  elsif ($request eq 'X-Spam-Relays-Untrusted') {
    $result = $self->{relays_untrusted_str};
  }
  # trusted relays list, as string
  elsif ($request eq 'X-Spam-Relays-Trusted') {
    $result = $self->{relays_trusted_str};
  }
  # external relays list, as string
  elsif ($request eq 'X-Spam-Relays-External') {
    $result = $self->{relays_external_str};
  }
  # internal relays list, as string
  elsif ($request eq 'X-Spam-Relays-Internal') {
    $result = $self->{relays_internal_str};
  }
  # ToCc: the combined recipients list
  elsif ($request eq 'ToCc') {
    $result = join("\n", $self->{msg}->get_header('To', $getraw));
    if ($result) {
      chomp $result;
      $result .= ", " if $result =~ /\S/;
    }
    $result .= join("\n", $self->{msg}->get_header('Cc', $getraw));
    $result = undef if !$result;
  }
  # MESSAGEID: handle lists which move the real message-id to another
  # header for resending.
  elsif ($request eq 'MESSAGEID') {
    $result = join("\n", grep { defined($_) && length($_) > 0 }
		   $self->{msg}->get_header('X-Message-Id', $getraw),
		   $self->{msg}->get_header('Resent-Message-Id', $getraw),
		   $self->{msg}->get_header('X-Original-Message-ID', $getraw),
		   $self->{msg}->get_header('Message-Id', $getraw));
  }
  # a conventional header
  else {
    $result = join('', $self->{msg}->get_header($request, $getraw));

    # metadata
    if (!$result) {
      $result = $self->{msg}->get_metadata($request);
      $result = undef if !$result;
    }
  }
      
  # special queries
  if (defined $result && ($getaddr || $getname)) {
    $result =~ s/^[^:]+:(.*);\s*$/$1/gs;	# 'undisclosed-recipients: ;'
    $result =~ s/\s+/ /g;			# reduce whitespace
    $result =~ s/^\s+//;			# leading whitespace
    $result =~ s/\s+$//;			# trailing whitespace

    if ($getaddr) {
      # Get the email address out of the header
      # All of these should result in "jm@foo":
      # jm@foo
      # jm@foo (Foo Blah)
      # jm@foo, jm@bar
      # display: jm@foo (Foo Blah), jm@bar ;
      # Foo Blah <jm@foo>
      # "Foo Blah" <jm@foo>
      # "'Foo Blah'" <jm@foo>
      # "_$B!z8=6b$=$N>l$GEv$?$j!*!zEv_(B_$B$?$k!*!)$/$8!z7|>^%\%s%P!<!z_(B" <jm@foo>  (bug 3979)
      #
      # strip out the (comments)
      $result =~ s/\s*\(.*?\)//g;
      # strip out the "quoted text"
      $result =~ s/(?<!<)"[^"]*"(?!@)//g;
      # Foo Blah <jm@xxx> or <jm@xxx>
      $result =~ s/^[^<]*?<(.*?)>.*$/$1/;
      # multiple addresses on one line? remove all but first
      $result =~ s/,.*$//;
    }
    elsif ($getname) {
      # Get the real name out of the header
      # All of these should result in "Foo Blah":
      #
      # jm@foo (Foo Blah)
      # jm@foo (Foo Blah), jm@bar
      # display: jm@foo (Foo Blah), jm@bar ;
      # Foo Blah <jm@foo>
      # "Foo Blah" <jm@foo>
      # "'Foo Blah'" <jm@foo>
      #
      $result =~ s/^[\'\"]*(.*?)[\'\"]*\s*<.+>\s*$/$1/g
	  or $result =~ s/^.+\s\((.*?)\)\s*$/$1/g; # jm@foo (Foo Blah)
    }
  }
  return $result;
}

# heavily optimized for speed
# $_[0] is self
# $_[1] is request
# $_[2] is defval
sub get {
  # fill in cache entry if it is empty
  $_[0]->{c}->{$_[1]} = _get(@_) unless exists $_[0]->{c}->{$_[1]};

  # return cache entry if it is defined
  return $_[0]->{c}->{$_[1]} if defined $_[0]->{c}->{$_[1]};

  # if the requested header wasn't found, we should return either
  # a default value as specified by the caller, or the blank string ''
  return $_[2] || '';
}

###########################################################################

sub ran_rule_debug_code {
  my ($self, $rulename, $ruletype, $bit) = @_;

  return '' unless exists($self->{should_log_rule_hits});

  # note: keep this in 'single quotes' to avoid the $ & performance hit,
  # unless specifically requested by the caller.   Also split the
  # two chars, just to be paranoid and ensure that a buggy perl interp
  # doesn't impose that hit anyway (just in case)
  my $match = '($' . '&' . '|| "negative match")';

  my $save_hits_code = '';
  if ($self->{save_pattern_hits}) {
    $save_hits_code = '
        $self->{pattern_hits}->{q{'.$rulename.'}} = '.$match.';
    ';
  }

  return '
    dbg("rules: ran '.$ruletype.' rule '.$rulename.' ======> got hit: \"" . '.
        $match.' . "\"");
    '.$save_hits_code.'
  ';
}

sub hash_line_for_rule {
  my ($self, $rulename) = @_;
  return "\n".'#line 1 "'.
        $self->{conf}->{source_file}->{$rulename}.
        ', rule '.$rulename.',"';
}

###########################################################################

sub do_head_tests {
  my ($self, $priority) = @_;
  local ($_);

  # note: we do this only once for all head pattern tests.  Only
  # eval tests need to use stuff in here.
  $self->{test_log_msgs} = ();        # clear test state

  dbg("rules: running header regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  # speedup code provided by Matt Sergeant
  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_head_tests_'.$clean_priority}
      && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_head_tests_'.$clean_priority}($self);
    use strict "refs";
    return;
  }

  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $rule) = each %{$self->{conf}{head_tests}->{$priority}}) {
    my $def = '';
    my ($hdrname, $testtype, $pat) =
        $rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    if (!defined $pat) {
      warn "rules: invalid rule: $rulename\n";
      $self->{rule_errors}++;
      next;
    }

    if ($pat =~ s/\s+\[if-unset:\s+(.+)\]\s*$//) { $def = $1; }

    $hdrname =~ s/#/[HASH]/g;                # avoid probs with eval below
    $def =~ s/#/[HASH]/g;

    $evalstr .= '
      if ($self->{conf}->{scores}->{q#'.$rulename.'#}) {
         '.$rulename.'_head_test($self, $_); # no need for OO calling here (its faster this way)
      }
    ';

    if ($doing_user_rules) {
      next if (!$self->is_user_rule_sub ($rulename.'_head_test'));
    }

    $evalstr2 .= '
      sub '.$rulename.'_head_test {
        my $self = shift;
        $_ = shift;
        '.$self->hash_line_for_rule($rulename).'
        if ($self->get(q#'.$hdrname.'#, q#'.$def.'#) '.$testtype.'~ '.$pat.') {
          $self->got_hit (q#'.$rulename.'#, q{});
          '. $self->ran_rule_debug_code($rulename, "header", 1) . '
        }
      }';

  }

  # clear out a previous version of this fn, if already defined
  if (defined &{'_head_tests_'.$clean_priority}) {
    undef &{'_head_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  $evalstr = <<"EOT";
{
    package Mail::SpamAssassin::PerMsgStatus;

    $evalstr2

    sub _head_tests_$clean_priority {
        my (\$self) = \@_;

        $evalstr;
    }

    1;
}
EOT

  eval $evalstr;

  if ($@) {
    warn "rules: failed to run header tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
  else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_head_tests_'.$clean_priority}($self);
    use strict "refs";
  }
}

sub do_body_tests {
  my ($self, $priority, $textary) = @_;
  local ($_);

  dbg("rules: running body-text per-line regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_BODY_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  $self->{test_log_msgs} = ();        # clear test state
  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_body_tests_'.$clean_priority}
       && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_body_tests_'.$clean_priority}($self, @$textary);
    use strict "refs";
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{body_tests}->{$priority}}) {
    $evalstr .= '
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        # call procedurally as it is faster.
        '.$rulename.'_body_test($self,@_);
      }
    ';

    if ($doing_user_rules) {
      next if (!$self->is_user_rule_sub ($rulename.'_body_test'));
    }

    $evalstr2 .= '
    sub '.$rulename.'_body_test {
           my $self = shift;
           foreach (@_) {
             '.$self->hash_line_for_rule($rulename).'
             if ('.$pat.') { 
                $self->got_pattern_hit(q{'.$rulename.'}, "BODY: "); 
                '. $self->ran_rule_debug_code($rulename, "body", 2) . '
		# Ok, we hit, stop now.
		last;
             }
           }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &{'_body_tests_'.$clean_priority}) {
    undef &{'_body_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _body_tests_$clean_priority {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("rules: failed to compile body tests, skipping:\n" . "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_body_tests_'.$clean_priority}($self, @$textary);
    use strict "refs";
  }
}

sub is_user_rule_sub {
  my ($self, $subname) = @_;
  return 0 if (eval 'defined &Mail::SpamAssassin::PerMsgStatus::'.$subname);
  1;
}

# Taken from URI and URI::Find
my $reserved   = q(;/?:@&=+$,[]\#|);
my $mark       = q(-_.!~*'());                                    #'; emacs
my $unreserved = "A-Za-z0-9\Q$mark\E\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f";
my $uricSet = quotemeta($reserved) . $unreserved . "%";

my $schemeRE = qr/(?:https?|ftp|mailto|javascript|file)/i;

my $uricCheat = $uricSet;
$uricCheat =~ tr/://d;

# the list from %VALID_TLDS in Util/RegistrarBoundaries.pm, as a
# Regexp::Optimize optimized regexp ;)  accurate as of 20050318
my $tldsRE = qr/
    (?=[a-wyz])
    (?:a(?:e(?:ro)?|r(?:pa)?|[cdfgilmnoqstuwzx])|b(?:iz?|[abdefghjmnorstvwyz])
      |c(?:o(?:m|op)?|[acdfghiklmnrsu])|d[ejkmoz]|e[ceghrst]|f[ijkmor]
      |g(?:[abdefghilmnpqrstuwy]|ov)|h[kmnrtu]|i(?:n(?:fo|t)?|[delmoqrst])
      |j[emop]|k[eghimnprwyz]|l[abcikrstuvy]
      |m(?:u(?:seum)?|[acdghkmnopqrstvwxyz]|i?l)|n(?:a(?:me)?|et?|[cfgilopruz])
      |o(?:m|rg)|p(?:ro?|[aefghklmnstwy])|r[eouw]|s[abcdeghijklmnortvyzu]
      |t[cdfghjklmnoprtvwz]|u[agkmsyz]|v[aceginu]|w[fs]|xxx|y[etu]|z[amw]|ed?u|qa
    )/ix;

# from RFC 1035, but allowing domains starting with numbers:
#   $label = q/[A-Za-z\d](?:[A-Za-z\d-]{0,61}[A-Za-z\d])?/;
#   $domain = qq<$label(?:\.$label)*>;
#   length($host) <= 255 && $host =~ /^($domain)$/
# changes:
#   massively simplified from grammar, only matches known TLDs, a single
#   dot at end of TLD works
# negative look-behinds:
#   (?<![a-z\d][.-]) = don't let there be more hostname behind, but
#                      don't miss ".....www.bar.com" or "-----www.foo.com"
#   (?<!.\@) = this will be caught by the email address regular expression
my $schemelessRE = qr/(?<![a-z\d][._-])(?<!.\@)\b[a-z\d]
                      [a-z\d._-]{0,251}
                      \.${tldsRE}\.?\b
                      (?![a-z\d._-])
                      /ix;

my $uriRe = qr/\b(?:$schemeRE:[$uricCheat]|$schemelessRE)[$uricSet#]*/o;

# Taken from Email::Find (thanks Tatso!)
# This is the BNF from RFC 822
my $esc         = '\\\\';
my $period      = '\.';
my $space       = '\040';
my $open_br     = '\[';
my $close_br    = '\]';
my $nonASCII    = '\x80-\xff';
my $ctrl        = '\000-\037';
my $cr_list     = '\n\015';
my $qtext       = qq/[^$esc$nonASCII$cr_list\"]/; #"
my $dtext       = qq/[^$esc$nonASCII$cr_list$open_br$close_br]/;
my $quoted_pair = qq<$esc>.qq<[^$nonASCII]>;
my $atom_char   = qq/[^($space)<>\@,;:\".$esc$open_br$close_br$ctrl$nonASCII]/;
#"
my $atom        = qq{(?>$atom_char+)};
my $quoted_str  = qq<\"$qtext*(?:$quoted_pair$qtext*)*\">; #"
my $word        = qq<(?:$atom|$quoted_str)>;
my $local_part  = qq<$word(?:$period$word)*>;

# This is a combination of the domain name BNF from RFC 1035 plus the
# domain literal definition from RFC 822, but allowing domains starting
# with numbers.
my $label       = q/[A-Za-z\d](?:[A-Za-z\d-]*[A-Za-z\d])?/;
my $domain_ref  = qq<$label(?:$period$label)*>;
my $domain_lit  = qq<$open_br(?:$dtext|$quoted_pair)*$close_br>;
my $domain      = qq<(?:$domain_ref|$domain_lit)>;

# Finally, the address-spec regex (more or less)
my $Addr_spec_re   = qr<$local_part\s*\@\s*$domain>o;

# TVD: This really belongs in metadata

=item $status->get_uri_list ()

Returns an array of all unique URIs found in the message.  It takes
a combination of the URIs found in the rendered (decoded and HTML
stripped) body and the URIs found when parsing the HTML in the message.
Will also set $status->{uri_list} (the array as returned by this function).

The returned array will include the "raw" URI as well as
"slightly cooked" versions.  For example, the single URI
'http://%77&#00119;%77.example.com/' will get turned into:
( 'http://%77&#00119;%77.example.com/', 'http://www.example.com/' )

=cut

sub get_uri_list {
  my ($self) = @_;

  # use cached answer if available
  if (defined $self->{uri_list}) {
    return @{$self->{uri_list}};
  }

  my @uris = ();
  $self->{redirect_num} = 0;

  # get URIs from HTML parsing
  while(my($uri, $info) = each %{ $self->get_uri_detail_list() }) {
    if ($info->{cleaned}) {
      foreach (@{$info->{cleaned}}) {
        push(@uris, $_);

        # count redirection attempts and log it
        if (my @http = m{\b(https?:/{0,2})}gi) {
          $self->{redirect_num} = $#http if ($#http > $self->{redirect_num});
        }
      }
    }
  }

  $self->{uri_list} = \@uris;

  return @uris;
}

=item $status->get_uri_detail_list ()

Returns a hash reference of all unique URIs found in the message and
various data about where the URIs were found in the message.  It takes a
combination of the URIs found in the rendered (decoded and HTML stripped)
body and the URIs found when parsing the HTML in the message.  Will also
set $status->{uri_detail_list} (the hash reference as returned by this
function).  This function will also set $status->{uri_domain_count} (count of
unique domains).

The hash format looks something like this:

  raw_uri => {
    types => { a => 1, img => 1, parsed => 1 },
    cleaned => [ canonified_uri ],
    anchor_text => [ "click here", "no click here" ],
    domains => { domain1 => 1, domain2 => 1 },
  }

C<raw_uri> is whatever the URI was in the message itself
(http://spamassassin.apache%2Eorg/).

C<types> is a hash of the HTML tags (lowercase) which referenced
the raw_uri.  I<parsed> is a faked type which specifies that the
raw_uri was seen in the rendered text.

C<cleaned> is an array of the raw and canonified version of the raw_uri
(http://spamassassin.apache%2Eorg/, http://spamassassin.apache.org/).

C<anchor_text> is an array of the anchor text (text between <a> and
</a>), if any, which linked to the URI.

C<domains> is a hash of the domains found in the canonified URIs.

=cut

sub get_uri_detail_list {
  my ($self) = @_;

  # use cached answer if available
  if (defined $self->{uri_detail_list}) {
    return $self->{uri_detail_list};
  }

  $self->{uri_domain_count} = 0;

  # do this so we're sure metadata->html is setup
  my @parsed = $self->_get_parsed_uri_list();

  # get URIs from HTML parsing
  # use the metadata version since $self->{html} may not be setup
  my $detail = $self->{msg}->{metadata}->{html}->{uri_detail} || { };

  # don't keep dereferencing ...
  my $redirector_patterns = $self->{conf}->{redirector_patterns};

  # canonify the HTML parsed URIs
  while(my($uri, $info) = each %{ $detail }) {
    my @tmp = Mail::SpamAssassin::Util::uri_list_canonify($redirector_patterns, $uri);
    $info->{cleaned} = \@tmp;

    foreach (@tmp) {
      my $domain = Mail::SpamAssassin::Util::uri_to_domain($_);
      if ($domain && !$info->{domains}->{$domain}) {
        $info->{domains}->{$domain} = 1;
        $self->{uri_domain_count}++;
      }
    }

    if (would_log('dbg', 'uri')) {
      dbg("uri: html uri found, $uri");
      foreach my $nuri (@tmp) {
        dbg("uri: cleaned html uri, $nuri");
      }
      if ($info->{domains}) {
        foreach my $domain (keys %{$info->{domains}}) {
          dbg("uri: html domain, $domain");
        }
      }
    }
  }

  # canonify the text parsed URIs
  foreach my $uri ( @parsed ) {
    $detail->{$uri}->{types}->{parsed} = 1;
    my $info = $detail->{$uri};

    my @uris = ();
    
    if (!exists $info->{cleaned}) {
      @uris = Mail::SpamAssassin::Util::uri_list_canonify($redirector_patterns, $uri);
      $info->{cleaned} = \@uris;

      foreach (@uris) {
        my $domain = Mail::SpamAssassin::Util::uri_to_domain($_);
        if ($domain && !$info->{domains}->{$domain}) {
          $info->{domains}->{$domain} = 1;
          $self->{uri_domain_count}++;
        }
      }
    }

    if (would_log('dbg', 'uri')) {
      dbg("uri: parsed uri found, $uri");
      foreach my $nuri (@uris) {
        dbg("uri: cleaned parsed uri, $nuri");
      }
      if ($info->{domains}) {
        foreach my $domain (keys %{$info->{domains}}) {
          dbg("uri: parsed domain, $domain");
        }
      }
    }
  }

  # setup the cache
  $self->{uri_detail_list} = $detail;

  return $detail;
}

sub _get_parsed_uri_list {
  my ($self) = @_;

  # use cached answer if available
  unless (defined $self->{parsed_uri_list}) {
    # TVD: we used to use decoded_body which is fine, except then we'll
    # try parsing URLs out of HTML, which is what the HTML code is going
    # to do (note: we know the HTML parsing occurs, because we call for the
    # rendered text which does HTML parsing...)  trying to get URLs out of
    # HTML w/out parsing causes issues, so let's not do it.
    # also, if we allow $textary to be passed in, we need to invalidate
    # the cache first. fyi.
    my $textary = $self->get_decoded_stripped_body_text_array();

    my ($rulename, $pat, @uris);
    local ($_);

    my $text;

    for (@$textary) {
      # NOTE: do not modify $_ in this loop
      while (/($uriRe)/igo) {
        my $uri = $1;

        # skip mismatches from URI regular expression
        next if $uri =~ /^[a-z\d.-]*\.\./i;	# skip ".."

        $uri =~ s/^<(.*)>$/$1/;
        $uri =~ s/[\]\)>#]$//;

        if ($uri !~ /^${schemeRE}:/io) {
          # If it's a hostname that was just sitting out in the
          # open, without a protocol, and not inside of an HTML tag,
          # the we should add the proper protocol in front, rather
          # than using the base URI.
          if ($uri =~ /^ftp\./i) {
            push (@uris, $uri);
            $uri = "ftp://$uri";
          }
          if ($uri =~ /\@/) {
            push (@uris, $uri);
            $uri = "mailto:$uri";
          }
          else # if ($uri =~ /^www\d*\./i)
          {
            # some spammers are using unschemed URIs to escape filters
            push (@uris, $uri);
            $uri = "http://$uri";
          }
        }

        # warn("uri: got URI: $uri\n");
        push @uris, $uri;
      }
      while (/($Addr_spec_re)/igo) {
        my $uri = $1;

        # skip mismatches from email address regular expression
        next unless $uri =~ /\.${tldsRE}\W*$/io;	# skip non-TLDs

        $uri =~ s/\s*\@\s*/@/;	# remove spaces around the '@'
        $uri = "mailto:$uri";	# prepend mailto:

        #warn("uri: got URI: $uri\n");
        push @uris, $uri;
      }
    }

    # setup the cache and return
    $self->{parsed_uri_list} = \@uris;
  }

  return @{$self->{parsed_uri_list}};
}

sub do_body_uri_tests {
  my ($self, $priority, @uris) = @_;
  local ($_);

  dbg("uri: running uri tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_URI_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  $self->{test_log_msgs} = ();        # clear test state
  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_body_uri_tests_'.$clean_priority}
      && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_body_uri_tests_'.$clean_priority}($self, @uris);
    use strict "refs";
    return;
  }

  # otherwise build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{uri_tests}->{$priority}}) {
    $evalstr .= '
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        '.$rulename.'_uri_test($self, @_); # call procedurally for speed
      }
    ';

    if ($doing_user_rules) {
      next if (!$self->is_user_rule_sub ($rulename.'_uri_test'));
    }

    $evalstr2 .= '
    sub '.$rulename.'_uri_test {
       my $self = shift;
       foreach (@_) {
         '.$self->hash_line_for_rule($rulename).'
         if ('.$pat.') { 
            $self->got_pattern_hit(q{'.$rulename.'}, "URI: ");
            '. $self->ran_rule_debug_code($rulename, "uri", 4) . '
            # Ok, we hit, stop now.
            last;
         }
       }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &{'_body_uri_tests_'.$clean_priority}) {
    undef &{'_body_uri_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _body_uri_tests_$clean_priority {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("rules: failed to compile URI tests, skipping:\n" . "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_body_uri_tests_'.$clean_priority}($self, @uris);
    use strict "refs";
  }
}

sub do_rawbody_tests {
  my ($self, $priority, $textary) = @_;
  local ($_);

  dbg("rules: running raw-body-text per-line regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  $self->{test_log_msgs} = ();        # clear test state
  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_rawbody_tests_'.$clean_priority}
      && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_rawbody_tests_'.$clean_priority}($self, @$textary);
    use strict "refs";
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{rawbody_tests}->{$priority}}) {
    $evalstr .= '
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
         '.$rulename.'_rawbody_test($self, @_); # call procedurally for speed
      }
    ';

    if ($doing_user_rules) {
      next if (!$self->is_user_rule_sub ($rulename.'_rawbody_test'));
    }

    $evalstr2 .= '
    sub '.$rulename.'_rawbody_test {
       my $self = shift;
       foreach (@_) {
         '.$self->hash_line_for_rule($rulename).'
         if ('.$pat.') { 
            $self->got_pattern_hit(q{'.$rulename.'}, "RAW: ");
            '. $self->ran_rule_debug_code($rulename, "rawbody", 8) . '
            # Ok, we hit, stop now.
            last;
         }
       }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &{'_rawbody_tests_'.$clean_priority}) {
    undef &{'_rawbody_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _rawbody_tests_$clean_priority {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("rules: failed to compile body tests, skipping:\n" . "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_rawbody_tests_'.$clean_priority}($self, @$textary);
    use strict "refs";
  }
}

sub do_full_tests {
  my ($self, $priority, $fullmsgref) = @_;
  local ($_);
  
  dbg("rules: running full-text regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_FULL_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  $self->{test_log_msgs} = ();        # clear test state

  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_full_tests_'.$clean_priority}
      && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_full_tests_'.$clean_priority}($self, $fullmsgref);
    use strict "refs";
    return;
  }

  # build up the eval string...
  my $evalstr = '';

  while (my($rulename, $pat) = each %{$self->{conf}{full_tests}->{$priority}}) {
    $evalstr .= '
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        '.$self->hash_line_for_rule($rulename).'
        if ($$fullmsgref =~ '.$pat.') {
          $self->got_pattern_hit(q{'.$rulename.'}, "FULL: ");
          '. $self->ran_rule_debug_code($rulename, "full", 16) . '
        }
      }
    ';
  }

  if (defined &{'_full_tests_'.$clean_priority}) {
    undef &{'_full_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  # and compile it.
  $evalstr = <<"EOT";
  {
    package Mail::SpamAssassin::PerMsgStatus;

    sub _full_tests_$clean_priority {
        my (\$self, \$fullmsgref) = \@_;
        study \$\$fullmsgref;
        $evalstr
    }

    1;
  }
EOT
  eval $evalstr;

  if ($@) {
    warn "rules: failed to compile full tests, skipping:\n" . "\t($@)\n";
    $self->{rule_errors}++;
  } else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_full_tests_'.$clean_priority}($self, $fullmsgref);
    use strict "refs";
  }
}

###########################################################################

sub do_head_eval_tests {
  my ($self, $priority) = @_;
  return unless (defined($self->{conf}->{head_evals}->{$priority}));
  $self->run_eval_tests ($self->{conf}->{head_evals}->{$priority}, '');
}

sub do_body_eval_tests {
  my ($self, $priority, $bodystring) = @_;
  return unless (defined($self->{conf}->{body_evals}->{$priority}));
  $self->run_eval_tests ($self->{conf}->{body_evals}->{$priority}, 'BODY: ', $bodystring);
}

sub do_rawbody_eval_tests {
  my ($self, $priority, $bodystring) = @_;
  return unless (defined($self->{conf}->{rawbody_evals}->{$priority}));
  $self->run_eval_tests ($self->{conf}->{rawbody_evals}->{$priority}, 'RAW: ', $bodystring);
}

sub do_full_eval_tests {
  my ($self, $priority, $fullmsgref) = @_;
  return unless (defined($self->{conf}->{full_evals}->{$priority}));
  $self->run_eval_tests ($self->{conf}->{full_evals}->{$priority}, '', $fullmsgref);
}

###########################################################################

sub do_meta_tests {
  my ($self, $priority) = @_;
  local ($_);

  dbg("rules: running meta tests; score so far=" . $self->{score} );

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{$Mail::SpamAssassin::Conf::TYPE_META_TESTS};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  # speedup code provided by Matt Sergeant
  if (defined &{'Mail::SpamAssassin::PerMsgStatus::_meta_tests_'.$clean_priority}
       && !$doing_user_rules) {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_meta_tests_'.$clean_priority}($self);
    use strict "refs";
    return;
  }

  my (%rule_deps, %setup_rules, %meta, $rulename);
  my $evalstr = '';

  # Get the list of meta tests
  my @metas = keys %{ $self->{conf}{meta_tests}->{$priority} };

  # Go through each rule and figure out what we need to do
  foreach $rulename (@metas) {
    my $rule   = $self->{conf}->{meta_tests}->{$priority}->{$rulename};
    my $token;

    # Lex the rule into tokens using a rather simple RE method ...
    my $lexer = ARITH_EXPRESSION_LEXER;
    my @tokens = ($rule =~ m/$lexer/g);

    # Set the rule blank to start
    $meta{$rulename} = "";

    # By default, there are no dependencies for a rule
    @{ $rule_deps{$rulename} } = ();

    # Go through each token in the meta rule
    foreach $token (@tokens) {

      # Numbers can't be rule names
      if ($token =~ /^(?:\W+|\d+)$/) {
        $meta{$rulename} .= "$token ";
      }
      else {
        $meta{$rulename} .= "\$self->{'tests_already_hit'}->{'$token'} ";
        $setup_rules{$token}=1;

        if (!exists $self->{conf}->{scores}->{$token}) {
          info("rules: meta test $rulename has undefined dependency '$token'");
        }
        elsif ($self->{conf}->{scores}->{$token} == 0) {
          my $conf = $self->{conf};
          my $dowarn = 1;

          # there are some cases where this is expected; don't warn
          # in those cases.
          if ((($self->{conf}->get_score_set()) & 1) == 0 &&
              $conf->{tflags}->{$token} &&
              $conf->{tflags}->{$token} =~ /\bnet\b/)
          {
            $dowarn = 0;    # bug 5040: net rules in a non-net scoreset
          }

          $dowarn and info("rules: meta test $rulename has dependency '$token' with a zero score");
        }

        # If the token is another meta rule, add it as a dependency
        push (@{ $rule_deps{$rulename} }, $token)
          if (exists $self->{conf}{meta_tests}->{$priority}->{$token});
      }
    }
  }

  # avoid "undefined" warnings by providing a default value for needed rules
  $evalstr .= join("\n", (map { "\$self->{'tests_already_hit'}->{'$_'} ||= 0;" } keys %setup_rules), "");

  # Sort by length of dependencies list.  It's more likely we'll get
  # the dependencies worked out this way.
  @metas = sort { @{ $rule_deps{$a} } <=> @{ $rule_deps{$b} } } @metas;

  my $count;

  # Now go ahead and setup the eval string
  do {
    $count = $#metas;
    my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups

    # Go through each meta rule we haven't done yet
    for (my $i = 0 ; $i <= $#metas ; $i++) {

      # If we depend on meta rules that haven't run yet, skip it
      next if (grep( $metas{$_}, @{ $rule_deps{ $metas[$i] } }));

      # Add this meta rule to the eval line
      $evalstr .= '  if ('.$meta{$metas[$i]}.') { $self->got_hit (q#'.$metas[$i].'#, ""); }'."\n";
      splice @metas, $i--, 1;    # remove this rule from our list
    }
  } while ($#metas != $count && $#metas > -1); # run until we can't go anymore

  # If there are any rules left, we can't solve the dependencies so complain
  my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
  foreach $rulename (@metas) {
    $self->{rule_errors}++; # flag to --lint that there was an error ...
    my $msg =
	"rules: excluding meta test $rulename, unsolved meta dependencies: " .
	    join(", ", grep($metas{$_}, @{ $rule_deps{$rulename} }));
    if ($self->{main}->{lint_rules}) {
      warn $msg."\n";
    }
    else {
      info($msg);
    }
  }

  if (defined &{'_meta_tests_'.$clean_priority}) {
    undef &{'_meta_tests_'.$clean_priority};
  }

  return unless ($evalstr);

  # setup the environment for meta tests
  $evalstr = <<"EOT";
{
    package Mail::SpamAssassin::PerMsgStatus;

    sub _meta_tests_$clean_priority {
        # note: cannot set \$^W here on perl 5.6.1 at least, it
        # crashes meta tests.

        my (\$self) = \@_;

        $evalstr;
    }

    1;
}
EOT

  eval $evalstr;

  if ($@) {
    warn "rules: failed to run meta tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
  else {
    no strict "refs";
    &{'Mail::SpamAssassin::PerMsgStatus::_meta_tests_'.$clean_priority}($self);
    use strict "refs";
  }
}    # do_meta_tests()

###########################################################################

sub run_eval_tests {
  my ($self, $evalhash, $prepend2desc, @extraevalargs) = @_;
  local ($_);
  
  my $debugenabled = would_log('dbg');

  my $scoreset = $self->{conf}->get_score_set();
  while (my ($rulename, $test) = each %{$evalhash}) {

    # Score of 0, skip it.
    next unless ($self->{conf}->{scores}->{$rulename});

    # If the rule is a net rule, and we're in a non-net scoreset, skip it.
    next if (exists $self->{conf}->{tflags}->{$rulename} &&
             (($scoreset & 1) == 0) &&
             $self->{conf}->{tflags}->{$rulename} =~ /\bnet\b/);

    # If the rule is a bayes rule, and we're in a non-bayes scoreset, skip it.
    next if (exists $self->{conf}->{tflags}->{$rulename} &&
             (($scoreset & 2) == 0) &&
             $self->{conf}->{tflags}->{$rulename} =~ /\bbayes\b/);

    my $score = $self->{conf}{scores}{$rulename};
    my $result;

    $self->{test_log_msgs} = ();        # clear test state

    my ($function, @args) = @{$test};
    unshift(@args, @extraevalargs);

    # check to make sure the function is defined
    if (!$self->can ($function)) {
      my $pluginobj = $self->{conf}->{eval_plugins}->{$function};
      if ($pluginobj) {
	# we have a plugin for this.  eval its function
	$self->register_plugin_eval_glue ($pluginobj, $function);
      } else {
	dbg("rules: no method found for eval test $function");
      }
    }

    # let plugins get the name of the rule that's currently being
    # run
    $self->{current_rule_name} = $rulename;

    eval {
      $result = $self->$function(@args);
    };

    if ($@) {
      warn "rules: failed to run $rulename test, skipping:\n" . "\t($@)\n";
      $self->{rule_errors}++;
      next;
    }

    if ($result) {
      $self->got_hit ($rulename, $prepend2desc);
      dbg("rules: ran eval rule $rulename ======> got hit") if $debugenabled;
    }
    #else {
    #  dbg("rules: ran eval rule $rulename ======> no hit") if $debugenabled;
    #}
  }
}

sub register_plugin_eval_glue {
  my ($self, $pluginobj, $function) = @_;

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
  eval $evalstr;

  if ($@) {
    warn "rules: failed to run header tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
}

###########################################################################

sub run_rbl_eval_tests {
  my ($self, $evalhash) = @_;
  my ($rulename, $pat, @args);
  local ($_);

  if ($self->{main}->{local_tests_only}) {
    dbg("rules: local tests only, ignoring RBL eval");
    return 0;
  }
  
  while (my ($rulename, $test) = each %{$evalhash}) {
    my $score = $self->{conf}->{scores}->{$rulename};
    next unless $score;

    $self->{test_log_msgs} = ();        # clear test state

    my ($function, @args) = @{$test};

    my $result;
    eval {
       $result = $self->$function($rulename, @args);
    };

    if ($@) {
      warn "rules: failed to run $rulename RBL test, skipping:\n" . "\t($@)\n";
      $self->{rule_errors}++;
      next;
    }
  }
}

###########################################################################

sub got_pattern_hit {
  my ($self, $rulename, $prefix) = @_;

  # only allow each test to hit once per mail
  return if (defined $self->{tests_already_hit}->{$rulename});

  $self->got_hit ($rulename, $prefix);
}

###########################################################################

# note: only eval tests should store state in $self->{test_log_msgs};
# pattern tests do not.
#
# the clearing of the test state is now inlined as:
#
# $self->{test_log_msgs} = ();        # clear test state
#
# except for this public API for plugin use:

=item $status->clear_test_state()

Clear test state, including test log messages from C<$status-E<gt>test_log()>.

=cut

sub clear_test_state {
    my ($self) = @_;
    $self->{test_log_msgs} = ();
}

sub _handle_hit {
    my ($self, $rule, $score, $area, $desc) = @_;

    # ignore meta-match sub-rules.
    if ($rule =~ /^__/) { push(@{$self->{subtest_names_hit}}, $rule); return; }

    # Add the rule hit to the score
    $self->{score} += $score;

    push(@{$self->{test_names_hit}}, $rule);
    $area ||= '';

    if ($score >= 10 || $score <= -10) {
      $score = sprintf("%4.0f", $score);
    }
    else {
      $score = sprintf("%4.1f", $score);
    }

    # save both summaries
    # TODO: this is slower than necessary, if we only need one
    $self->{tag_data}->{REPORT} .= sprintf ("* %s %s %s%s\n%s",
              $score, $rule, $area,
              $self->_wrap_desc($desc,
                  4+length($rule)+length($score)+length($area), "*      "),
              ($self->{test_log_msgs}->{TERSE} ?
              "*      " . $self->{test_log_msgs}->{TERSE} : ''));

    $self->{tag_data}->{SUMMARY} .= sprintf ("%s %-22s %s%s\n%s",
              $score, $rule, $area,
              $self->_wrap_desc($desc,
                  3+length($rule)+length($score)+length($area), " " x 28),
              ($self->{test_log_msgs}->{LONG} || ''));

    $self->{test_log_msgs} = ();        # clear test logs
}

sub _wrap_desc {
  my ($self, $desc, $firstlinelength, $prefix) = @_;

  my $firstline = " " x $firstlinelength;
  my $wrapped = Mail::SpamAssassin::Util::wrap($desc, $prefix, $firstline, 75, 0);
  $wrapped =~ s/^\s+//s;
  $wrapped;
}

sub handle_hit {
  my ($self, $rule, $area, $deffallbackdesc) = @_;

  my $desc = $self->{conf}->{descriptions}->{$rule};
  $desc ||= $deffallbackdesc;
  $desc ||= $rule;

  my $score = $self->{conf}->{scores}->{$rule};

  $self->_handle_hit($rule, $score, $area, $desc);
}

sub got_hit {
  my ($self, $rule, $prepend2desc) = @_;

  $self->{tests_already_hit}->{$rule} = 1;

  my $txt = $self->{conf}->{full_tests}->{$rule};
  $txt ||= $self->{conf}->{full_evals}->{$rule};
  $txt ||= $self->{conf}->{head_tests}->{$rule};
  $txt ||= $self->{conf}->{body_tests}->{$rule};
  $self->handle_hit ($rule, $prepend2desc, $txt);
}

sub test_log {
  my ($self, $msg) = @_;
  while ($msg =~ s/^(.{30,48})\s//) {
    $self->_test_log_line ($1);
  }
  $self->_test_log_line ($msg);
}

sub _test_log_line {
  my ($self, $msg) = @_;

  $self->{test_log_msgs}->{TERSE} .= sprintf ("[%s]\n", $msg);
  if (length($msg) > 47) {
    $self->{test_log_msgs}->{LONG} .= sprintf ("%78s\n", "[$msg]");
  } else {
    $self->{test_log_msgs}->{LONG} .= sprintf ("%27s [%s]\n", "", $msg);
  }
}

###########################################################################

# helper for get().  Do not call directly, as get() caches its results
# and this does not!
sub get_envelope_from {
  my ($self) = @_;
  
  # bug 2142:
  # Get the SMTP MAIL FROM:, aka. the "envelope sender", if our
  # calling app has helpfully marked up the source message
  # with it.  Various MTAs and calling apps each have their
  # own idea of what header to use for this!   see

  my $envf;

  # use the "envelope-sender" string found in the Received headers,
  # if possible... use the last untrusted header, in case there's
  # trusted headers.
  my $lasthop = $self->{relays_untrusted}->[0];
  if (!defined $lasthop) {
    # no untrusted headers?  in that case, the message is ALL_TRUSTED.
    # use the first trusted header (ie. the oldest, originating one).
    $lasthop = $self->{relays_trusted}->[-1];
  }

  if (defined $lasthop) {
    $envf = $lasthop->{envfrom};
    if ($envf && ($envf =~ /\@/)) {
      goto ok;
    }
  }

  # Use the 'envelope-sender-header' header that the user has specified.
  # We assume this is correct, *even* if the fetchmail/X-Sender screwup
  # appears.
  $envf = $self->{conf}->{envelope_sender_header};
  if ((defined $envf) && ($envf = $self->get($envf)) && ($envf =~ /\@/)) {
    goto ok;
  }

  # WARNING: a lot of list software adds an X-Sender for the original env-from
  # (including Yahoo! Groups).  Unfortunately, fetchmail will pick it up and
  # reuse it as the env-from for *its* delivery -- even though the list
  # software had used a different env-from in the intervening delivery.  Hence,
  # if this header is present, and there's a fetchmail sig in the Received
  # lines, we cannot trust any Envelope-From headers, since they're likely to
  # be incorrect fetchmail guesses.

  if ($self->get ("X-Sender") =~ /\@/) {
    my $rcvd = join (' ', $self->get ("Received"));
    if ($rcvd =~ /\(fetchmail/) {
      dbg("message: X-Sender and fetchmail signatures found, cannot trust envelope-from");
      return undef;
    }
  }

  # procmailrc notes this, amavisd are adding it, we recommend it
  # (although we now recommend adding to Received instead)
  if ($envf = $self->get ("X-Envelope-From")) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get ("ALL") =~ /(?:^|\n)Received:\s.*\nX-Envelope-From:\s/s) {
      dbg("message: X-Envelope-From header found after 1 or more Received lines, cannot trust envelope-from");
    } else {
      goto ok;
    }
  }

  # qmail, new-inject(1)
  if ($envf = $self->get ("Envelope-Sender")) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get ("ALL") =~ /(?:^|\n)Received:\s.*\nEnvelope-Sender:\s/s) {
      dbg("message: Envelope-Sender header found after 1 or more Received lines, cannot trust envelope-from");
    } else {
      goto ok;
    }
  }

  # Postfix, sendmail, also mentioned in RFC821
  if ($envf = $self->get ("Return-Path")) {
    # heuristic: this could have been relayed via a list which then used
    # a *new* Envelope-from.  check
    if ($self->get ("ALL") =~ /(?:^|\n)Received:\s.*\nReturn-Path:\s/s) {
      dbg("message: Return-Path header found after 1 or more Received lines, cannot trust envelope-from");
    } else {
      goto ok;
    }
  }

  # give up.
  return undef;

ok:
  $envf =~ s/^<*//gs;                # remove <
  $envf =~ s/>*\s*$//gs;        # remove >, whitespace, newlines
  return $envf;
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

=item $status->create_fulltext_tmpfile (fulltext_ref)

This function creates a temporary file containing the passed scalar
reference data (typically the full/pristine text of the message).
This is typically used by external programs like pyzor and dccproc, to
avoid hangs due to buffering issues.   Methods that need this, should
call $self->create_fulltext_tmpfile($fulltext) to retrieve the temporary
filename; it will be created if it has not already been.

Note: This can only be called once until $status->delete_fulltext_tmpfile() is
called.

=cut

sub create_fulltext_tmpfile {
  my ($self, $fulltext) = @_;

  if (defined $self->{fulltext_tmpfile}) {
    return $self->{fulltext_tmpfile};
  }

  my ($tmpf, $tmpfh) = Mail::SpamAssassin::Util::secure_tmpfile();
  print $tmpfh $$fulltext;
  close $tmpfh;

  $self->{fulltext_tmpfile} = $tmpf;

  return $self->{fulltext_tmpfile};
}

=item $status->delete_fulltext_tmpfile ()

Will cleanup after a $status->create_fulltext_tmpfile() call.  Deletes the
temporary file and uncaches the filename.

=cut

sub delete_fulltext_tmpfile {
  my ($self) = @_;
  if (defined $self->{fulltext_tmpfile}) {
    unlink $self->{fulltext_tmpfile};
    $self->{fulltext_tmpfile} = undef;
  }
}

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

