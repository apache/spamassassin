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

Mail::SpamAssassin::Plugin::OSBF - OSBF learning classifier

=head1 DESCRIPTION

This plugin implements a trained probabilistic classifier, using an algorithm
based on Winnow, as described in section 2 of _Combining Winnow and Orthogonal
Sparse Bigrams for Incremental Spam Filtering_, by Siefkes, Assis, Chhabra and
Yerazunis:

  http://www.siefkes.net/ie/winnow-spam.pdf
  http://en.wikipedia.org/wiki/Winnow

The tokenizer uses Orthogonal Sparse Bigrams, as described in that paper.

The results are incorporated into SpamAssassin as the OSBF_* rules.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Plugin::OSBF;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use Mail::SpamAssassin::Bayes::CombineChi;

use Digest::SHA1 qw(sha1 sha1_hex);

our @ISA = qw(Mail::SpamAssassin::Plugin);

use vars qw{
  $IGNORED_HDRS
  $MARK_PRESENCE_ONLY_HDRS
  $OPPORTUNISTIC_LOCK_VALID
};

# Which headers should we scan for tokens?  Don't use all of them, as it's easy
# to pick up spurious clues from some.  What we now do is use all of them
# *less* these well-known headers; that way we can pick up spammers' tracking
# headers (which are obviously not well-known in advance!).

# Received is handled specially
$IGNORED_HDRS = qr{(?: (?:X-)?Sender    # misc noise
  |Delivered-To |Delivery-Date
  |(?:X-)?Envelope-To
  |X-MIME-Auto[Cc]onverted |X-Converted-To-Plain-Text

  |Subject      # not worth a tiny gain vs. to db size increase

  # Date: can provide invalid cues if your spam corpus is
  # older/newer than ham
  |Date

  # List headers: ignore. a spamfiltering mailing list will
  # become a nonspam sign.
  |X-List|(?:X-)?Mailing-List
  |(?:X-)?List-(?:Archive|Help|Id|Owner|Post|Subscribe
    |Unsubscribe|Host|Id|Manager|Admin|Comment
    |Name|Url)
  |X-Unsub(?:scribe)?
  |X-Mailman-Version |X-Been[Tt]here |X-Loop
  |Mail-Followup-To
  |X-eGroups-(?:Return|From)
  |X-MDMailing-List
  |X-XEmacs-List

  # gatewayed through mailing list (thanks to Allen Smith)
  |(?:X-)?Resent-(?:From|To|Date)
  |(?:X-)?Original-(?:From|To|Date)

  # Spamfilter/virus-scanner headers: too easy to chain from
  # these
  |X-MailScanner(?:-SpamCheck)?
  |X-Spam(?:-(?:Status|Level|Flag|Report|Hits|Score|Checker-Version))?
  |X-Antispam |X-RBL-Warning |X-Mailscanner
  |X-MDaemon-Deliver-To |X-Virus-Scanned
  |X-Mass-Check-Id
  |X-Pyzor |X-DCC-\S{2,25}-Metrics
  |X-Filtered-B[Yy] |X-Scanned-By |X-Scanner
  |X-AP-Spam-(?:Score|Status) |X-RIPE-Spam-Status
  |X-SpamCop-[^:]+
  |X-SMTPD |(?:X-)?Spam-Apparently-To
  |SPAM |X-Perlmx-Spam
  |X-Bogosity

  # some noisy Outlook headers that add no good clues:
  |Content-Class |Thread-(?:Index|Topic)
  |X-Original[Aa]rrival[Tt]ime

  # Annotations from IMAP, POP, and MH:
  |(?:X-)?Status |X-Flags |Replied |Forwarded
  |Lines |Content-Length
  |X-UIDL? |X-IMAPbase

  # Annotations from Bugzilla
  |X-Bugzilla-[^:]+

  # Annotations from VM: (thanks to Allen Smith)
  |X-VM-(?:Bookmark|(?:POP|IMAP)-Retrieved|Labels|Last-Modified
    |Summary-Format|VHeader|v\d-Data|Message-Order)

  # Annotations from Gnus:
  | X-Gnus-Mail-Source
  | Xref

)}x;

# Note only the presence of these headers, in order to reduce the
# hapaxen they generate.
$MARK_PRESENCE_ONLY_HDRS = qr{(?: X-Face
  |X-(?:Gnu-?PG|PGP|GPG)(?:-Key)?-Fingerprint
)}ix;

# tweaks tested as of Nov 18 2002 by jm: see SpamAssassin-devel list archives
# for results.  The winners are now the default settings.
use constant IGNORE_TITLE_CASE => 1;
use constant TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES => 1;
use constant TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;

# tweaks of May 12 2003, see SpamAssassin-devel archives again.
use constant PRE_CHEW_ADDR_HEADERS => 1;
use constant CHEW_BODY_URIS => 1;
use constant CHEW_BODY_MAILADDRS => 1;
use constant HDRS_TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;
use constant BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;
use constant URIS_TOKENIZE_LONG_TOKENS_AS_SKIPS => 0;
use constant IGNORE_MSGID_TOKENS => 0;

# tweaks of 12 March 2004, see bug 2129.
use constant DECOMPOSE_BODY_TOKENS => 1;
use constant MAP_HEADERS_MID => 1;
use constant MAP_HEADERS_FROMTOCC => 1;
use constant MAP_HEADERS_USERAGENT => 1;

# tweaks, see http://issues.apache.org/SpamAssassin/show_bug.cgi?id=3173#c26
use constant ADD_INVIZ_TOKENS_I_PREFIX => 1;
use constant ADD_INVIZ_TOKENS_NO_PREFIX => 0;

# How many seconds should the opportunistic_expire lock be valid?
$OPPORTUNISTIC_LOCK_VALID = 300;

# Should we use the Robinson f(w) equation from
# http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html ?
# It gives better results, in that scores are more likely to distribute
# into the <0.5 range for nonspam and >0.5 for spam.
use constant USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS => 1;

# How many significant tokens are required for a classifier score to
# be considered usable?
use constant REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE => -1;

# How long a token should we hold onto?  (note: German speakers typically
# will require a longer token than English ones.)
use constant MAX_TOKEN_LENGTH => 15;

###########################################################################

sub new {
  my $class = shift;
  my ($main) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($main);
  bless ($self, $class);

  $self->{main} = $main;
  $self->{conf} = $main->{conf};
  $self->{use_ignores} = 1;

  $self->register_eval_rule("check_osbf");
  $self;
}

sub finish {
  my $self = shift;
  if ($self->{store}) {
    $self->{store}->untie_db();
  }
  %{$self} = ();
}

# Plugin hook.
# Return this implementation object, for callers that need to know
# it.  TODO: callers shouldn't *need* to know it! 
#
# used in test suite to get access to {store}, internal APIs;
# used in Mail::SpamAssassin::PerMsgStatus for the
# compute_declassification_distance() call.
#
sub learner_get_implementation {      
  my ($self) = @_;
  return $self;
}

###########################################################################

sub check_osbf {
  my ($self, $pms, $fulltext, $min, $max) = @_;

  return 0 if (!$pms->{conf}->{use_learner});
  return 0 if (!$pms->{conf}->{use_bayes} || !$pms->{conf}->{use_bayes_rules});

  # TODO: osbf_score?

  if (!exists ($pms->{bayes_score})) {
    my $timer = $self->{main}->time_method("check_osbf");
    $pms->{bayes_score} = $self->scan($pms, $pms->{msg});
  }

  if (defined $pms->{bayes_score} &&
      ($min == 0 || $pms->{bayes_score} > $min) &&
      ($max eq "undef" || $pms->{bayes_score} <= $max))
  {
      if ($pms->{conf}->{detailed_bayes_score}) {
        $pms->test_log(sprintf ("score: %3.4f, hits: %s",
                                 $pms->{bayes_score},
                                 $pms->{bayes_hits}));
      }
      else {
        $pms->test_log(sprintf ("score: %3.4f", $pms->{bayes_score}));
      }
      return 1;
  }

  return 0;
}

###########################################################################

# Plugin hook.
sub sanity_check_bayes_is_untied {
  my ($self, $params) = @_;
  my $quiet = $params->{quiet};

  # do a sanity check here.  Wierd things happen if we remain tied
  # after compiling; for example, spamd will never see that the
  # number of messages has reached the bayes-scanning threshold.
  if ($self->{store}->db_readable()) {
    warn "osbf: oops! still tied to bayes DBs, untying\n" unless $quiet;
    $self->{store}->untie_db();
  }
}

###########################################################################

sub ignore_message {
  my ($self,$PMS) = @_;

  return 0 unless $self->{use_ignores};

  my $ig_from = $self->{main}->call_plugins ("check_wb_list",
        { permsgstatus => $PMS, type => 'from', list => 'bayes_ignore_from' });
  my $ig_to = $self->{main}->call_plugins ("check_wb_list",
        { permsgstatus => $PMS, type => 'to', list => 'bayes_ignore_to' });

  my $ignore = $ig_from || $ig_to;

  dbg("osbf: not using bayes, bayes_ignore_from or _to rule") if $ignore;

  return $ignore;
}

###########################################################################

# Plugin hook.
sub learn_message {
  my ($self, $params) = @_;
  my $isspam = $params->{isspam};
  my $msg = $params->{msg};
  my $id = $params->{id};

  if (!$self->{conf}->{use_bayes}) { return; }

  # Winnow cannot support learning to journal
  $self->{main}->{learn_to_journal} = 0;

  my $msgdata = $self->get_body_from_msg ($msg);
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    my $ok;
    if ($self->{main}->{learn_to_journal}) {
      # If we're going to learn to journal, we'll try going r/o first...
      # If that fails for some reason, let's try going r/w.  This happens
      # if the DB doesn't exist yet.
      $ok = $self->{store}->tie_db_readonly() || $self->{store}->tie_db_writable();
    } else {
      $ok = $self->{store}->tie_db_writable();
    }

    if ($ok) {
      $ret = $self->_learn_trapped ($isspam, $msg, $msgdata, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
    1;
  } or do {		# if we died, untie the dbs.
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    $self->{store}->untie_db();
    die "osbf: (in learn) $eval_stat\n";
  };

  return $ret;
}

# this function is trapped by the wrapper above
sub _learn_trapped {
  my ($self, $isspam, $msg, $msgdata, $msgid) = @_;
  my @msgid = ( $msgid );

  if (!defined $msgid) {
    @msgid = $self->get_msgid($msg);
  }

  foreach $msgid ( @msgid ) {
    my $seen = $self->{store}->seen_get ($msgid);

    if (defined ($seen)) {
      if (($seen =~ /^s/ && $isspam) || ($seen =~ /^h/ && !$isspam)) {
        dbg("osbf: $msgid already learnt correctly, not learning twice");
        return 0;
      } elsif ($seen !~ /^[hs]/) {
        warn("osbf: db_seen corrupt: value='$seen' for $msgid, ignored");
      } else {
        # bug 3704: If the message was already learned, don't try learning it again.
        # this prevents, for instance, manually learning as spam, then autolearning
        # as ham, or visa versa.
        if ($self->{main}->{learn_no_relearn}) {
	  dbg("osbf: $msgid already learnt as opposite, not re-learning");
	  return 0;
	}

        dbg("osbf: $msgid already learnt as opposite, forgetting first");

        # kluge so that forget() won't untie the db on us ...
        my $orig = $self->{main}->{learn_caller_will_untie};
        $self->{main}->{learn_caller_will_untie} = 1;

        my $fatal = !defined $self->{main}->{bayes_scanner}->forget ($msg);

        # reset the value post-forget() ...
        $self->{main}->{learn_caller_will_untie} = $orig;
    
        # forget() gave us a fatal error, so propagate that up
        if ($fatal) {
          dbg("osbf: forget() returned a fatal error, so learn() will too");
	  return;
        }
      }

      # we're only going to have seen this once, so stop if it's been
      # seen already
      last;
    }
  }

  # Now that we're sure we haven't seen this message before ...
  $msgid = $msgid[0];

  if ($isspam) {
    $self->{store}->nspam_nham_change (1, 0);
  } else {
    $self->{store}->nspam_nham_change (0, 1);
  }

  my $msgatime = $msg->receive_date();

  # If the message atime comes back as being more than 1 day in the
  # future, something's messed up and we should revert to current time as
  # a safety measure.
  #
  $msgatime = time if ( $msgatime - time > 86400 );

  my $tokens = $self->tokenize($msg, $msgdata);

  my $tokensdata = $self->{store}->tok_get_all(keys %{$tokens});
  my $total_spam = 0;
  my $total_ham = 0;
  my $weights = ();
  foreach my $tokendata (@{$tokensdata}) {
    my ($token, $tok_spam, $tok_ham, $atime) = @{$tokendata};
    if (!defined $tok_spam || !defined $tok_ham) {
      ($tok_spam, $tok_ham, undef) = $self->{store}->tok_get ($token);
    }
    if ($tok_spam != 0 || $tok_ham != 0) {
      # add the token to the classification
      $total_spam += ($tok_spam || 1.0);
      $total_ham += ($tok_ham || 1.0);
    }

    # store the weights, even if this is a previously unknown token;
    # we'll be updating them if we decide to learn
    $weights->{$token} = [ $tok_spam || 1.0, $tok_ham || 1.0 ];
  }

  my $div = (scalar keys %$weights || 0.00001);
  $total_spam /= $div;
  $total_ham /= $div;

  # 5% "thick threshold" separation, see section 2.1 of the Winnow paper
  my $skip_train;
  if ($isspam) {
    $skip_train = ($total_spam > 1.05 && $total_ham < 0.95);
  } else {
    $skip_train = ($total_ham > 1.05 && $total_spam < 0.95);
  }

  if ($skip_train) {
    # the message was classified correctly, with good margins; we
    # don't need to train on it
    dbg("osbf: skipping train, classified as h=$total_ham s=$total_spam");

  } else {
    dbg("osbf: needs train, classified as h=$total_ham s=$total_spam");
    my $mult_spam = 1;
    my $mult_ham = 1;
    my $hist_spam = '.';    # symbol saved in 'seen' file to record history
    my $hist_ham = '.';
    if ($isspam) {
      if ($total_spam < 1.05) { $mult_spam = 1.23; $hist_spam = '+'; }
      if ($total_ham > 0.95) { $mult_ham = 0.83;   $hist_ham = '-'; }
    } else {
      if ($total_spam > 0.95) { $mult_spam = 0.83; $hist_spam = '-'; }
      if ($total_ham < 1.05) { $mult_ham = 1.23;   $hist_ham = '+'; }
    }
    $self->modify_weights($mult_spam, $mult_ham, $weights, $msgatime);

    # only write a "seen" entry if we actually trained on it.
    # record which way we changed the entries ($hist_*)
    $self->{store}->seen_put ($msgid,
            ($isspam ? 's' : 'h').$hist_spam.$hist_ham);
  }

  $self->{store}->cleanup();

  $self->{main}->call_plugins("bayes_learn", { toksref => $tokens,
					       isspam => $isspam,
					       msgid => $msgid,
					       msgatime => $msgatime,
					     });

  dbg("osbf: learned '$msgid', atime: $msgatime");

  1;
}

sub modify_weights {
  my ($self, $mult_spam, $mult_ham, $weights, $msgatime) = @_;
  foreach my $w (keys %$weights) {
    if ($mult_spam != 1) { $weights->{$w}->[0] *= $mult_spam; }
    if ($mult_ham  != 1) { $weights->{$w}->[1] *= $mult_ham; }
  }
  $self->{store}->multi_tok_value_change($weights, $msgatime);
}

###########################################################################

# Plugin hook.
sub forget_message {
  my ($self, $params) = @_;
  my $msg = $params->{msg};
  my $id = $params->{id};

  if (!$self->{conf}->{use_bayes}) { return; }

  my $msgdata = $self->get_body_from_msg ($msg);
  my $ret;

  # Winnow cannot support learning to journal
  $self->{main}->{learn_to_journal} = 0;

  # we still tie for writing here, since we write to the seen db
  # synchronously
  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    my $ok;
    if ($self->{main}->{learn_to_journal}) {
      # If we're going to learn to journal, we'll try going r/o first...
      # If that fails for some reason, let's try going r/w.  This happens
      # if the DB doesn't exist yet.
      $ok = $self->{store}->tie_db_readonly() || $self->{store}->tie_db_writable();
    } else {
      $ok = $self->{store}->tie_db_writable();
    }

    if ($ok) {
      $ret = $self->_forget_trapped ($msg, $msgdata, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
    1;
  } or do {		# if we died, untie the dbs.
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    $self->{store}->untie_db();
    die "osbf: (in forget) $eval_stat\n";
  };

  return $ret;
}

# this function is trapped by the wrapper above
sub _forget_trapped {
  my ($self, $msg, $msgdata, $msgid) = @_;
  my @msgid = ( $msgid );
  my $isspam;
  my $hist_spam;
  my $hist_ham;

  if (!defined $msgid) {
    @msgid = $self->get_msgid($msg);
  }

  while( $msgid = shift @msgid ) {
    my $seen = $self->{store}->seen_get ($msgid);

    if (defined ($seen)) {
      $seen =~ /^(.)(.)(.)/;
      $seen = $1;
      if ($seen eq 's') {
        $isspam = 1;
      } elsif ($seen eq 'h') {
        $isspam = 0;
      } else {
        dbg("osbf: forget: msgid $msgid seen entry is neither ham nor spam, ignored");
        return 0;
      }

      $hist_spam = $2;
      $hist_ham = $3;
      # messages should only be learned once, so stop if we find a msgid
      # which was seen before
      last;
    }
    else {
      dbg("osbf: forget: msgid $msgid not learnt, ignored");
    }
  }

  # This message wasn't learnt before, so return
  if (!defined $isspam) {
    dbg("osbf: forget: no msgid from this message has been learnt, skipping message");
    return 0;
  }
  elsif ($isspam) {
    $self->{store}->nspam_nham_change (-1, 0);
  }
  else {
    $self->{store}->nspam_nham_change (0, -1);
  }

  my $tokens = $self->tokenize($msg, $msgdata);

  my $tokensdata = $self->{store}->tok_get_all(keys %{$tokens});
  my $total_spam = 0;
  my $total_ham = 0;
  my $weights = ();
  foreach my $tokendata (@{$tokensdata}) {
    my ($token, $tok_spam, $tok_ham, $atime) = @{$tokendata};
    if (!defined $tok_spam || !defined $tok_ham) {
      ($tok_spam, $tok_ham, undef) = $self->{store}->tok_get ($token);
    }

    # ignore unknown tokens, we don't need to forget them if we
    # never learned them in the first place
    if ($tok_spam && $tok_ham) {
      $weights->{$token} = [ $tok_spam, $tok_ham ];
    }
  }

  # unlike in the "learn" case, we don't run a classify; we always need to
  # modify the weights for a forgetting, since we're reversing the effects of a
  # previous learn which definitely took place
  {
    my $mult_spam = 1;
    my $mult_ham = 1;
    if    ($hist_spam eq '+') { $mult_spam = 1/1.23; }
    elsif ($hist_spam eq '-') { $mult_spam = 1/0.83; }
    if    ($hist_ham  eq '+') { $mult_ham  = 1/1.23; }
    elsif ($hist_ham  eq '-') { $mult_ham  = 1/0.83; }
    $self->modify_weights($mult_spam, $mult_ham, $weights);
  }

  $self->{store}->seen_delete ($msgid);
  $self->{store}->cleanup();

  $self->{main}->call_plugins("bayes_forget", { toksref => $tokens,
						isspam => $isspam,
						msgid => $msgid,
					      });

  1;
}

###########################################################################

# Plugin hook.
sub learner_sync {
  my ($self, $params) = @_;
  if (!$self->{conf}->{use_bayes}) { return 0; }
  dbg("osbf: osbf journal sync starting");
  $self->{store}->sync($params);
  dbg("osbf: osbf journal sync completed");
}

###########################################################################

# Plugin hook.
sub learner_expire_old_training {
  my ($self, $params) = @_;
  if (!$self->{conf}->{use_bayes}) { return 0; }
  dbg("osbf: expiry starting");
  $self->{store}->expire_old_tokens($params);
  dbg("osbf: expiry completed");
}

###########################################################################

# Plugin hook.
# Check to make sure we can tie() the DB, and we have enough entries to do a scan
# if we're told the caller will untie(), go ahead and leave the db tied.
sub learner_is_scan_available {
  my ($self, $params) = @_;

  return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();

  # We need the DB to stay tied, so if the journal sync occurs, don't untie!
  my $caller_untie = $self->{main}->{learn_caller_will_untie};
  $self->{main}->{learn_caller_will_untie} = 1;

  # Do a journal sync if necessary.  Do this before the nspam_nham_get()
  # call since the sync may cause an update in the number of messages
  # learnt.
  $self->_opportunistic_calls(1);

  # Reset the variable appropriately
  $self->{main}->{learn_caller_will_untie} = $caller_untie;

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  if ($ns < $self->{conf}->{bayes_min_spam_num}) {
    dbg("osbf: not available for scanning, only $ns spam(s) in osbf DB < ".$self->{conf}->{bayes_min_spam_num});
    if (!$self->{main}->{learn_caller_will_untie}) {
      $self->{store}->untie_db();
    }
    return 0;
  }
  if ($nn < $self->{conf}->{bayes_min_ham_num}) {
    dbg("osbf: not available for scanning, only $nn ham(s) in osbf DB < ".$self->{conf}->{bayes_min_ham_num});
    if (!$self->{main}->{learn_caller_will_untie}) {
      $self->{store}->untie_db();
    }
    return 0;
  }

  return 1;
}

###########################################################################

sub scan {
  my ($self, $permsgstatus, $msg) = @_;
  my $score;

  return unless $self->{conf}->{use_learner};

  # When we're doing a scan, we'll guarantee that we'll do the untie,
  # so override the global setting until we're done.
  my $caller_untie = $self->{main}->{learn_caller_will_untie};
  $self->{main}->{learn_caller_will_untie} = 1;

  goto skip if ($self->{main}->{bayes_scanner}->ignore_message($permsgstatus));

  goto skip unless $self->learner_is_scan_available();

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  ## if ($self->{log_raw_counts}) { # see _compute_prob_for_token()
  ## $self->{raw_counts} = " ns=$ns nn=$nn ";
  ## }

  dbg("osbf: corpus size: nspam = $ns, nham = $nn");

  my $msgdata = $self->_get_msgdata_from_permsgstatus ($permsgstatus);
  my $msgtokens = $self->tokenize($msg, $msgdata);
  my $tokensdata = $self->{store}->tok_get_all(keys %{$msgtokens});

  my @touch_tokens = ();
  my $log_each_token = (would_log('dbg', 'osbf') > 1);

  # A variant of the Winnow classifier algorithm, as described in
  # section 2 of _Combining Winnow and Orthogonal Sparse Bigrams
  # for Incremental Spam Filtering_, Siefkes, Assis, Chhabra
  # and Yerazunis.

  my %pw;
  my $total_spam = 0;
  my $total_ham = 0;
  foreach my $tokendata (@{$tokensdata}) {
    my ($token, $tok_spam, $tok_ham, $atime) = @{$tokendata};
    if (!defined $tok_spam || !defined $tok_ham) {
      ($tok_spam, $tok_ham, undef) = $self->{store}->tok_get ($token);
    }
    next if ($tok_spam == 0 && $tok_ham == 0);  # both not found
    my $w_spam = $tok_spam || 1.0;
    my $w_ham = $tok_ham || 1.0;
    $total_spam += $w_spam;
    $total_ham += $w_ham;

    # update the atime on this token, it proved useful
    push(@touch_tokens, $token);

dbg("osbf: token '$msgtokens->{$token}' => s=$tok_spam / h=$tok_ham");
    if ($log_each_token) {
      dbg("osbf: token '$msgtokens->{$token}' => s=$tok_spam / h=$tok_ham");
    }

    $pw{$token} = {
      prob => 0.5,
      spam_count => $w_spam,      # TODO, does this make sense?
      ham_count => $w_ham,
      atime => $atime
    };
  }

  # If none of the tokens were found in the DB, we're going to skip
  # this message...
  if (!scalar @touch_tokens) {
    dbg("osbf: cannot use osbf on this message; none of the tokens were found in the database");
    goto skip;
  }

  # Figure out the message receive time (used as atime below)
  # If the message atime comes back as being in the future, something's
  # messed up and we should revert to current time as a safety measure.
  #
  my $msgatime = $msg->receive_date();
  my $now = time;
  $msgatime = $now if ( $msgatime > $now );

  # warn "JMD s=$total_spam h=$total_ham";
  if ($total_ham > $total_spam) {
    $score = 0.0;
  } else {
    $score = 1.0;
  }

  dbg("osbf: score = $score");

  # no need to call tok_touch_all unless there were significant
  # tokens and a score was returned
  # we don't really care about the return value here
  $self->{store}->tok_touch_all(\@touch_tokens, $msgatime);

  $permsgstatus->{bayes_nspam} = $ns;
  $permsgstatus->{bayes_nham} = $nn;

  $self->{main}->call_plugins("bayes_scan", { toksref => $msgtokens,
					      probsref => \%pw,
					      score => $score,
					      msgatime => $msgatime,
					      significant_tokens => \@touch_tokens,
					    });

skip:
  if (!defined $score) {
    dbg("osbf: not scoring message, returning undef");
  }

  # Take any opportunistic actions we can take
  if ($self->{main}->{opportunistic_expire_check_only}) {
    # we're supposed to report on expiry only -- so do the
    # _opportunistic_calls() run for the journal only.
    $self->_opportunistic_calls(1);
    $permsgstatus->{bayes_expiry_due} = $self->{store}->expiry_due();
  }
  else {
    $self->_opportunistic_calls();
  }

  # Do any cleanup we need to do
  $self->{store}->cleanup();

  # Reset the value accordingly
  $self->{main}->{learn_caller_will_untie} = $caller_untie;

  # If our caller won't untie the db, we need to do it.
  if (!$caller_untie) {
    $self->{store}->untie_db();
  }

  return $score;
}

###########################################################################

# Plugin hook.
sub learner_dump_database {
  my ($self, $params) = @_;
  my $magic = $params->{magic};
  my $toks = $params->{toks};
  my $regex = $params->{regex};

  # allow dump to occur even if use_bayes disables everything else ...
  #return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();
  
  my @vars = $self->{store}->get_storage_variables();

  my($sb,$ns,$nh,$nt,$le,$oa,$bv,$js,$ad,$er,$na) = @vars;

  my $template = '%3.3f %10f %10f %10u  %s'."\n";

  if ( $magic ) {
    printf ($template, 0.0, 0, $bv, 0, 'non-token data: osbf db version');
    printf ($template, 0.0, 0, $ns, 0, 'non-token data: nspam');
    printf ($template, 0.0, 0, $nh, 0, 'non-token data: nham');
    printf ($template, 0.0, 0, $nt, 0, 'non-token data: ntokens');
    printf ($template, 0.0, 0, $oa, 0, 'non-token data: oldest atime');
    printf ($template, 0.0, 0, $na, 0, 'non-token data: newest atime') if ( $bv >= 2 );
    printf ($template, 0.0, 0, $sb, 0, 'non-token data: current scan-count') if ( $bv < 2 );
    printf ($template, 0.0, 0, $js, 0, 'non-token data: last journal sync atime') if ( $bv >= 2 );
    printf ($template, 0.0, 0, $le, 0, 'non-token data: last expiry atime');
    if ( $bv >= 2 ) {
      printf ($template, 0.0, 0, $ad, 0, 'non-token data: last expire atime delta');
      printf ($template, 0.0, 0, $er, 0, 'non-token data: last expire reduction count');
    }
  }

  if ( $toks ) {
    # let the store sort out the db_toks
    $self->{store}->dump_db_toks($template, $regex, @vars);
  }

  if (!$self->{main}->{learn_caller_will_untie}) {
    $self->{store}->untie_db();
  }
  return 1;
}

###########################################################################
# TODO: these are NOT public, but the test suite needs to call them.

sub get_msgid {
  my ($self, $msg) = @_;

  my @msgid;

  my $msgid = $msg->get_header("Message-Id");
  if (defined $msgid && $msgid ne '' && $msgid !~ /^\s*<\s*(?:\@sa_generated)?>.*$/) {
    # remove \r and < and > prefix/suffixes
    chomp $msgid;
    $msgid =~ s/^<//; $msgid =~ s/>.*$//g;
    push(@msgid, $msgid);
  }

  # Use sha1_hex(Date:, last received: and top N bytes of body)
  # where N is MIN(1024 bytes, 1/2 of body length)
  #
  my $date = $msg->get_header("Date");
  $date = "None" if (!defined $date || $date eq ''); # No Date?

  my @rcvd = $msg->get_header("Received");
  my $rcvd = $rcvd[$#rcvd];
  $rcvd = "None" if (!defined $rcvd || $rcvd eq ''); # No Received?

  # Make a copy since pristine_body is a reference ...
  my $body = join('', $msg->get_pristine_body());
  if (length($body) > 64) { # Small Body?
    my $keep = ( length $body > 2048 ? 1024 : int(length($body) / 2) );
    substr($body, $keep) = '';
  }

  unshift(@msgid, sha1_hex($date."\000".$rcvd."\000".$body).'@sa_generated');

  return wantarray ? @msgid : $msgid[0];
}

sub get_body_from_msg {
  my ($self, $msg) = @_;

  if (!ref $msg) {
    # I have no idea why this seems to happen. TODO
    warn "osbf: msg not a ref: '$msg'";
    return { };
  }

  my $permsgstatus =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);
  $msg->extract_message_metadata ($permsgstatus);
  my $msgdata = $self->_get_msgdata_from_permsgstatus ($permsgstatus);
  $permsgstatus->finish();

  if (!defined $msgdata) {
    # why?!
    warn "osbf: failed to get body for ".scalar($self->get_msgid($self->{msg}))."\n";
    return { };
  }

  return $msgdata;
}

sub _get_msgdata_from_permsgstatus {
  my ($self, $msg) = @_;

  my $msgdata = { };
  $msgdata->{bayes_token_body} = $msg->{msg}->get_visible_rendered_body_text_array();
  $msgdata->{bayes_token_inviz} = $msg->{msg}->get_invisible_rendered_body_text_array();
  @{$msgdata->{bayes_token_uris}} = $msg->get_uri_list();
  return $msgdata;
}

###########################################################################

# The calling functions expect a uniq'ed array of tokens ...
sub tokenize {
  my ($self, $msg, $msgdata) = @_;

  # the body
  my @tokens = map { $self->_tokenize_line ($_, '', 1) }
                                    @{$msgdata->{bayes_token_body}};

  # the URI list
  push (@tokens, map { $self->_tokenize_line ($_, '', 2) }
                                    @{$msgdata->{bayes_token_uris}});

  # add invisible tokens
  if (ADD_INVIZ_TOKENS_I_PREFIX) {
    push (@tokens, map { $self->_tokenize_line ($_, "I*:", 1) }
                                    @{$msgdata->{bayes_token_inviz}});
  }
  if (ADD_INVIZ_TOKENS_NO_PREFIX) {
    push (@tokens, map { $self->_tokenize_line ($_, "", 1) }
                                    @{$msgdata->{bayes_token_inviz}});
  }

  # Tokenize the headers
  my %hdrs = $self->_tokenize_headers ($msg);
  while( my($prefix, $value) = each %hdrs ) {
    push(@tokens, $self->_tokenize_line ($value, "H$prefix:", 0));
  }

  # Go ahead and uniq the array, skip null tokens (can happen sometimes)
  # generate an SHA1 hash and take the lower 40 bits as our token
  my %tokens;
  foreach my $token (@tokens) {
    next unless length($token); # skip 0 length tokens
    $tokens{substr(sha1($token), -5)} = $token;
  }

  # return the keys == tokens ...
  return \%tokens;
}

sub _tokenize_line {
  my $self = $_[0];
  my $tokprefix = $_[2];
  my $region = $_[3];

  my @rettokens;
  my $magic_re = $self->{store}->get_magic_re();
  my ($w1,$w2,$w3,$w4,$w5) = ('','','','','');

  my @words = ($_[1] =~
      /([^\p{Z}\p{C}][\/!?#]?[-\p{L}\p{M}\p{N}]*(?:['"=;]|\/?>|:\/*)?)/g);
  foreach my $token (@words)
  {
    next if ($token =~ /^[\.\,]+$/);    # just punctuation
    # $token =~ s/^[-'"\.,]+//;        # trim non-alphanum chars at start or end
    # $token =~ s/[-'"\.,]+$//;        # so we don't get loads of '"foo' tokens

    # Skip false magic tokens
    # TVD: we need to do a defined() check since SQL doesn't have magic
    # tokens, so the SQL BayesStore returns undef.  I really want a way
    # of optimizing that out, but I haven't come up with anything yet.
    #
    next if ( defined $magic_re && $token =~ /$magic_re/ );

    # are we in the body?  If so, apply some body-specific breakouts
    if ($region == 1 || $region == 2) {
      if (0 && CHEW_BODY_MAILADDRS && $token =~ /\S\@\S/i) {
	push (@rettokens, $self->_tokenize_mail_addrs ($token));
      }
      elsif (0 && CHEW_BODY_URIS && $token =~ /\S\.[a-z]/i) {
	push (@rettokens, "UD:".$token); # the full token
	my $bit = $token; while ($bit =~ s/^[^\.]+\.(.+)$/$1/gs) {
	  push (@rettokens, "UD:".$1); # UD = URL domain
	}
      }
    }

    # decompose tokens?  do this after shortening long tokens
    if ($region == 1 || $region == 2) {
      if (0 && DECOMPOSE_BODY_TOKENS) {
        if ($token =~ /[^\w:\*]/) {
          my $decompd = $token;                        # "Foo!"
          $decompd =~ s/[^\w:\*]//gs;
          push (@rettokens, $tokprefix.$decompd);      # "Foo"
        }

        if ($token =~ /[A-Z]/) {
          my $decompd = $token; $decompd = lc $decompd;
          push (@rettokens, $tokprefix.$decompd);      # "foo!"

          if ($token =~ /[^\w:\*]/) {
            $decompd =~ s/[^\w:\*]//gs;
            push (@rettokens, $tokprefix.$decompd);    # "foo"
          }
        }
      }
    }

    $w5 = $w4;
    $w4 = $w3;
    $w3 = $w2;
    $w2 = $w1;
    $w1 = $tokprefix.$token;

    # here's the OSB (orthogonal sparse bigrams) part:
    push (@rettokens, $w2.' '.$w1);
    push (@rettokens, $w3.' '.$w1);
    push (@rettokens, $w4.' '.$w1);
    push (@rettokens, $w5.' '.$w1);
  }

  return @rettokens;
}

sub _tokenize_headers {
  my ($self, $msg) = @_;

  my %parsed;

  my %user_ignore;
  $user_ignore{lc $_} = 1 for @{$self->{main}->{conf}->{bayes_ignore_headers}};

  # get headers in array context
  my @hdrs;
  my @rcvdlines;
  for ($msg->get_all_headers()) {
    # first, keep a copy of Received headers, so we can strip down to last 2
    if (/^Received:/i) {
      push(@rcvdlines, $_);
      next;
    }
    # and now skip lines for headers we don't want (including all Received)
    next if /^${IGNORED_HDRS}:/i;
    next if IGNORE_MSGID_TOKENS && /^Message-ID:/i;
    push(@hdrs, $_);
  }
  push(@hdrs, $msg->get_all_metadata());

  # and re-add the last 2 received lines: usually a good source of
  # spamware tokens and HELO names.
  if ($#rcvdlines >= 0) { push(@hdrs, $rcvdlines[$#rcvdlines]); }
  if ($#rcvdlines >= 1) { push(@hdrs, $rcvdlines[$#rcvdlines-1]); }

  for (@hdrs) {
    next unless /\S/;
    my ($hdr, $val) = split(/:/, $_, 2);

    # remove user-specified headers here, after Received, in case they
    # want to ignore that too
    next if exists $user_ignore{lc $hdr};

    # Prep the header value
    $val ||= '';
    chomp($val);

    # special tokenization for some headers:
    if ($hdr =~ /^(?:|X-|Resent-)Message-Id$/i) {
      $val = $self->_pre_chew_message_id ($val);
    }
    elsif (PRE_CHEW_ADDR_HEADERS && $hdr =~ /^(?:|X-|Resent-)
	(?:Return-Path|From|To|Cc|Reply-To|Errors-To|Mail-Followup-To|Sender)$/ix)
    {
      $val = $self->_pre_chew_addr_header ($val);
    }
    elsif ($hdr eq 'Received') {
      $val = $self->_pre_chew_received ($val);
    }
    elsif ($hdr eq 'Content-Type') {
      $val = $self->_pre_chew_content_type ($val);
    }
    elsif ($hdr eq 'MIME-Version') {
      $val =~ s/1\.0//;		# totally innocuous
    }
    elsif ($hdr =~ /^${MARK_PRESENCE_ONLY_HDRS}$/i) {
      $val = "1"; # just mark the presence, they create lots of hapaxen
    }

    if (MAP_HEADERS_MID) {
      if ($hdr =~ /^(?:In-Reply-To|References|Message-ID)$/i) {
        $parsed{"*MI"} = $val;
      }
    }
    if (MAP_HEADERS_FROMTOCC) {
      if ($hdr =~ /^(?:From|To|Cc)$/i) {
        $parsed{"*Ad"} = $val;
      }
    }
    if (MAP_HEADERS_USERAGENT) {
      if ($hdr =~ /^(?:X-Mailer|User-Agent)$/i) {
        $parsed{"*UA"} = $val;
      }
    }

    if (exists $parsed{$hdr}) {
      $parsed{$hdr} .= " ".$val;
    } else {
      $parsed{$hdr} = $val;
    }
    if (would_log('dbg', 'osbf') > 1) {
      dbg("osbf: header tokens for $hdr = \"$parsed{$hdr}\"");
    }
  }

  return %parsed;
}

sub _pre_chew_content_type {
  my ($self, $val) = @_;

  # hopefully this will retain good bits without too many hapaxen
  if ($val =~ s/boundary=[\"\'](.*?)[\"\']/ /ig) {
    my $boundary = $1;
    $boundary =~ s/[a-fA-F0-9]/H/gs;
    # break up blocks of separator chars so they become their own tokens
    $boundary =~ s/([-_\.=]+)/ $1 /gs;
    $val .= $boundary;
  }

  # stop-list words for Content-Type header: these wind up totally gray
  $val =~ s/\b(?:text|charset)\b//;

  $val;
}

sub _pre_chew_message_id {
  my ($self, $val) = @_;
  # we can (a) get rid of a lot of hapaxen and (b) increase the token
  # specificity by pre-parsing some common formats.

  # Outlook Express format:
  $val =~ s/<([0-9a-f]{4})[0-9a-f]{4}[0-9a-f]{4}\$
           ([0-9a-f]{4})[0-9a-f]{4}\$
           ([0-9a-f]{8})\@(\S+)>/ OEA$1 OEB$2 OEC$3 $4 /gx;

  # Exim:
  $val =~ s/<[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]\@//;

  # Sendmail:
  $val =~ s/<20\d\d[01]\d[0123]\d[012]\d[012345]\d[012345]\d\.
           [A-F0-9]{10,12}\@//gx;

  # try to split Message-ID segments on probable ID boundaries. Note that
  # Outlook message-ids seem to contain a server identifier ID in the last
  # 8 bytes before the @.  Make sure this becomes its own token, it's a
  # great spam-sign for a learning system!  Be sure to split on ".".
  $val =~ s/[^_A-Za-z0-9]/ /g;
  $val;
}

sub _pre_chew_received {
  my ($self, $val) = @_;

  # Thanks to Dan for these.  Trim out "useless" tokens; sendmail-ish IDs
  # and valid-format RFC-822/2822 dates

  $val =~ s/\swith\sSMTP\sid\sg[\dA-Z]{10,12}\s/ /gs;  # Sendmail
  $val =~ s/\swith\sESMTP\sid\s[\dA-F]{10,12}\s/ /gs;  # Sendmail
  $val =~ s/\bid\s[a-zA-Z0-9]{7,20}\b/ /gs;    # Sendmail
  $val =~ s/\bid\s[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]/ /gs; # exim

  $val =~ s/(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?
           [0-3\s]?[0-9]\s
           (?:Jan|Feb|Ma[ry]|Apr|Ju[nl]|Aug|Sep|Oct|Nov|Dec)\s
           (?:19|20)?[0-9]{2}\s
           [0-2][0-9](?:\:[0-5][0-9]){1,2}\s
           (?:\s*\(|\)|\s*(?:[+-][0-9]{4})|\s*(?:UT|[A-Z]{2,3}T))*
           //gx;

  # IPs: break down to nearest /24, to reduce hapaxes -- EXCEPT for
  # IPs in the 10 and 192.168 ranges, they gets lots of significant tokens
  # (on both sides)
  # also make a dup with the full IP, as fodder for
  # bayes_dump_to_trusted_networks: "H*r:ip*aaa.bbb.ccc.ddd"
  $val =~ s{\b(\d{1,3}\.)(\d{1,3}\.)(\d{1,3})(\.\d{1,3})\b}{
           if ($2 eq '10' || ($2 eq '192' && $3 eq '168')) {
             $1.$2.$3.$4.
		" ip*".$1.$2.$3.$4." ";
           } else {
             $1.$2.$3.
		" ip*".$1.$2.$3.$4." ";
           }
         }gex;

  # trim these: they turn out as the most common tokens, but with a
  # prob of about .5.  waste of space!
  $val =~ s/\b(?:with|from|for|SMTP|ESMTP)\b/ /g;

  $val;
}

sub _pre_chew_addr_header {
  my ($self, $val) = @_;
  local ($_);

  my @addrs = $self->{main}->find_all_addrs_in_line ($val);
  my @toks;
  foreach (@addrs) {
    push (@toks, $self->_tokenize_mail_addrs ($_));
  }
  return join (' ', @toks);
}

sub _tokenize_mail_addrs {
  my ($self, $addr) = @_;

  ($addr =~ /(.+)\@(.+)$/) or return ();
  my @toks;
  push(@toks, "U*".$1, "D*".$2);
  $_ = $2; while (s/^[^\.]+\.(.+)$/$1/gs) { push(@toks, "D*".$1); }
  return @toks;
}


###########################################################################

# compute the probability that a token is spammish
sub _compute_prob_for_token {
  my ($self, $token, $ns, $nn, $s, $n) = @_;

  # we allow the caller to give us the token information, just
  # to save a potentially expensive lookup
  if (!defined($s) || !defined($n)) {
    ($s, $n, undef) = $self->{store}->tok_get ($token);
  }

  return if ($s == 0 && $n == 0);

  if (!USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    return if ($s + $n < 10);      # ignore low-freq tokens
  }

  if (!$self->{use_hapaxes}) {
    return if ($s + $n < 2);
  }

  return if ( $ns == 0 || $nn == 0 );

  my $ratios = ($s / $ns);
  my $ration = ($n / $nn);

  my $prob;

  if ($ratios == 0 && $ration == 0) {
    warn "osbf: oops? ratios == ration == 0";
    return;
  } else {
    $prob = ($ratios) / ($ration + $ratios);
  }

  if (USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    # use Robinson's f(x) equation for low-n tokens, instead of just
    # ignoring them
    my $robn = $s+$n;
    $prob = ($Mail::SpamAssassin::Bayes::Combine::FW_S_DOT_X + ($robn * $prob))
                             /
            ($Mail::SpamAssassin::Bayes::Combine::FW_S_CONSTANT + $robn);
  }

  # 'log_raw_counts' is used to log the raw data for the Bayes equations during
  # a mass-check, allowing the S and X constants to be optimized quickly
  # without requiring re-tokenization of the messages for each attempt. There's
  # really no need for this code to be uncommented in normal use, however.   It
  # has never been publicly documented, so commenting it out is fine. ;)

  ## if ($self->{log_raw_counts}) {
  ## $self->{raw_counts} .= " s=$s,n=$n ";
  ## }

  return $prob;
}

###########################################################################
# If a token is neither hammy nor spammy, return 0.
# For a spammy token, return the minimum number of additional ham messages
# it would have had to appear in to no longer be spammy.  Hammy tokens
# are handled similarly.  That's what the function does (at the time
# of this writing, 31 July 2003, 16:02:55 CDT).  It would be slightly
# more useful if it returned the number of /additional/ ham messages
# a spammy token would have to appear in to no longer be spammy but I
# fear that might require the solution to a cubic equation, and I
# just don't have the time for that now.

sub compute_declassification_distance {
  my ($self, $Ns, $Nn, $ns, $nn, $prob) = @_;
  return 0;
  #TODO?  probably not
}

###########################################################################

sub _opportunistic_calls {
  my($self, $journal_only) = @_;

  # If we're not already tied, abort.
  if (!$self->{store}->db_readable()) {
    dbg("osbf: opportunistic call attempt failed, DB not readable");
    return;
  }

  # Is an expire or sync running?
  my $running_expire = $self->{store}->get_running_expire_tok();
  if ( defined $running_expire && $running_expire+$OPPORTUNISTIC_LOCK_VALID > time() ) {
    dbg("osbf: opportunistic call attempt skipped, found fresh running expire magic token");
    return;
  }

  # handle expiry and syncing
  if (!$journal_only && $self->{store}->expiry_due()) {
    dbg("osbf: opportunistic call found expiry due");

    # sync will bring the DB R/W as necessary, and the expire will remove
    # the running_expire token, may untie as well.
    $self->{main}->{bayes_scanner}->sync(1,1);
  }
  elsif ( $self->{store}->sync_due() ) {
    dbg("osbf: opportunistic call found journal sync due");

    # sync will bring the DB R/W as necessary, may untie as well
    $self->{main}->{bayes_scanner}->sync(1,0);

    # We can only remove the running_expire token if we're doing R/W
    if ($self->{store}->db_writable()) {
      $self->{store}->remove_running_expire_tok();
    }
  }

  return;
}

###########################################################################

sub learner_new {
  my ($self) = @_;

  if ($self->{conf}->{osbf_store_module}) {
    my $module = $self->{conf}->{osbf_store_module};
    $module = untaint_var($module);  # good enough?
    my $store;

    eval '
      require '.$module.';
      $store = '.$module.'->new($self);
      1;
    ' or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      die "osbf: (in new) $eval_stat\n";
    };
    $self->{store} = $store;
  }
  else {
    require Mail::SpamAssassin::OSBF::Store::DBM;
    $self->{store} = Mail::SpamAssassin::OSBF::Store::DBM->new($self);
  }

  $self;
}

1;

=back

=cut
