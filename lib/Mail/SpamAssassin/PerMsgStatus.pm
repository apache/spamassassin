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

Mail::SpamAssassin::PerMsgStatus - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = new Mail::SpamAssassin ({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin.cf'
  });
  my $mail = $spamtest->parse();

  my $status = $spamtest->check ($mail);
  if ($status->is_spam()) {
    $status->rewrite_mail ();
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
use bytes;
use Carp;

use Text::Wrap ();

use Mail::SpamAssassin::EvalTests;
use Mail::SpamAssassin::AutoWhitelist;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::MsgContainer;

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

  # HTML parser stuff
  $self->{html} = {};

  bless ($self, $class);
  $self;
}

###########################################################################

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
  if ( ($set & 2) == 0 && $self->{main}->{bayes_scanner}->is_scan_available() ) {
    dbg("debug: Scoreset $set but Bayes is available, switching scoresets");
    $self->{conf}->set_score_set ($set|2);
  }

  $self->extract_message_metadata();

  {
    # Here, we launch all the DNS RBL queries and let them run while we
    # inspect the message
    $self->run_rbl_eval_tests ($self->{conf}->{rbl_evals});

    # do head tests
    $self->do_head_tests();

    # do body tests with decoded portions
    {
      my $decoded = $self->get_decoded_stripped_body_text_array();
      # warn "dbg ". join ("", @{$decoded}). "\n";
      $self->do_body_tests($decoded);
      $self->do_body_eval_tests($decoded);
      undef $decoded;
    }

    # do rawbody tests with raw text portions
    {
      my $bodytext = $self->get_decoded_body_text_array();
      $self->do_rawbody_tests($bodytext);
      $self->do_rawbody_eval_tests($bodytext);
      # NB: URI tests are here because "strip" removes too much
      $self->do_body_uri_tests($bodytext);
      undef $bodytext;
    }

    # and do full tests: first with entire, full, undecoded message
    # use get_all_headers instead of 
    {
      my $fulltext = join ('', $self->{msg}->get_all_headers(1), "\n",
                                $self->{msg}->get_pristine_body());
      $self->do_full_tests(\$fulltext);
      $self->do_full_eval_tests(\$fulltext);
      undef $fulltext;
    }

    $self->do_head_eval_tests();

    # harvest the DNS results
    $self->harvest_dnsbl_queries();

    # finish the DNS results
    $self->rbl_finish();

    # Do meta rules second-to-last
    $self->do_meta_tests();

    # auto-learning
    $self->learn();

    # add points from learning systems (Bayes and AWL)
    $self->{score} += $self->{learned_points};
  }

  $self->delete_fulltext_tmpfile();


  # Round the score to 3 decimal places to avoid rounding issues
  # We assume required_score to be properly rounded already.
  # add 0 to force it back to numeric representation instead of string.
  $self->{score} = (sprintf "%0.3f", $self->{score}) + 0;
  
  dbg ("is spam? score=".$self->{score}.
                        " required=".$self->{conf}->{required_score}.
                        " tests=".$self->get_names_of_tests_hit());
  $self->{is_spam} = $self->is_spam();

  my $report;
  $report = $self->{conf}->{report_template};
  $report ||= '(no report template found)';

  $report = $self->_replace_tags($report);

  # now that we've finished checking the mail, clear out this cache
  # to avoid unforeseen side-effects.
  $self->{hdr_cache} = { };

  $report =~ s/\n*$/\n\n/s;
  $self->{report} = $report;

  $self->{main}->call_plugins ("check_end", { permsgstatus => $self });
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

  if (!$self->{conf}->{bayes_auto_learn}) { return; }
  if (!$self->{conf}->{use_bayes}) { return; }
  if ($self->{disable_auto_learning}) { return; }

  # Figure out min/max for autolearning.
  # Default to specified auto_learn_threshold settings
  my $min = $self->{conf}->{bayes_auto_learn_threshold_nonspam};
  my $max = $self->{conf}->{bayes_auto_learn_threshold_spam};

  dbg ("auto-learn? ham=$min, spam=$max, ".
                "body-points=".$self->{body_only_points}.", ".
                "head-points=".$self->{head_only_points});

  my $isspam;

  # This section should use sum($score[scoreset % 2]) not just {score}.  otherwise we shift what we
  # autolearn on and it gets really wierd.  - tvd
  my $score = 0;
  my $orig_scoreset = $self->{conf}->get_score_set();
  if ( ($orig_scoreset & 2) == 0 ) { # we don't need to recompute
    dbg ("auto-learn: currently using scoreset $orig_scoreset.  no need to recompute.");
    $score = $self->{score};
  }
  else {
    my $new_scoreset = $orig_scoreset & ~2;
    dbg ("auto-learn: currently using scoreset $orig_scoreset.  recomputing score based on scoreset $new_scoreset.");
    $self->{conf}->set_score_set($new_scoreset); # reduce to autolearning scores
    $score = $self->get_nonlearn_nonuserconf_points();
    dbg ("auto-learn: original score: ".$self->{score}.", recomputed score: $score");
    $self->{conf}->set_score_set($orig_scoreset); # return to appropriate scoreset
  }

  if ($score < $min) {
    $isspam = 0;
  } elsif ($score >= $max) {
    $isspam = 1;
  } else {
    dbg ("auto-learn? no: inside auto-learn thresholds");
    $self->{auto_learn_status} = "no";
    return;
  }

  my $learner_said_ham_points = -1.0;
  my $learner_said_spam_points = 1.0;

  if ($isspam) {
    my $required_body_points = 3;
    my $required_head_points = 3;

    if ($self->{body_only_points} < $required_body_points) {
      $self->{auto_learn_status} = "no";
      dbg ("auto-learn? no: too few body points (".
                  $self->{body_only_points}." < ".$required_body_points.")");
      return;
    }
    if ($self->{head_only_points} < $required_head_points) {
      $self->{auto_learn_status} = "no";
      dbg ("auto-learn? no: too few head points (".
                  $self->{head_only_points}." < ".$required_head_points.")");
      return;
    }
    if ($self->{learned_points} < $learner_said_ham_points) {
      $self->{auto_learn_status} = "no";
      dbg ("auto-learn? no: learner indicated ham (".
                  $self->{learned_points}." < ".$learner_said_ham_points.")");
      return;
    }

  } else {
    if ($self->{learned_points} > $learner_said_spam_points) {
      $self->{auto_learn_status} = "no";
      dbg ("auto-learn? no: learner indicated spam (".
                  $self->{learned_points}." > ".$learner_said_spam_points.")");
      return;
    }
  }

  dbg ("auto-learn? yes, ".($isspam?"spam ($score > $max)":"ham ($score < $min)"));

  $self->{main}->call_plugins ("autolearn", {
      permsgstatus => $self,
      isspam => $isspam
    });

  eval {
    my $learnstatus = $self->{main}->learn ($self->{msg}, undef, $isspam, 0);
    $learnstatus->finish();
    if ( $learnstatus->did_learn() ) {
      $self->{auto_learn_status} = $isspam ? "spam" : "ham";
    }
    $self->{main}->finish_learner();        # for now

    if (exists $self->{main}->{bayes_scanner}) {
      $self->{main}->{bayes_scanner}->sanity_check_is_untied();
    }
  };

  if ($@) {
    dbg ("auto-learning failed: $@");
    $self->{auto_learn_status} = "failed";
  }
}

sub get_nonlearn_nonuserconf_points {
  my ($self) = @_;

  my $scores = $self->{conf}->{scores};
  my $tflags = $self->{conf}->{tflags};
  my $points = 0;

  foreach my $test ( @{$self->{test_names_hit}} )
  {
    # ignore tests with 0 score in this scoreset,
    # or if the test is a learning or userconf test
    next if ($scores->{$test} == 0);
    next if (exists $tflags->{$test} && $tflags->{$test} =~ /\bnoautolearn\b/);

    $points += $scores->{$test};
  }

  return (sprintf "%0.3f", $points) + 0;
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

sub get_required_hits {
  my ($self) = @_;
  return $self->{conf}->{required_score};
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

  $Text::Wrap::columns   = 74;
  $Text::Wrap::huge      = 'overflow';

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

  # be paranoid -- there's a die() in there
  my $wrapped;
  eval {
    # add "Content preview:" ourselves, so that the text aligns
    # correctly with the template -- then trim it off.  We don't
    # have to get this *exactly* right, but it's nicer if we
    # make a bit of an effort ;)
    $wrapped = Text::Wrap::wrap ("Content preview:  ", "  ", $str);
    if (defined $wrapped) {
      $wrapped =~ s/^Content preview:\s+//gs;
      $str = $wrapped;
    }
  };

  $str;
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

  if ($self->{is_spam} && $self->{conf}->{report_safe}) {
    return $self->rewrite_as_spam();
  }
  else {
    return $self->rewrite_headers();
  }
}

# rewrite the entire message as spam (headers and body)
sub rewrite_as_spam {
  my ($self) = @_;

  # This is the original message.  We do not want to make any modifications so
  # we may recover it if necessary.  It will be put into the new message as a
  # message/rfc822 MIME part.
  my $original = $self->{msg}->get_pristine();

  # This is the new message.
  my $newmsg = '';

  # remove first line if it is "From "
  $original =~ s/^From .*\n//;

  # the report charset
  my $report_charset = "";
  if ($self->{conf}->{report_charset}) {
    $report_charset = "; charset=" . $self->{conf}->{report_charset};
  }

  # the SpamAssassin report
  my $report = $self->{report};

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
    $subject ||= '';
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{Subject});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $subject =~ s/^(?:\Q${tag}\E |)/${tag} /g; # For some reason the tag may already be there!?
  }

  if ($self->{conf}->{rewrite_header}->{To}) {
    $to ||= '';
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{To});
    $tag =~ s/\n/ /gs; # strip tag's newlines
    $to =~ s/(?:\t\Q(${tag})\E|)$/\t(${tag})/
  }

  if ($self->{conf}->{rewrite_header}->{From}) {
    $from ||= '';
    my $tag = $self->_replace_tags($self->{conf}->{rewrite_header}->{From});
    $tag =~ s/\n+//gs; # strip tag's newlines
    $from =~ s/(?:\t\Q(${tag})\E|)$/\t(${tag})/
  }

  # add report headers to message
  $newmsg .= "From: $from" if $from;
  $newmsg .= "To: $to" if $to;
  $newmsg .= "Cc: $cc" if $cc;
  $newmsg .= "Subject: $subject" if $subject;
  $newmsg .= "Date: $date" if $date;
  $newmsg .= "Message-Id: $msgid" if $msgid;

  foreach my $header (keys %{$self->{conf}->{headers_spam}} ) {
    my $data = $self->{conf}->{headers_spam}->{$header};
    my $line = $self->_process_header($header,$data) || "";
    $line = $self->qp_encode_header($line);
    $newmsg .= "X-Spam-$header: $line\n" # add even if empty
  }

  if (defined $self->{conf}->{report_safe_copy_headers}) {
    my %already_added = map { $_ => 1 } qw/from to cc subject date message-id/;

    foreach my $hdr ( @{$self->{conf}->{report_safe_copy_headers}} ) {
      next if ( exists $already_added{lc $hdr} );
      my @hdrtext = $self->{msg}->get_pristine_header($hdr);
      $already_added{lc $hdr}++;

      if ( lc $hdr eq "received" ) { # add Received at the top ...
          my $rhdr = "";
          foreach (@hdrtext) {
            $rhdr .= "$hdr: $_";
          }
          $newmsg = "$rhdr$newmsg";
      }
      else {
        foreach ( @hdrtext ) {
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
  while ($original =~ /^\Q${boundary}\E$/m) {
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
  
  my $mbox = $self->{msg}->get_mbox_seperator() || '';
  return $mbox . $newmsg;
}

sub rewrite_headers {
  my ($self) = @_;

  # put the pristine headers into an array
  my(@pristine_headers) = $self->{msg}->get_pristine_header() =~ /^([^:]+:[ ]+(?:.*\n(?:\s+\S.*\n)*))/mig;
  my $addition = 'headers_ham';

  if($self->{is_spam}) {
      # Deal with header rewriting
      while ( my($header, $value) = each %{$self->{conf}->{rewrite_header}}) {
	unless ( $header =~ /^(?:Subject|From|To)$/ ) {
	  dbg("rewrite: ignoring $header = $value");
	  next;
	}

	# Figure out the rewrite piece
        my $tag = $self->_replace_tags($value);
        $tag =~ s/\n/ /gs;

	# The tag should be a comment for this header ...
	$tag = "($tag)" if ( $header =~ /^(?:From|To)$/ );

	# Go ahead and markup the headers
	foreach ( @pristine_headers ) {
	  # skip non-correct-header or headers that are already tagged
	  next if ( !/^${header}:/i );
          s/^([^:]+:[ ]*)(?:\Q${tag}\E )?/$1${tag} /i;
	}
      }

      $addition = 'headers_spam';
  }

  while ( my($header, $data) = each %{$self->{conf}->{$addition}} ) {
    my $line = $self->_process_header($header,$data) || "";
    $line = $self->qp_encode_header($line);
    push(@pristine_headers, "X-Spam-$header: $line\n");
  }

  my $mbox = $self->{msg}->get_mbox_seperator() || '';
  return join('', $mbox, @pristine_headers, "\n", $self->{msg}->get_pristine_body());
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

  dbg ("encoding header in $cs: $text");
  return $text;
}

sub _process_header {
  my ($self, $hdr_name, $hdr_data) = @_;

  $hdr_data = $self->_replace_tags($hdr_data);
  $hdr_data =~ s/(?:\r?\n)+$//; # make sure there are no trailing newlines ...

  if ($self->{conf}->{fold_headers} ) {
    if ($hdr_data =~ /\n/) {
      $hdr_data =~ s/\s*\n\s*/\n\t/g;
      return $hdr_data;
    } else {
      my $hdr = "X-Spam-$hdr_name!!$hdr_data";
      # use '!!' instead of ': ' so it doesn't wrap on the space
      $Text::Wrap::columns = 79;
      $Text::Wrap::huge = 'wrap';
      $Text::Wrap::break = '(?<=[\s,])';
      $hdr = Text::Wrap::wrap('',"\t",$hdr);
      return (split (/!!/, $hdr, 2))[1]; # just return the data part
    }
  } else {
    $hdr_data =~ s/\n/ /g; # Can't have newlines in headers, unless folded
    return $hdr_data;
  }
}

sub _replace_tags {
  my $self = shift;
  my $text = shift;

  $text =~ s/_(\w+?)(?:\((.*?)\)|)_/${\($self->_get_tag($1,$2 || ""))}/g;
  return $text;
}

sub _get_tag_value_for_yesno {
  my $self   = shift;
  
  return $self->{is_spam} ? "Yes" : "No";
}

sub _get_tag_value_for_score {
  my $self   = shift;
  
  my $score  = sprintf("%2.1f", $self->{score});
  my $rscore = $self->_get_tag_value_for_required_score();
  
  # Do some rounding tricks to avoid the 5.0!=5.0-phenomenon,
  # see <http://bugzilla.spamassassin.org/show_bug.cgi?id=2607>
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

  %tags = ( YESNO     => sub {    $self->_get_tag_value_for_yesno() },
  
            YESNOCAPS => sub { uc $self->_get_tag_value_for_yesno() },

            SCORE => sub { $self->_get_tag_value_for_score() },
            HITS  => sub { $self->_get_tag_value_for_score() },

            REQD  => sub { $self->_get_tag_value_for_required_score() },

            VERSION => sub { Mail::SpamAssassin::Version() },

            SUBVERSION => sub { $Mail::SpamAssassin::SUB_VERSION },

            HOSTNAME => sub {
	      $self->{conf}->{report_hostname} ||
	      Mail::SpamAssassin::Util::fq_hostname();
	    },

            CONTACTADDRESS => sub { $self->{conf}->{report_contact}; },

            BAYES => sub {
              exists($self->{bayes_score}) ?
                        sprintf("%3.4f", $self->{bayes_score}) : "0.5"
            },

            DATE => sub {
              Mail::SpamAssassin::Util::time_to_rfc822_date();
            },

            STARS => sub {
              my $arg = (shift || "*");
              my $length = int($self->{score});
              $length = 50 if $length > 50;
              return $arg x $length;
            },

            AUTOLEARN => sub {
              return($self->{auto_learn_status} || "unavailable");
            },

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
              return $line;
            },

            PREVIEW => sub { $self->get_content_preview() },

            REPORT => sub {
              return "\n" . ($self->{tag_data}->{REPORT} || "");
            },

          );

  if (exists $tags{$tag}) {
      return $tags{$tag}->(@_);
  } elsif ($self->{tag_data}->{$tag}) {
    return $self->{tag_data}->{$tag};
  } else {
    return "";
  }
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

  delete $self->{body_text_array};
  delete $self->{main};
  delete $self->{msg};
  delete $self->{conf};
  delete $self->{res};
  delete $self->{score};
  delete $self->{test_names_hit};
  delete $self->{subtest_names_hit};
  delete $self->{test_logs};
  delete $self->{replacelines};

  $self = { };
}

###########################################################################

sub extract_message_metadata {
  my ($self) = @_;

  $self->{msg}->extract_message_metadata($self->{main});

  foreach my $item (qw(
	relays_trusted relays_trusted_str num_relays_trusted
	relays_untrusted relays_untrusted_str num_relays_untrusted
	))
  {
    $self->{$item} = $self->{msg}->{metadata}->{$item};
  }

  $self->{tag_data}->{RELAYSTRUSTED} = $self->{relays_trusted_str};
  $self->{tag_data}->{RELAYSUNTRUSTED} = $self->{relays_untrusted_str};
  $self->{tag_data}->{LANGUAGES} = $self->{msg}->{metadata}->{"X-Languages"};

  # allow plugins to add more metadata, read the stuff that's there, etc.
  $self->{main}->call_plugins ("parsed_metadata", { permsgstatus => $self });
}

###########################################################################
# Non-public methods from here on.

sub get_decoded_body_text_array {
  return $_[0]->{msg}->{metadata}->get_decoded_body_text_array();
}

sub get_decoded_stripped_body_text_array {
  return $_[0]->{msg}->{metadata}->get_rendered_body_text_array();
}

###########################################################################

sub get {
  my ($self, $request, $defval) = @_;
  local ($_);

  if (exists $self->{hdr_cache}->{$request}) {
    $_ = $self->{hdr_cache}->{$request};
  }
  else {
    my $hdrname = $request;
    my $getaddr = ($hdrname =~ s/:addr$//);
    my $getname = ($hdrname =~ s/:name$//);
    my $getraw = ($hdrname eq 'ALL' || $hdrname =~ s/:raw$//);

    if ($hdrname eq 'ALL') {
      $_ = $self->{msg}->get_all_headers($getraw);
    }
    # EnvelopeFrom: the SMTP MAIL FROM: addr
    elsif ($hdrname eq 'EnvelopeFrom') {
      $getraw = 1;        # this will *not* be encoded unless it's a trick
      $getname = 0;        # avoid other tricks
      $getaddr = 0;
      $_ = $self->get_envelope_from();
    }
    # ToCc: the combined recipients list
    elsif ($hdrname eq 'ToCc') {
      $_ = join ("\n", $self->{msg}->get_header ('To', $getraw));
      if ($_ ne '') {
        chop $_;
        $_ .= ", " if /\S/;
      }
      $_ .= join ("\n", $self->{msg}->get_header ('Cc', $getraw));
      undef $_ if $_ eq '';
    }
    # MESSAGEID: handle lists which move the real message-id to another
    # header for resending.
    elsif ($hdrname eq 'MESSAGEID') {
      $_ = join ("\n", grep { defined($_) && length($_) > 0 }
                $self->{msg}->get_header ('X-Message-Id', $getraw),
                $self->{msg}->get_header ('Resent-Message-Id', $getraw),
                $self->{msg}->get_header ('X-Original-Message-ID', $getraw), # bug 2122
                $self->{msg}->get_header ('Message-Id', $getraw));
    }
    # untrusted relays list, as string
    elsif ($hdrname eq 'X-Spam-Relays-Untrusted') {
      $_ = $self->{relays_untrusted_str};
    }
    # trusted relays list, as string
    elsif ($hdrname eq 'X-Spam-Relays-Trusted') {
      $_ = $self->{relays_trusted_str};
    }
    # a conventional header
    else {
      my @hdrs = $self->{msg}->get_header ($hdrname, $getraw);
      if ($#hdrs >= 0) {
        $_ = join ('', @hdrs);
      }
      else {
        $_ = undef;
      }
    }

    if (defined) {
      if ($getaddr) {
        s/\r?\n//gs;
        s/\s*\(.*?\)//g;            # strip out the (comments)
        s/^[^<]*?<(.*?)>.*$/$1/;    # "Foo Blah" <jm@foo> or <jm@foo>
        s/, .*$//gs;                # multiple addrs on one line: return 1st
        s/ ;$//gs;                  # 'undisclosed-recipients: ;'
      }
      elsif ($getname) {
        chomp; s/\r?\n//gs;
        s/^[\'\"]*(.*?)[\'\"]*\s*<.+>\s*$/$1/g # Foo Blah <jm@foo>
            or s/^.+\s\((.*?)\)\s*$/$1/g;           # jm@foo (Foo Blah)
      }
    }
    $self->{hdr_cache}->{$request} = $_;
  }

  if (!defined) {
    $defval ||= '';
    $_ = $defval;
  }

  $_;
}

###########################################################################

sub decode_mime_bit {
  my ($self, $encoding, $text) = @_;
  local ($_) = $text;

  $encoding = lc($encoding);

  if ($encoding eq 'utf-16') {
    # we just dump the high bits and keep the 8-bit characters
    s/_/ /g;
    s/=00//g;
    s/\=([0-9A-F]{2})/chr(hex($1))/ge;
  }
  else {
    # keep 8-bit stuff, forget mapping charsets though
    s/_/ /g;
    s/\=([0-9A-F]{2})/chr(hex($1))/ge;
  }

  return $_;
}

sub ran_rule_debug_code {
  my ($self, $rulename, $ruletype, $bit) = @_;

  return '' if (!$Mail::SpamAssassin::DEBUG->{enabled}
                && !$self->{save_pattern_hits});

  my $log_hits_code = '';
  my $save_hits_code = '';

  if ($Mail::SpamAssassin::DEBUG->{enabled} &&
      ($Mail::SpamAssassin::DEBUG->{rulesrun} & $bit) != 0)
  {
    # note: keep this in 'single quotes' to avoid the $ & performance hit,
    # unless specifically requested by the caller.
    $log_hits_code = ': match=\'$&\'';
  }

  if ($self->{save_pattern_hits}) {
    $save_hits_code = '
        $self->{pattern_hits}->{q{'.$rulename.'}} = $&;
    ';
  }

  return '
    dbg ("Ran '.$ruletype.' rule '.$rulename.' ======> got hit'.
        $log_hits_code.'", "rulesrun", '.$bit.');
    '.$save_hits_code.'
  ';

  # do we really need to see when we *don't* get a hit?  If so, it should be a
  # separate level as it's *very* noisy.
  #} else {
  #  dbg ("Ran '.$ruletype.' rule '.$rulename.' but did not get hit", "rulesrun", '.
  #      $bit.');
}

sub hash_line_for_rule {
  my ($self, $rulename) = @_;
  return "\n".'#line 1 "'.
        $self->{conf}->{source_file}->{$rulename}.
        ', rule '.$rulename.',"';
}

###########################################################################

sub do_head_tests {
  my ($self) = @_;
  local ($_);

  # note: we do this only once for all head pattern tests.  Only
  # eval tests need to use stuff in here.
  $self->{test_log_msgs} = ();        # clear test state

  dbg ("running header regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS};

  # speedup code provided by Matt Sergeant
  if (defined &Mail::SpamAssassin::PerMsgStatus::_head_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_head_tests($self);
    return;
  }

  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $rule) = each %{$self->{conf}{head_tests}}) {
    my $def = '';
    my ($hdrname, $testtype, $pat) =
        $rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    if (!defined $pat) {
      warn "invalid rule: $rulename\n";
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
          '. $self->ran_rule_debug_code ($rulename,"header regex", 1) . '
        }
      }';

  }

  # clear out a previous version of this fn, if already defined
  if (defined &_head_tests) { undef &_head_tests; }

  $evalstr = <<"EOT";
{
    package Mail::SpamAssassin::PerMsgStatus;

    $evalstr2

    sub _head_tests {
        my (\$self) = \@_;

        $evalstr;
    }

    1;
}
EOT

  eval $evalstr;

  if ($@) {
    warn "Failed to run header SpamAssassin tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_head_tests($self);
  }
}

sub do_body_tests {
  my ($self, $textary) = @_;
  local ($_);

  dbg ("running body-text per-line regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_BODY_TESTS};

  $self->{test_log_msgs} = ();        # clear test state
  if ( defined &Mail::SpamAssassin::PerMsgStatus::_body_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_body_tests($self, @$textary);
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{body_tests}}) {
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
           foreach ( @_ ) {
             '.$self->hash_line_for_rule($rulename).'
             if ('.$pat.') { 
                $self->got_body_pattern_hit (q{'.$rulename.'}); 
                '. $self->ran_rule_debug_code ($rulename,"body-text regex", 2) . '
		# Ok, we hit, stop now.
		last;
             }
           }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &_body_tests) { undef &_body_tests; }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _body_tests {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("Failed to compile body SpamAssassin tests, skipping:\n".
              "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_body_tests($self, @$textary);
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
my $unreserved = "A-Za-z0-9\Q$mark\E\x00-\x08\x0b\x0c\x0e-\x1f";
my $uricSet = quotemeta($reserved) . $unreserved . "%";

my $schemeRE = qr/(?:https?|ftp|mailto|javascript|file)/;

my $uricCheat = $uricSet;
$uricCheat =~ tr/://d;

my $schemelessRE = qr/(?<![.=])(?:www\.|ftp\.)/;
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

# Discard all but one of identical successive entries in an array.
# The input must be sorted if you want the returned array to be
# without identical entries.
sub _uniq {
  my $previous;
  my @uniq;
  if (@_) {
    push(@uniq, ($previous = shift(@_)));
  }
  foreach my $current (@_) {
    next if ($current eq $previous);
    push(@uniq, ($previous = $current));
  }
  return @uniq;
}

sub get_uri_list {
  my ($self) = @_;

  #$self->{found_bad_uri_encoding} = 0;

  my $textary = $self->get_decoded_body_text_array();
  my ($rulename, $pat, @uris);
  local ($_);

  my $text;

  for (@$textary) {
    # NOTE: do not modify $_ in this loop
    while (/($uriRe)/go) {
      my $uri = $1;

      $uri =~ s/^<(.*)>$/$1/;
      $uri =~ s/[\]\)>#]$//;

      if ($uri !~ /^${schemeRE}:/io) {
        # If it's a hostname that was just sitting out in the
        # open, without a protocol, and not inside of an HTML tag,
        # the we should add the proper protocol in front, rather
        # than using the base URI.
        if ($uri =~ /^www\d*\./i) {
          # some spammers are using unschemed URIs to escape filters
          push (@uris, $uri);
          $uri = "http://$uri";
        }
        elsif ($uri =~ /^ftp\./i) {
          push (@uris, $uri);
          $uri = "ftp://$uri";
        }
      }

      # warn("Got URI: $uri\n");
      push @uris, $uri;
    }
    while (/($Addr_spec_re)/go) {
      my $uri = $1;

      $uri = "mailto:$uri";

      #warn("Got URI: $uri\n");
      push @uris, $uri;
    }
  }

  # get URIs from HTML parsing
  if (defined $self->{html}{uri}) {
    push @uris, @{ $self->{html}{uri} };
  }

  # Make sure we catch bad encoding tricks ...
  foreach my $uri ( @uris ) {
    next if ( $uri =~ /^mailto:/i );

    # bug 2844
    # http://www.foo.biz?id=3 -> http://www.foo.biz/?id=3
    $uri =~ s/^(https?:\/\/[^\/\?]+)\?/$1\/?/;

    # deal with encoding of chars ...
    # this is just the set of printable chars, minus ' ' (aka: dec 33-126, hex 21-7e)
    #
    $uri =~ s/\&\#0*(3[3-9]|[4-9]\d|1[01]\d|12[0-6]);/sprintf "%c",$1/e;
    $uri =~ s/\&\#x0*(2[1-9]|[3-6][a-f0-9]|7[0-9a-e]);/sprintf "%c",hex($1)/ei;

    my($nuri, $unencoded, $encoded) = Mail::SpamAssassin::Util::URLEncode($uri);
    if ( $nuri ne $uri ) {
      push(@uris, $nuri);

      # allow some unencodings to be ok ...
      # This is essentially HTTP_EXCESSIVE_ESCAPES ...
      #if ( $unencoded =~ /[a-zA-Z0-9\/]/ ) {
      #  $self->{found_bad_uri_encoding} = 1;
      #}
    }
  }

  # remove duplicates
  @uris = _uniq(sort(@uris));

  $self->{uri_list} = \@uris;
  dbg("uri tests: Done uriRE");
  return @{$self->{uri_list}};
}

sub do_body_uri_tests {
  my ($self, $textary) = @_;
  local ($_);

  dbg ("running uri tests; score so far=".$self->{score});
  my @uris = $self->get_uri_list();

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_URI_TESTS};

  $self->{test_log_msgs} = ();        # clear test state
  if (defined &Mail::SpamAssassin::PerMsgStatus::_body_uri_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_body_uri_tests($self, @uris);
    return;
  }

  # otherwise build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{uri_tests}}) {

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
       foreach ( @_ ) {
         '.$self->hash_line_for_rule($rulename).'
         if ('.$pat.') { 
            $self->got_uri_pattern_hit (q{'.$rulename.'});
            '. $self->ran_rule_debug_code ($rulename,"uri test", 4) . '
         }
       }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &_body_uri_tests) { undef &_body_uri_tests; }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _body_uri_tests {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("Failed to compile URI SpamAssassin tests, skipping:\n".
          "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_body_uri_tests($self, @uris);
  }
}

sub do_rawbody_tests {
  my ($self, $textary) = @_;
  local ($_);

  dbg ("running raw-body-text per-line regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS};

  $self->{test_log_msgs} = ();        # clear test state
  if (defined &Mail::SpamAssassin::PerMsgStatus::_rawbody_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_rawbody_tests($self, @$textary);
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my $evalstr2 = '';

  while (my($rulename, $pat) = each %{$self->{conf}{rawbody_tests}}) {

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
       foreach ( @_ ) {
         '.$self->hash_line_for_rule($rulename).'
         if ('.$pat.') { 
            $self->got_body_pattern_hit (q{'.$rulename.'});
            '. $self->ran_rule_debug_code ($rulename,"body_pattern_hit", 8) . '
         }
       }
    }
    ';
  }

  # clear out a previous version of this fn, if already defined
  if (defined &_rawbody_tests) { undef &_rawbody_tests; }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  $evalstr2

  sub _rawbody_tests {
    my \$self = shift;
    $evalstr;
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
    warn("Failed to compile body SpamAssassin tests, skipping:\n".
              "\t($@)\n");
    $self->{rule_errors}++;
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_rawbody_tests($self, @$textary);
  }
}

sub do_full_tests {
  my ($self, $fullmsgref) = @_;
  local ($_);
  
  dbg ("running full-text regexp tests; score so far=".$self->{score});

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_FULL_TESTS};

  $self->{test_log_msgs} = ();        # clear test state

  if (defined &Mail::SpamAssassin::PerMsgStatus::_full_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_full_tests($self, $fullmsgref);
    return;
  }

  # build up the eval string...
  my $evalstr = '';

  while (my($rulename, $pat) = each %{$self->{conf}{full_tests}}) {
    $evalstr .= '
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        '.$self->hash_line_for_rule($rulename).'
        if ($$fullmsgref =~ '.$pat.') {
          $self->got_body_pattern_hit (q{'.$rulename.'});
          '. $self->ran_rule_debug_code ($rulename,"full-text regex", 16) . '
        }
      }
    ';
  }

  if (defined &_full_tests) { undef &_full_tests; }

  # and compile it.
  $evalstr = <<"EOT";
  {
    package Mail::SpamAssassin::PerMsgStatus;

    sub _full_tests {
        my (\$self, \$fullmsgref) = \@_;
        study \$\$fullmsgref;
        $evalstr
    }

    1;
  }
EOT
  eval $evalstr;

  if ($@) {
    warn "Failed to compile full SpamAssassin tests, skipping:\n".
              "\t($@)\n";
    $self->{rule_errors}++;
  } else {
    Mail::SpamAssassin::PerMsgStatus::_full_tests($self, $fullmsgref);
  }
}

###########################################################################

sub do_head_eval_tests {
  my ($self) = @_;
  $self->run_eval_tests ($self->{conf}->{head_evals}, '');
}

sub do_body_eval_tests {
  my ($self, $bodystring) = @_;
  $self->run_eval_tests ($self->{conf}->{body_evals}, 'BODY: ', $bodystring);
}

sub do_rawbody_eval_tests {
  my ($self, $bodystring) = @_;
  $self->run_eval_tests ($self->{conf}->{rawbody_evals}, 'RAW: ', $bodystring);
}

sub do_full_eval_tests {
  my ($self, $fullmsgref) = @_;
  $self->run_eval_tests ($self->{conf}->{full_evals}, '', $fullmsgref);
}

###########################################################################

sub do_meta_tests {
  my ($self) = @_;
  local ($_);

  dbg( "running meta tests; score so far=" . $self->{score} );

  my $doing_user_rules = 
    $self->{conf}->{user_rules_to_compile}->{Mail::SpamAssassin::Conf::TYPE_META_TESTS};

  # speedup code provided by Matt Sergeant
  if ( defined &Mail::SpamAssassin::PerMsgStatus::_meta_tests && !$doing_user_rules) {
    Mail::SpamAssassin::PerMsgStatus::_meta_tests($self);
    return;
  }

  my ( %rule_deps, %setup_rules, %meta, $rulename );
  my $evalstr = '';

  # Get the list of meta tests
  my @metas = keys %{ $self->{conf}{meta_tests} };

  # Go through each rule and figure out what we need to do
  foreach $rulename (@metas) {
    my $rule   = $self->{conf}->{meta_tests}->{$rulename};
    my $token;

    # Lex the rule into tokens using a rather simple RE method ...
    my @tokens =
      $rule =~ m/(
	\w+|	        	                # Rule Name
	[\(\)]|					# Parens
	\|\||					# Boolean OR
	\&\&|					# Boolean AND
	\^|					# Boolean XOR
	!|					# Boolean NOT
	>=?|					# GT or EQ
	<=?|					# LT or EQ
	==|					# EQ
	!=|					# NEQ
	[\+\-\*\/]|				# Mathematical Operator
	[\?:]|                                  # ? : Operator
	\d+					# A Number
      )/gx;

    # Set the rule blank to start
    $meta{$rulename} = "";

    # By default, there are no dependencies for a rule
    @{ $rule_deps{$rulename} } = ();

    # Go through each token in the meta rule
    foreach $token (@tokens) {

      # Numbers can't be rule names
      if ( $token =~ /^(?:\W+|\d+)$/ ) {
        $meta{$rulename} .= "$token ";
      }
      else {
        $meta{$rulename} .= "\$self->{'tests_already_hit'}->{'$token'} ";
        $setup_rules{$token}=1;

        # If the token is another meta rule, add it as a dependency
        push ( @{ $rule_deps{$rulename} }, $token )
          if ( exists $self->{conf}{meta_tests}->{$token} );
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
    for ( my $i = 0 ; $i <= $#metas ; $i++ ) {

      # If we depend on meta rules that haven't run yet, skip it
      next if ( grep( $metas{$_}, @{ $rule_deps{ $metas[$i] } } ) );

      # Add this meta rule to the eval line
      $evalstr .= '  if ('.$meta{$metas[$i]}.') { $self->got_hit (q#'.$metas[$i].'#, ""); }'."\n";
      splice @metas, $i--, 1;    # remove this rule from our list
    }
  } while ( $#metas != $count && $#metas > -1 ); # run until we can't go anymore

  # If there are any rules left, we can't solve the dependencies so complain
  my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
  foreach $rulename (@metas) {
    dbg( "Excluding meta test $rulename; unsolved meta dependencies: "
        . join ( ", ", grep($metas{$_},@{ $rule_deps{$rulename} }) ) );
  }

  if (defined &_meta_tests) { undef &_meta_tests; }

  # setup the environment for meta tests
  $evalstr = <<"EOT";
{
    package Mail::SpamAssassin::PerMsgStatus;

    sub _meta_tests {
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
    warn "Failed to run header SpamAssassin tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_meta_tests($self);
  }
}    # do_meta_tests()

###########################################################################

sub run_eval_tests {
  my ($self, $evalhash, $prepend2desc, @extraevalargs) = @_;
  local ($_);
  
  my $debugenabled = $Mail::SpamAssassin::DEBUG->{enabled};

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
	dbg ("no method found for eval test $function");
      }
    }

    eval {
      $result = $self->$function(@args);
    };

    if ($@) {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
                      "\t($@)\n";
      $self->{rule_errors}++;
      next;
    }

    if ($result) {
        $self->got_hit ($rulename, $prepend2desc);
        dbg("Ran run_eval_test rule $rulename ======> got hit", "rulesrun", 32) if $debugenabled;
    } else {
        #dbg("Ran run_eval_test rule $rulename but did not get hit", "rulesrun", 32) if $debugenabled;
    }
  }
}

sub register_plugin_eval_glue {
  my ($self, $pluginobj, $function) = @_;

  dbg ("registering glue method for $function ($pluginobj)");
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
    warn "Failed to run header SpamAssassin tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
}

###########################################################################

sub run_rbl_eval_tests {
  my ($self, $evalhash) = @_;
  my ($rulename, $pat, @args);
  local ($_);

  if ($self->{main}->{local_tests_only}) {
    dbg ("local tests only, ignoring RBL eval", "rulesrun", 32);
    return 0;
  }
  
  my $debugenabled = $Mail::SpamAssassin::DEBUG->{enabled};

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
      warn "Failed to run $rulename RBL SpamAssassin test, skipping:\n".
                "\t($@)\n";
      $self->{rule_errors}++;
      next;
    }
  }
}

###########################################################################

sub got_body_pattern_hit {
  my ($self, $rulename) = @_;

  # only allow each test to hit once per mail
  return if (defined $self->{tests_already_hit}->{$rulename});

  $self->got_hit ($rulename, 'BODY: ');
}

sub got_uri_pattern_hit {
  my ($self, $rulename) = @_;

  # only allow each test to hit once per mail
  # TODO: Move this into the rule matcher
  return if (defined $self->{tests_already_hit}->{$rulename});

  $self->got_hit ($rulename, 'URI: ');
}

###########################################################################

# note: only eval tests should store state in $self->{test_log_msgs};
# pattern tests do not.
#
# the clearing of the test state is now inlined as:
#
# $self->{test_log_msgs} = ();        # clear test state

sub _handle_hit {
    my ($self, $rule, $score, $area, $desc) = @_;

    # ignore meta-match sub-rules.
    if ($rule =~ /^__/) { push(@{$self->{subtest_names_hit}}, $rule); return; }

    my $tflags = $self->{conf}->{tflags}->{$rule}; $tflags ||= '';

    # ignore 'noautolearn' rules when considering score for Bayes auto-learning
    if ($tflags =~ /\bnoautolearn\b/i) {
      $self->{learned_points} += $score;
    }
    else {
      $self->{score} += $score;
      if (!$self->{conf}->maybe_header_only ($rule)) {
        $self->{body_only_points} += $score;
      }
      if (!$self->{conf}->maybe_body_only ($rule)) {
        $self->{head_only_points} += $score;
      }
    }

    push(@{$self->{test_names_hit}}, $rule);
    $area ||= '';

    if ($score >= 10 || $score <= -10) {
      $score = sprintf("%4.0f", $score);
    }
    else {
      $score = sprintf("%4.1f", $score);
    }

    # save both summaries
    $self->{tag_data}->{REPORT} .= sprintf ("* %s %s %s%s\n%s",
                                       $score, $rule, $area, $desc,
                                       ($self->{test_log_msgs}->{TERSE} ?
                                        "*      " . $self->{test_log_msgs}->{TERSE} : '')
                                   );
    $self->{tag_data}->{SUMMARY} .= sprintf ("%s %-22s %s%s\n%s",
                                       $score, $rule, $area, $desc,
                                       ($self->{test_log_msgs}->{LONG} || ''));
    $self->{test_log_msgs} = ();        # clear test logs
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
  
  # Get the SMTP MAIL FROM:, aka. the "envelope sender", if our
  # calling app has helpfully marked up the source message
  # with it.  Various MTAs and calling apps each have their
  # own idea of what header to use for this!   see
  # http://bugzilla.spamassassin.org/show_bug.cgi?id=2142 .

  my $envf;

  # WARNING: a lot of list software adds an X-Sender for the original env-from
  # (including Yahoo! Groups).  Unfortunately, fetchmail will pick it up and
  # reuse it as the env-from for *its* delivery -- even though the list software
  # had used a different env-from in the intervening delivery.   Hence, if this
  # header is present, and there's a fetchmail sig in the Received lines, we
  # cannot trust any Envelope-From headers, since they're likely to be
  # incorrect fetchmail guesses.

  if ($self->get ("X-Sender", 1)) {
    my $rcvd = $self->get ("Received", 1);
    if ($rcvd =~ /\(fetchmail/) {
      dbg ("X-Sender and fetchmail signatures found, cannot trust envelope-from");
      return undef;
    }
  }

  # procmailrc notes this, amavisd are adding it, we recommend it
  if ($envf = $self->get ("X-Envelope-From", 1)) { goto ok; }

  # qmail, new-inject(1)
  if ($envf = $self->get ("Envelope-Sender", 1)) { goto ok; }

  # Postfix, sendmail, also mentioned in RFC821
  if ($envf = $self->get ("Return-Path", 1)) { goto ok; }

  # give up.
  return undef;

ok:
  $envf =~ s/^<*//gs;                # remove <
  $envf =~ s/>*\s*$//gs;        # remove >, whitespace, newlines
  return $envf;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

# this is a lazily-written temporary file containing the full text
# of the message, for use with external programs like pyzor and
# dccproc, to avoid hangs due to buffering issues.   Methods that
# need this, should call $self->create_fulltext_tmpfile($fulltext)
# to retrieve the temporary filename; it will be created if it has
# not already been.
#
# (SpamAssassin3 note: we should use tmp files to hold the message
# for 3.0 anyway, as noted by Matt previously; this will then
# be obsolete.)
#
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

