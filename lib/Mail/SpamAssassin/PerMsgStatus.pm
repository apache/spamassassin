=head1 NAME

Mail::SpamAssassin::PerMsgStatus - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = new Mail::SpamAssassin ({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin.cf'
  });
  my $mail = Mail::Audit->new();

  my $status = $spamtest->check ($mail);
  if ($status->is_spam()) {
    $status->rewrite_mail ();
    $mail->accept("caught_spam");
  }
  ...


=head1 DESCRIPTION

The Mail::SpamAssassin C<check()> method returns an object of this
class.  This object encapsulates all the per-message state.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PerMsgStatus;

use Carp;
use strict;

use Mail::SpamAssassin::EvalTests;
use Mail::SpamAssassin::ExposedMessage;
use Mail::SpamAssassin::EncappedMessage;
use Mail::Audit;

use vars	qw{
  	@ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg) = @_;

  my $self = {
    'main'		=> $main,
    'msg'		=> $msg,
    'hits'		=> 0,
    'test_logs'		=> '',
    'tests_already_hit' => { },
  };

  $self->{conf} = $self->{main}->{conf};

  bless ($self, $class);
  $self;
}

###########################################################################

sub check {
  my ($self) = @_;
  local ($_);

  # in order of slowness; fastest first, slowest last.
  # we do ALL the tests, even if a spam triggers lots of them early on.
  # this lets us see ludicrously spammish mails (score: 40) etc., which
  # (TODO) we can then immediately submit to spamblocking services.

  {
    $self->{msg_body_array} = $self->{msg}->get_body();
    $self->{full_msg_string} = $self->{msg}->get_all_headers()."\n".
				  join ('', @{$self->{msg_body_array}});

    $self->do_head_tests();
    $self->do_body_tests();
    $self->do_body_eval_tests();
    $self->do_full_tests();
    $self->do_full_eval_tests();
    $self->do_head_eval_tests();

    # these are big, so delete them now.
    delete $self->{msg_body_array};
    delete $self->{full_msg_string};
  }

  $self->{required_hits} = $self->{conf}->{required_hits};
  $self->{is_spam} = ($self->{hits} >= $self->{required_hits});

  $_ = $self->{conf}->{report_template};
  $_ ||= '(no report template found)';

  s/_HITS_/$self->{hits}/gs;
  s/_REQD_/$self->{required_hits}/gs;
  s/_SUMMARY_/$self->{test_logs}/gs;
  s/_VER_/$Mail::SpamAssassin::VERSION/gs;
  s/_HOME_/$Mail::SpamAssassin::HOME_URL/gs;
  s/^/SPAM: /gm;

  $self->{report} = "\n".$_."\n";
}

###########################################################################

=item $isspam = $status->is_spam ()

After a mail message has been checked, this method can be called.  It will
return 1 for mail determined likely to be spam, 0 if it does not seem
spam-like.

=cut

sub is_spam {
  my ($self) = @_;
  return $self->{is_spam};
}

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

=item $status->rewrite_mail ()

Rewrite the mail message.  This will add headers, and possibly body text, to
reflect it's spam or not-spam status.

The modifications made are as follows:

=over 4

=item Subject: header for spam mails

The string C<*****SPAM*****> is prepended to the subject.

=item X-Spam-Status: header for spam mails

A string, C<Yes, hits=nn required=nn> is set in this header to reflect
the filter status.

=item X-Spam-Flag: header for spam mails

Set to C<YES>.

=item Content-Type: header for spam mails

Set to C<text/plain>, in order to defang HTML mail or other active
content that could "call back" to the spammer.

=item spam mail body text

The SpamAssassin report is added to top of the mail message body.

=item X-Spam-Status: header for non-spam mails

A string, C<No, hits=nn required=nn> is set in this header to reflect
the filter status.

=back

=cut

sub rewrite_mail {
  my ($self) = @_;

  if ($self->{is_spam}) {
    $self->rewrite_as_spam();
  } else {
    $self->rewrite_as_non_spam();
  }
}

sub rewrite_as_spam {
  my ($self) = @_;

  # First, rewrite the subject line.
  $_ = $self->{msg}->get_header ("Subject"); $_ ||= '';
  s/^/\*\*\*\*\*SPAM\*\*\*\*\* /g;
  $self->{msg}->replace_header ("Subject", $_);

  # add some headers...
  $_ = sprintf ("Yes, hits=%d required=%d",
  			$self->{hits}, $self->{required_hits});

  $self->{msg}->put_header ("X-Spam-Status", $_);
  $self->{msg}->put_header ("X-Spam-Flag", 'YES');

  # defang HTML mail; change it to text-only.
  $self->{msg}->replace_header ("Content-Type", "text/plain");
  $self->{msg}->delete_header ("Content-type"); 	# just in case

  my $lines = $self->{msg}->get_body();
  unshift (@{$lines}, split (/$/, $self->{report}));
  $self->{msg}->replace_body ($lines);

  $self->{msg}->{audit};
}

sub rewrite_as_non_spam {
  my ($self) = @_;

  $_ = sprintf ("No, hits=%d required=%d", $self->{hits},
        $self->{required_hits});
  $self->{msg}->put_header ("X-Spam-Status", $_);
  $self->{msg}->{audit};
}

=item $status->handle_auto_report ()

If this mail message has a high enough hit score, report it to spam-tracking
services straight away, without waiting for user confirmation.  See the
documentation for L<spamassassin>'s C<-r> switch for details on what
spam-tracking services are used.

=cut

sub handle_auto_report {
  my ($self) = @_;

  dbg ("auto-report? score=".$self->{hits}.
  			" threshold=".$self->{conf}->{auto_report_threshold});

  if ($self->{hits} >= $self->{conf}->{auto_report_threshold}) {
    dbg ("score is high enough to automatically report this as spam");
    $self->{main}->report_as_spam ($self->{msg}->{audit});
  }
}

###########################################################################
# Non-public methods from here on.

sub get_body_text {
  my ($self) = @_;
  local ($_);

  if (defined $self->{body_text}) { return $self->{body_text}; }

  my $ctype = $self->{msg}->get_header ('Content-Type');
  $ctype ||=  $self->{msg}->get_header ('Content-type');
  $ctype ||=  '';

  my $body = $self->{msg}->get_body();
  if ($ctype !~ /boundary="(.*)"/) {
    $self->{body_text} = $body;
    return $self->{body_text};
  }

  # else it's a multipart MIME message. Skip non-text parts and
  # just assemble the body array from the text bits.
  $self->{body_text} = [ ];
  my $multipart_boundary = "--$1\n";
  my $end_boundary = "--$1--\n";

  my @workingbody = @{$body};

  while ($_ = (shift @workingbody)) {
    push (@{$self->{body_text}}, $_);

    if ($multipart_boundary eq $_) {
      $_ = (shift @workingbody);
      last unless defined $_;
      next if /^Content-[Tt]ype: (?:text\/\S+|multipart\/alternative)/;

      # skip this attachment, it's non-text.
      while ($_ = (shift @workingbody)) {
	last if ($multipart_boundary eq $_ || $end_boundary eq $_);
      }
    }
  }

  return $self->{body_text};
}

###########################################################################

sub get {
  my ($self, $hdrname) = @_;
  local ($_);

  if ($hdrname eq 'ALL') { return $self->{msg}->get_all_headers(); }

  my $getaddr = 0;
  if ($hdrname =~ s/:addr$//) { $getaddr = 1; }

  $_ = join ("\n", $self->{msg}->get_header ($hdrname));
  if ($hdrname eq 'Message-Id' && (!defined($_) || $_ eq '')) {
    $_ = join ("\n", $self->{msg}->get_header ('Message-ID'));	# news-ish
  }
  $_ ||= '';

  if ($getaddr) {
    s/^.*?<.+>\s*$/$1/g			# Foo Blah <jm@foo>
    	or s/^(.+)\s\(.*?\)\s*$/$1/g;	# jm@foo (Foo Blah)
  }

  $_;
}

###########################################################################

sub do_head_tests {
  my ($self) = @_;
  local ($_);

  dbg ("running header regexp tests; score so far=".$self->{hits});

  my ($rulename, $rule);
  while (($rulename, $rule) = each %{$self->{conf}->{head_tests}}) {
    my $hit = 0;
    $self->clear_test_state();

    my ($hdrname, $testtype, $pat) = 
    		$rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    $_ = $self->get ($hdrname);

    if (!eval 'if ($_ '.$testtype.'~ '.$pat.') { $hit = 1; } 1;') {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
      		"\t$rule ($@)\n";
      next;
    }

    if ($hit) { $self->got_hit ($rulename, ''); }
  }
}

sub do_body_tests {
  my ($self) = @_;
  my ($rulename, $pat);
  local ($_);
  $self->clear_test_state();

  dbg ("running body-text per-line regexp tests; score so far=".$self->{hits});

  # build up the eval string...
  my $evalstr = '';
  while (($rulename, $pat) = each %{$self->{conf}->{body_tests}}) {
    $evalstr .= '
      if ('.$pat.') { $self->got_body_pattern_hit (q{'.$rulename.'}); }
    ';
  }

  # generate the loop that goes through each line...
  my $textary = $self->get_body_text();
  $evalstr = 'foreach $_ (@{$textary}) { study; '.$evalstr.'; }';

  # and run it.
  if (!eval $evalstr.'1;') {
    warn "Failed to run body SpamAssassin tests, skipping:\n".
	      "\t($@)\n";
  }
}

sub do_full_tests {
  my ($self) = @_;
  my ($rulename, $pat);
  local ($_);
  $self->clear_test_state();

  dbg ("running full-text regexp tests; score so far=".$self->{hits});

  # build up the eval string...
  my $evalstr = '';
  while (($rulename, $pat) = each %{$self->{conf}->{full_tests}}) {
    $evalstr .= '
      if ('.$pat.') { $self->got_hit (q{'.$rulename.'}, q{}); }
    ';
  }

  # and run it.
  $_ = $self->{full_msg_string};
  if (!eval 'study; '.$evalstr.'; 1;') {
    warn "Failed to run full SpamAssassin tests, skipping:\n".
	      "\t($@)\n";
  }
}

###########################################################################

sub do_head_eval_tests {
  my ($self) = @_;
  $self->run_eval_tests ($self->{conf}->{head_evals}, '');
}

sub do_body_eval_tests {
  my ($self) = @_;
  $self->run_eval_tests ($self->{conf}->{body_evals}, 'BODY: ', $self->{msg_body_array});
}

sub do_full_eval_tests {
  my ($self) = @_;
  $self->run_eval_tests ($self->{conf}->{full_evals}, '', $self->{full_msg_string});
}

###########################################################################

sub run_eval_tests {
  my ($self, $evalhash, $prepend2desc, @extraevalargs) = @_;
  my ($rulename, $pat, $evalsub, @args);
  local ($_);

  while (($rulename, $evalsub) = each %{$evalhash}) {
    my $result;
    $self->clear_test_state();

    @args = ();
    if (scalar @extraevalargs >= 0) { push (@args, '@extraevalargs'); }

    $evalsub =~ s/\s*\((.*?)\)\s*$//;
    if (defined $1 && $1 ne '') { push (@args, $1); }

    my $evalstr = '$result = $self->'.$evalsub.'('.join (', ', @args).');';
    dbg ("running: $evalstr");
    if (!eval $evalstr.'1;') {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
      		"\t($@)\n";
      next;
    }

    if ($result) { $self->got_hit ($rulename, $prepend2desc); }
  }
}

###########################################################################

sub got_body_pattern_hit {
  my ($self, $rulename) = @_;

  # only allow each test to hit once per mail
  return if (defined $self->{tests_already_hit}->{$rulename});
  $self->{tests_already_hit}->{$rulename} = 1;

  $self->got_hit ($rulename, 'BODY: ');
}

###########################################################################

sub clear_test_state {
  my ($self) = @_;
  $self->{test_log_msgs} = '';
}

sub handle_hit {
  my ($self, $rule, $area, $deffallbackdesc) = @_;

  my $desc = $self->{conf}->{descriptions}->{$rule};
  $desc ||= $deffallbackdesc;
  $desc ||= $rule;

  my $score = $self->{conf}->{scores}->{$rule};
  $self->{hits} += $score;

  $self->{test_logs} .= sprintf ("%-16s %s%s\n%s",
		"Hit! (".$score." point".($score == 1 ? "":"s").")",
		$area, $desc, $self->{test_log_msgs});
}

sub got_hit {
  my ($self, $rule, $prepend2desc) = @_;

  my $txt = $self->{conf}->{full_tests}->{$rule};
  $txt ||= $self->{conf}->{full_evals}->{$rule};
  $txt ||= $self->{conf}->{head_tests}->{$rule};
  $txt ||= $self->{conf}->{body_tests}->{$rule};
  $self->handle_hit ($rule, $prepend2desc, $txt);
}

sub test_log {
  my ($self, $msg) = @_;
  $self->{test_log_msgs} .= sprintf ("%16s [%s]\n", "", $msg);
}

###########################################################################

sub work_out_local_domain {
  my ($self) = @_;

  # TODO -- if needed.

  # my @rcvd = $self->{msg}->get_header ("Received");
  # print "JMD ".join (' ',@rcvd);

# from dogma.slashnull.org (dogma.slashnull.org [212.17.35.15]) by
    # mail.netnoteinc.com (Postfix) with ESMTP id 3E010114097 for
    # <jm@netnoteinc.com>; Thu, 19 Apr 2001 07:28:53 +0000 (Eire)
 # (from jm@localhost) by dogma.slashnull.org (8.9.3/8.9.3) id
    # IAA28324 for jm@netnoteinc.com; Thu, 19 Apr 2001 08:28:53 +0100
 # from gaganan.com ([211.51.69.106]) by dogma.slashnull.org
    # (8.9.3/8.9.3) with SMTP id IAA28319 for <jm@jmason.org>; Thu,
    # 19 Apr 2001 08:28:50 +0100

}

sub dbg { Mail::SpamAssassin::dbg (@_); }

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

