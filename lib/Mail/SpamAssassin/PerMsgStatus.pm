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
use Mail::Audit;

use vars	qw{
  	@ISA
};

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    'main'	=> shift,
    'audit'	=> shift,

    'hits'		=> 0,
    'test_logs'		=> '',
    'tests_already_hit' => { },
  };
  bless ($self, $class);

  $self->{conf} = $self->{main}->{conf};

  $self;
}

###########################################################################

sub check {
  my ($self) = @_;

  $self->do_head_tests();          # pretty quick, these ones
  $self->do_body_tests();          # a bit more expensive than the heads
  $self->do_head_eval_tests();     # most expensive of all; DNS lookups etc

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
  my $mail = $self->{audit};

  # First, rewrite the subject line.
  $_ = $mail->get ("Subject"); $_ ||= '';
  s/^/\*\*\*\*\*SPAM\*\*\*\*\* /g;
  $mail->{obj}->head->replace ("Subject", $_);

  # add some headers...
  $_ = sprintf ("Yes, hits=%d required=%d", $self->{hits},
        $self->{required_hits});
  $mail->put_header ("X-Spam-Status", $_);
  $mail->put_header ("X-Spam-Flag", 'YES');

  # defang HTML mail; change it to text-only.
  $mail->{obj}->head->replace ("Content-Type", "text/plain");
  $mail->{obj}->head->delete ("Content-type");  # just in case

  my $lines = $mail->{obj}->body();
  unshift (@{$lines}, split (/$/, $self->{report}));
  $mail->{obj}->body ($lines);
  $mail;
}

sub rewrite_as_non_spam {
  my ($self) = @_;
  my $mail = $self->{audit};

  $_ = sprintf ("No, hits=%d required=%d", $self->{hits},
        $self->{required_hits});
  $mail->put_header ("X-Spam-Status", $_);
  $mail;
}

###########################################################################
# Non-public methods from here on.

sub get_body_text {
  my ($self) = @_;
  local ($_);

  if (defined $self->{body_text}) { return $self->{body_text}; }

  my $head = $self->{audit}->{obj}->head();
  my $body = $self->{audit}->{obj}->body();

  my $ctype = $head->get ('Content-Type');
  $ctype ||=  $head->get ('Content-type');
  $ctype ||=  '';

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

sub get_header {
  my ($self, $hdrname) = @_;
  local ($_);

  my $getaddr = 0;
  if ($hdrname =~ s/:addr$//) { $getaddr = 1; }

  my $head = $self->{audit}->{obj}->head();
  $_ = join ("\n", $head->get ($hdrname));
  if ($hdrname eq 'Message-Id' && (!defined($_) || $_ eq '')) {
    $_ = join ("\n", $head->get ('Message-ID'));	# news-ish
  }
  $_ ||= '';

  if ($getaddr) {
    s/^.*?<.+>\s*$/$1/g			# Foo Blah <jm@foo>
    	or s/^(.+)\s\(.*?\)\s*$/$1/g;	# jm@foo (Foo Blah)
  }

  $_;
}

sub do_head_tests {
  my ($self) = @_;
  local ($_);

  my $head = $self->{audit}->{obj}->head();

  $self->work_out_local_domain ($head);

  my ($rulename, $rule);
  while (($rulename, $rule) = each %{$self->{conf}->{head_tests}}) {
    my $hit = 0;

    my ($hdrname, $testtype, $pat) = 
    		$rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    $_ = $self->get_header ($hdrname);

    $self->clear_test_state();
    if (!eval 'if ($_ '.$testtype.'~ '.$pat.') { $hit = 1; } 1;') {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
      		"\t$rule ($@)\n";
      next;
    }

    if ($hit) { $self->got_hit ($rulename, ''); }
  }
}

sub do_head_eval_tests {
  my ($self) = @_;
  local ($_);

  my $head = $self->{audit}->{obj}->head();

  my ($rulename, $evalsub, $args);
  while (($rulename, $evalsub) = each %{$self->{conf}->{head_evals}}) {
    $evalsub =~ s/\s*\((.*?)\)\s*$//;
    if (defined $1 && $1 ne '') {
      $args = ', '.$1;
    } else {
      $args = '';
    }
    
    $self->clear_test_state();
    my $result;
    if (!eval '$result = $self->'.$evalsub.'($head'.$args.'); 1;')
    {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
      		"\t($@)\n";
      next;
    }
    if ($result) { $self->got_hit ($rulename); }
  }
}

sub do_body_tests {
  my ($self) = @_;
  local ($_);
  my ($rulename, $pat, $evalsub, $args);

  my $evalstr = '';
  while (($rulename, $pat) = each %{$self->{conf}->{body_tests}}) {
    $evalstr .= '
      if ('.$pat.') { $self->got_body_pattern_hit (q{'.$rulename.'}); }
    ';
  }

  my $body = $self->{audit}->{obj}->body();
  while (($rulename, $evalsub) = each %{$self->{conf}->{body_evals}}) {
    $evalsub =~ s/\s*\((.*?)\)\s*$//;
    if (defined $1 && $1 ne '') {
      $args = ', '.$1;
    } else {
      $args = '';
    }

    $self->clear_test_state();
    my $result;
    if (!eval '$result = $self->'.$evalsub.'($body'.$args.'); 1;')
    {
      warn "Failed to run $rulename SpamAssassin test, skipping:\n".
      		"\t($@)\n";
      next;
    }
    if ($result) { $self->got_body_hit ($rulename); }
  }

  my $textary = $self->get_body_text();
  $self->clear_test_state();
  $evalstr = 'foreach $_ (@{$textary}) { study; '.$evalstr.'; } 1;';

  if (!eval $evalstr) {
    warn "Failed to run body SpamAssassin tests, skipping:\n".
	      "\t($@)\n";
    return;
  }
}

sub got_body_pattern_hit {
  my ($self, $rulename) = @_;

  # only allow each test to hit once per mail
  return if (defined $self->{tests_already_hit}->{$rulename});
  $self->{tests_already_hit}->{$rulename} = 1;

  $self->got_body_hit ($rulename);
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

  $self->{test_logs} .= sprintf ("   %-16s %s%s\n%s",
		"Hit! (".$score." point".($score == 1 ? "":"s").")",
		$area, $desc, $self->{test_log_msgs});
}

sub got_hit {
  my ($self, $rule) = @_;
  $self->handle_hit ($rule, '', $self->{conf}->{head_tests}->{$rule});
}

sub got_body_hit {
  my ($self, $rule) = @_;
  $self->handle_hit ($rule, 'BODY: ', $self->{conf}->{body_tests}->{$rule});
}

sub test_log {
  my ($self, $msg) = @_;
  $self->{test_log_msgs} .= sprintf ("%19s [%s]\n", "", $msg);
}

###########################################################################

sub work_out_local_domain {
  my ($self, $head) = @_;

  # TODO -- if needed.

  # my @rcvd = $head->get ("Received");
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

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

