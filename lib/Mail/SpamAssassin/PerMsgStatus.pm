=head1 NAME

Mail::SpamAssassin::PerMsgStatus - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = new Mail::SpamAssassin ({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin.cf'
  });
  my $mail = Mail::SpamAssassin::MyMailAudit->new();

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

use vars	qw{
  	@ISA $base64alphabet
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
    'test_names_hit'	=> '',
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
  # we can then immediately submit to spamblocking services.
  # Also, if parts of the message contain encoded bits (quoted-printable
  # or base64), we test *both*.

  {
    $self->do_head_tests();

    # do body tests with raw text portions
    {
      my $bodytext = $self->get_raw_body_text_array();
      $self->do_body_tests($bodytext);
      $self->do_body_eval_tests($bodytext);
      $bodytext = undef;
    }

    # do body tests with decoded portions
    {
      my $decoded = $self->get_decoded_body_text_array();
      if (defined $decoded) {
	$self->do_body_tests($decoded);
	$self->do_body_eval_tests($decoded);
      }
      $decoded = undef;
    }

    # and do full tests: first with entire, full, undecoded message
    {
      my $fulltext = join ('', $self->{msg}->get_all_headers(), "\n",
      				@{$self->{msg}->get_body()});
      $self->do_full_tests(\$fulltext);
      $self->do_full_eval_tests(\$fulltext);
      $fulltext = undef;
    }

    # then with decoded message
    {
      my $decoded = $self->get_decoded_body_text_array();
      if (defined $decoded) {
	my $fulltext = join ('', $self->{msg}->get_all_headers(), "\n",
				  @{$decoded});
	$self->do_full_tests(\$fulltext);
	$self->do_full_eval_tests(\$fulltext);
	$fulltext = undef;
      }
      $decoded = undef;
    }

    $self->do_head_eval_tests();
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

###########################################################################

=item $list = $status->get_names_of_tests_hit ()

After a mail message has been checked, this method can be called.  It will
return a comma-separated string, listing all the symbolic test names
of the tests which were trigged by the mail.

=cut

sub get_names_of_tests_hit {
  my ($self) = @_;

  $self->{test_names_hit} =~ s/,$//;
  return $self->{test_names_hit};
}

###########################################################################

=item $num = $status->get_hits ()

After a mail message has been checked, this method can be called.  It will
return the number of hits this message incurred.

=cut

sub get_hits {
  my ($self) = @_;
  return $self->{hits};
}

###########################################################################

=item $num = $status->get_required_hits ()

After a mail message has been checked, this method can be called.  It will
return the number of hits required for a mail to be considered spam.

=cut

sub get_required_hits {
  my ($self) = @_;
  return $self->{required_hits};
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

=item $status->rewrite_mail ()

Rewrite the mail message.  This will add headers, and possibly body text, to
reflect it's spam or not-spam status.

The modifications made are as follows:

=over 4

=item Subject: header for spam mails

The string C<*****SPAM*****> is prepended to the subject.

=item X-Spam-Status: header for spam mails

A string, C<Yes, hits=nn required=nn tests=...> is set in this header to
reflect the filter status.  The keys in this string are as follows:

=over 4

=item hits=nn The number of hits the message triggered.

=item required=nn The threshold at which a mail is marked as spam.

=item tests=... The symbolic names of tests which were triggered.

=back

=item X-Spam-Flag: header for spam mails

Set to C<YES>.

=item Content-Type: header for spam mails

Set to C<text/plain>, in order to defang HTML mail or other active
content that could "call back" to the spammer.

=item spam mail body text

The SpamAssassin report is added to top of the mail message body.

=item X-Spam-Status: header for non-spam mails

A string, C<No, hits=nn required=nn tests=...> is set in this header to reflect
the filter status.  The keys in this string are the same as for spam mails (see
above).

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

  # message we'll be reading original values from. Normally the
  # same as $self->{msg} (the target message for the rewritten
  # mail), but if it already had spamassassin markup, we'll need
  # to create a new $srcmsg to hold a 'cleaned-up' version.
  my $srcmsg = $self->{msg};

  if ($self->{msg}->get_header ("X-Spam-Status")) {
    # the mail already has spamassassin markup. Remove it!
    # bit messy this; we need to get the mail as a string,
    # remove the spamassassin markup in it, then re-create
    # a Mail object using a reference to the text 
    # array (why not a string, ghod only knows).

    my $text = $self->{main}->remove_spamassassin_markup ($self->{msg});
    my @textary = split (/^/m, $text);
    my %opts = ( 'data', \@textary );
    
    # this used to be Mail::Audit->new(), but create_new() abstracts
    # that away, so that we always get the right type of object. Wheee!
    my $new_msg = $srcmsg->create_new(%opts);

    # agh, we have to do this ourself?! why won't M::A do it right?
    # for some reason it puts headers in the body
    # while ($_ = shift @textary) { /^$/ and last; }
    # $self->{msg}->replace_body (\@textary);

    $srcmsg = $self->{main}->encapsulate_mail_object($new_msg);

    # delete the SpamAssassin-added headers in the target message.
    $self->{msg}->delete_header ("X-Spam-Status");
    $self->{msg}->delete_header ("X-Spam-Flag");
    $self->{msg}->delete_header ("X-Spam-Prev-Content-Type");
  }

  # First, rewrite the subject line.
  $_ = $srcmsg->get_header ("Subject"); $_ ||= '';
  s/^/\*\*\*\*\*SPAM\*\*\*\*\* /g;
  $self->{msg}->replace_header ("Subject", $_);

  # add some headers...

  $_ = sprintf ("Yes, hits=%d required=%d tests=%s",
	$self->{hits}, $self->{required_hits}, $self->get_names_of_tests_hit());

  $self->{msg}->put_header ("X-Spam-Status", $_);
  $self->{msg}->put_header ("X-Spam-Flag", 'YES');

  # defang HTML mail; change it to text-only.
  my $ct = $srcmsg->get_header ("Content-Type");
  $ct ||= $srcmsg->get_header ("Content-type");

  if (defined $ct && $ct ne '' && $ct ne 'text/plain') {
    $self->{msg}->replace_header ("Content-Type", "text/plain");
    $self->{msg}->delete_header ("Content-type"); 	# just in case
    $self->{msg}->replace_header ("X-Spam-Prev-Content-Type", $ct);
  }

  my $lines = $srcmsg->get_body();
  unshift (@{$lines}, split (/$/, $self->{report}));
  ${$lines}[0] =~ s/\n//;
  $self->{msg}->replace_body ($lines);

  $self->{msg}->get_mail_object;
}

sub rewrite_as_non_spam {
  my ($self) = @_;

  $self->{test_names_hit} =~ s/,$//;

  $_ = sprintf ("No, hits=%d required=%d tests=%s",
	$self->{hits}, $self->{required_hits}, $self->{test_names_hit});
  $self->{msg}->put_header ("X-Spam-Status", $_);
  $self->{msg}->get_mail_object;
}

=item $status->handle_auto_report ()

If this mail message has a high enough hit score, report it to spam-tracking
services straight away, without waiting for user confirmation.  See the
documentation for C<spamassassin>'s C<-r> switch for details on what
spam-tracking services are used.

=cut

sub handle_auto_report {
  my ($self) = @_;

  dbg ("auto-report? score=".$self->{hits}.
  			" threshold=".$self->{conf}->{auto_report_threshold});

  if ($self->{hits} >= $self->{conf}->{auto_report_threshold}) {
    dbg ("score is high enough to automatically report this as spam");

    my $testshit = $self->get_names_of_tests_hit();

    my $opts = { };
    if ($testshit =~ /RAZOR_CHECK/) { $opts->{dont_report_to_razor} = 1; }

    $self->{main}->report_as_spam ($self->{msg}->get_mail_object, $opts);
  }
}

=item $status->finish ()

Indicate that this C<$status> object is finished with, and can be destroyed.

If you are using SpamAssassin in a persistent environment, or checking many
mail messages from one L<Mail::SpamAssassin> factory, this method should be
called to ensure Perl's garbage collection will clean up old status objects.

=cut

sub finish {
  my ($self) = @_;
  delete $self->{main};
  delete $self->{msg};
  delete $self->{conf};
}

###########################################################################
# Non-public methods from here on.

sub get_raw_body_text_array {
  my ($self) = @_;
  local ($_);

  if (defined $self->{body_text_array}) { return $self->{body_text_array}; }

  $self->{found_encoding_base64} = 0;
  $self->{found_encoding_quoted_printable} = 0;

  my $cte = $self->{msg}->get_header ('Content-Transfer-Encoding');
  if (defined $cte && $cte =~ /quoted-printable/) {
    $self->{found_encoding_quoted_printable} = 1;
  } elsif (defined $cte && $cte =~ /base64/) {
    $self->{found_encoding_base64} = 1;
  }

  my $ctype = $self->{msg}->get_header ('Content-Type');
  $ctype ||=  $self->{msg}->get_header ('Content-type');
  $ctype ||=  '';

  my $body = $self->{msg}->get_body();
  if ($ctype !~ /boundary="(.*)"/) {
    $self->{body_text_array} = $body;
    return $self->{body_text_array};
  }

  # else it's a multipart MIME message. Skip non-text parts and
  # just assemble the body array from the text bits.
  $self->{body_text_array} = [ ];
  my $multipart_boundary = "--$1\n";
  my $end_boundary = "--$1--\n";

  my @workingbody = @{$body};

  while ($_ = (shift @workingbody)) {
    push (@{$self->{body_text_array}}, $_);

    if (/^Content-Transfer-Encoding: /) {
      if (/quoted-printable/) {
	$self->{found_encoding_quoted_printable} = 1;
      } elsif (/base64/) {
	$self->{found_encoding_base64} = 1;
      }
    }

    if ($multipart_boundary eq $_) {
      $_ = (shift @workingbody);
      last unless defined $_;
      next if /^Content-[Tt]ype: (?:text\/\S+|multipart\/alternative)/;

      # skip this attachment, it's non-text.
      while ($_ = (shift @workingbody)) {
	if ($end_boundary eq $_) { last; }
	if ($multipart_boundary eq $_) { unshift (@workingbody, $_); last; }
      }
    }
  }
  @workingbody = ();

  return $self->{body_text_array};
}

###########################################################################

sub get_decoded_body_text_array {
  my ($self) = @_;
  local ($_);
  my $textary = $self->get_raw_body_text_array();

  # TODO: doesn't yet handle checking multiple-attachment messages,
  # where one part is qp and another is b64.  Instead the qp will
  # be simply stripped.

  if ($self->{found_encoding_base64}) {
    $_ = '';
    my $foundb64 = 0;
    foreach my $line (@{$textary}) {
      if (length($line) != 77) {	# 76 + newline
	if ($foundb64) {
	  $_ .= $line;		# last line of block is usually short
	  last;
	}
      } else {
	$_ .= $line; $foundb64 = 1;
      }
    }

    $_ = $self->slow_base64_decode ($_);
    # print "decoded: $_\n";
    my @lines = split (/^/, $_);
    return \@lines;

  } elsif ($self->{found_encoding_quoted_printable}) {
    $_ = join ('', $textary);
    s/\=([0-9A-Fa-f]{2})/chr(hex($1))/ge; s/\=\n/\n/;
    my @lines = split (/^/, $_);
    return \@lines;

  } else {
    return undef;
  }
}

###########################################################################

sub get {
  my ($self, $hdrname, $defval) = @_;
  local ($_);

  if ($hdrname eq 'ALL') { return $self->{msg}->get_all_headers(); }

  my $getaddr = 0;
  if ($hdrname =~ s/:addr$//) { $getaddr = 1; }

  my @hdrs = $self->{msg}->get_header ($hdrname);
  if ($#hdrs >= 0) {
    $_ = join ("\n", @hdrs);
  } else {
    $_ = undef;
  }

  if ($hdrname eq 'Message-Id' && (!defined($_) || $_ eq '')) {
    $_ = join ("\n", $self->{msg}->get_header ('Message-ID'));	# news-ish
  }

  if (!defined $_) {
    $defval ||= '';
    $_ = $defval;
  }

  if ($getaddr) {
    chomp; s/\r?\n//gs;
    s/^.*?<(.+)>\s*$/$1/g		# Foo Blah <jm@foo>
    	or s/^(.+)\s\(.*?\)\s*$/$1/g;	# jm@foo (Foo Blah)

  } else {
    $_ = $self->mime_decode_header ($_);
  }

  $_;
}

###########################################################################

# This function will decode MIME-encoded headers.  Note that it is ONLY
# used from test functions, so destructive or mildly inaccurate results
# will not have serious consequences.  Do not replace the original message
# contents with anything decoded using this!
#
sub mime_decode_header {
  my ($self, $enc) = @_;

  # cf. http://www.nacs.uci.edu/indiv/ehood/MHonArc/doc/resources/charsetconverters.html

  # quoted-printable encoded headers.
  # ASCII:  =?US-ASCII?Q?Keith_Moore?= <moore@cs.utk.edu>
  # Latin1: =?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?= <keld@dkuug.dk>
  # Latin1: =?ISO-8859-1?Q?Andr=E9_?= Pirard <PIRARD@vm1.ulg.ac.be>

  if ($enc =~ s{=\?([^\?]+)\?Q\?([^\?]+)\?=}{
    		$self->decode_mime_bit ($1, $2);
	      }eg)
  {
    dbg ("decoded MIME header: \"$enc\"");
  }

  # TODO: handle base64-encoded headers. eg:
  # =?UTF-8?B?Rlc6IFBhc3NpbmcgcGFyYW1ldGVycyBiZXR3ZWVuIHhtbHMgdXNp?=
  # =?UTF-8?B?bmcgY29jb29uIC0gcmVzZW50IA==?=   (yuck)
  # not high-priorty as they're still very rare.

  return $enc;
}

sub decode_mime_bit {
  my ($self, $encoding, $text) = @_;
  local ($_) = $text;

  if ($encoding =~ /^US-ASCII$/i
  	|| $encoding =~ /^ISO-8859-\d+$/i
  	|| $encoding =~ /^UTF-8$/i
      )
  {
    # keep 8-bit stuff. forget mapping charsets though
    s/_/ /g; s/\=([0-9A-Fa-f]{2})/chr(hex($1))/ge;
  }

  if ($encoding eq 'UTF-16')
  {
    # we just dump the high bits and keep the 8-bit chars.
    s/_/ /g; s/=00//g; s/\=([0-9A-Fa-f]{2})/chr(hex($1))/ge;
  }

  return $_;
}

###########################################################################

sub do_head_tests {
  my ($self) = @_;
  local ($_);

  dbg ("running header regexp tests; score so far=".$self->{hits});

  my ($rulename, $rule);
  my $evalstr = '';

  # note: we do this only once for all head pattern tests.  Only
  # eval tests need to use stuff in here.
  $self->clear_test_state();

  while (($rulename, $rule) = each %{$self->{conf}->{head_tests}}) {
    next if ($self->{conf}->{scores}->{$rulename} == 0.0);

    my $def = '';
    my ($hdrname, $testtype, $pat) = 
    		$rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    if ($pat =~ s/\s+\[if-unset:\s+(.+)\]\s*$//i) { $def = $1; }
    $_ = $self->get ($hdrname, $def);
    s/#/[HASH]/gs;		# avoid probs with eval below

    $evalstr .= '
      if (q#'.$_.'# '.$testtype.'~ '.$pat.') {
	$self->got_hit (q{'.$rulename.'}, q{});
      }
    ';
  }

  if (!eval $evalstr.'1;') {
    warn "Failed to run header SpamAssassin tests, skipping some: $@\n";
  }
}

sub do_body_tests {
  my ($self, $textary) = @_;
  my ($rulename, $pat);
  local ($_);
  $self->clear_test_state();

  dbg ("running body-text per-line regexp tests; score so far=".$self->{hits});

  # build up the eval string...
  my $evalstr = '';
  while (($rulename, $pat) = each %{$self->{conf}->{body_tests}}) {
    next if ($self->{conf}->{scores}->{$rulename} == 0.0);
    $evalstr .= '
      if ('.$pat.') { $self->got_body_pattern_hit (q{'.$rulename.'}); }
    ';
  }

  # generate the loop that goes through each line...
  $evalstr = 'foreach $_ (@{$textary}) { '.$evalstr.'; }';

  # and run it.
  if (!eval $evalstr.'1;') {
    warn "Failed to run body SpamAssassin tests, skipping:\n".
	      "\t($@)\n";
  }
}

sub do_full_tests {
  my ($self, $fullmsgref) = @_;
  my ($rulename, $pat);
  local ($_);
  $self->clear_test_state();

  dbg ("running full-text regexp tests; score so far=".$self->{hits});

  # build up the eval string...
  my $evalstr = '';
  while (($rulename, $pat) = each %{$self->{conf}->{full_tests}}) {
    next if ($self->{conf}->{scores}->{$rulename} == 0);
    $evalstr .= '
      if ($$fullmsgref =~ '.$pat.') { $self->got_hit (q{'.$rulename.'}, q{}); }
    ';
  }

  # and run it.
  study $$fullmsgref;
  if (!eval $evalstr.'; 1;') {
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
  my ($self, $bodystring) = @_;
  $self->run_eval_tests ($self->{conf}->{body_evals}, 'BODY: ', $bodystring);
}

sub do_full_eval_tests {
  my ($self, $fullmsgref) = @_;
  $self->run_eval_tests ($self->{conf}->{full_evals}, '', $fullmsgref);
}

###########################################################################

sub run_eval_tests {
  my ($self, $evalhash, $prepend2desc, @extraevalargs) = @_;
  my ($rulename, $pat, $evalsub, @args);
  local ($_);

  while (($rulename, $evalsub) = each %{$evalhash}) {
    next if ($self->{conf}->{scores}->{$rulename} == 0);

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

# note: only eval tests should store state in here; pattern tests do
# not.
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

  $self->{test_names_hit} .= $rule.",";

  $self->{test_logs} .= sprintf ("%-18s %s%s\n%s",
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
  $self->{test_log_msgs} .= sprintf ("%18s [%s]\n", "", $msg);
}

###########################################################################
# Rather than add a requirement for MIME::Base64, use a slower but
# built-in base64 decode mechanism.
#
# original credit for this code:
# b64decode -- decode a raw BASE64 message
# A P Barrett <barrett@ee.und.ac.za>, October 1993
# Minor mods by jm@jmason.org for spamassassin and "use strict"

sub slow_base64_decode {
  my ($self) = shift;
  local ($_) = shift;

  $base64alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
		    'abcdefghijklmnopqrstuvwxyz'.
		    '0123456789+/'; # and '='

  my $leftover = '';

  # ignore illegal characters
  s/[^$base64alphabet]//go;
  # insert the leftover stuff from last time
  $_ = $leftover . $_;
  # if there are not a multiple of 4 bytes, keep the leftovers for later
  m/^((....)*)/; $_=$&; $leftover=$';
  # turn each group of 4 values into 3 bytes
  s/(....)/&b64decodesub($1)/eg;
  # special processing at EOF for last few bytes
  if (eof) {
      $_ .= &b64decodesub($leftover); $leftover = '';
  }
  # output it
  return $_;
}

# b64decodesub -- takes some characters in the base64 alphabet and
# returns the raw bytes that they represent.
sub b64decodesub
{
  local ($_) = $_[0];
	   
  # translate each char to a value in the range 0 to 63
  eval qq{ tr!$base64alphabet!\0-\77!; };
  # keep 6 bits out of every 8, and pack them together
  $_ = unpack('B*', $_); # look at the bits
  s/(..)(......)/$2/g;   # keep 6 bits of every 8
  s/((........)*)(.*)/$1/; # throw away spare bits (not multiple of 8)
  $_ = pack('B*', $_);   # turn the bits back into bytes
  $_; # return
}

###########################################################################

sub work_out_local_domain {
  my ($self) = @_;

  # TODO -- if needed.

  # my @rcvd = $self->{msg}->get_header ("Received");

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
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

