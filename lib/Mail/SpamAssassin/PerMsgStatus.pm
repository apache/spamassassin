=head1 NAME

Mail::SpamAssassin::PerMsgStatus - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = new Mail::SpamAssassin ({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin.cf'
  });
  my $mail = Mail::SpamAssassin::NoMailAudit->new();

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
use Mail::SpamAssassin::AutoWhitelist;

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
  $self->{stop_at_threshold} = $self->{main}->{stop_at_threshold};

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
  #
  # TODO: change this to do whitelist/blacklists first? probably a plan
  # NOTE: definitely need AWL stuff last, for regression-to-mean of score

  $self->remove_unwanted_headers();

  {
    $self->do_head_tests();

    # do body tests with decoded portions
    {
      my $decoded = $self->get_decoded_stripped_body_text_array();
      # warn "JMD ". join ("", @{$decoded}). "\n";
      $self->do_body_tests($decoded);
      $self->do_body_eval_tests($decoded);
      $self->do_body_uri_tests($decoded);
      undef $decoded;
    }

    # do rawbody tests with raw text portions
    {
      my $bodytext = $self->get_decoded_body_text_array();
      $self->do_rawbody_tests($bodytext);
      $self->do_rawbody_eval_tests($bodytext);
      undef $bodytext;
    }

    # and do full tests: first with entire, full, undecoded message
    # still skip application/image attachments though
    {
      my $fulltext = join ('', $self->{msg}->get_all_headers(), "\n",
      				@{$self->get_raw_body_text_array()});
      $self->do_full_tests(\$fulltext);
      $self->do_full_eval_tests(\$fulltext);
      undef $fulltext;
    }

    $self->do_head_eval_tests();

    # Do AWL tests last, since these need the score to have already been calculated
    $self->do_awl_tests();
  }

  dbg ("is spam? score=".$self->{hits}.
  			" required=".$self->{conf}->{required_hits});
  $self->{is_spam} = ($self->{hits} >= $self->{conf}->{required_hits});

  if ($self->{conf}->{use_terse_report}) {
    $_ = $self->{conf}->{terse_report_template};
  } else {
    $_ = $self->{conf}->{report_template};
  }
  $_ ||= '(no report template found)';

  s/_HITS_/$self->{hits}/gs;
  s/_REQD_/$self->{conf}->{required_hits}/gs;
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
  # changed to test this so sub-tests can ask "is_spam" during a run
  return ($self->{hits} >= $self->{conf}->{required_hits});
}

###########################################################################

=item $list = $status->get_names_of_tests_hit ()

After a mail message has been checked, this method can be called.  It will
return a comma-separated string, listing all the symbolic test names
of the tests which were trigged by the mail.

=cut

sub get_names_of_tests_hit {
  my ($self) = @_;

  $self->{test_names_hit} =~ s/,\s*$//;
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
  return $self->{conf}->{required_hits};
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
reflect its spam or not-spam status.

The modifications made are as follows:

=over 4

=item Subject: header for spam mails

The string C<*****SPAM*****> (changeable with C<subject_tag> config option) is
prepended to the subject, unless the C<rewrite_subject 0> configuration option
is given.

=item X-Spam-Status: header for spam mails

A string, C<Yes, hits=nn required=nn tests=...> is set in this header to
reflect the filter status.  The keys in this string are as follows:

=item X-Spam-Report: header for spam mails

The SpamAssassin report is added to the mail header if
the C<report_header = 1> configuration option is given.

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

=item X-Spam-Checker-Version: header for spam mails

Set to the version number of the SpamAssassin checker which tested the mail.

=item spam mail body text

The SpamAssassin report is added to top of the mail message body,
unless the C<report_header 1> configuration option is given.

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

    undef @textary;		# please perl, GC this properly

    $srcmsg = $self->{main}->encapsulate_mail_object($new_msg);

    # delete the SpamAssassin-added headers in the target message.
    $self->{msg}->delete_header ("X-Spam-Status");
    $self->{msg}->delete_header ("X-Spam-Flag");
    $self->{msg}->delete_header ("X-Spam-Checker-Version");
    $self->{msg}->delete_header ("X-Spam-Prev-Content-Type");
    $self->{msg}->delete_header ("X-Spam-Prev-Content-Transfer-Encoding");
    $self->{msg}->delete_header ("X-Spam-Report");
  }

  # First, rewrite the subject line.
  if ($self->{conf}->{rewrite_subject}) {
    $_ = $srcmsg->get_header ("Subject");
    $_ ||= '';

    my $tag = $self->{conf}->{subject_tag};

    my $hit = sprintf ("%05.2f", $self->{hits});
    $tag =~ s/_HITS_/$hit/;

    my $reqd = sprintf ("%05.2f", $self->{conf}->{required_hits});
    $tag =~ s/_REQD_/$reqd/;
    
    s/^(?:\Q${tag}\E |)/${tag} /g;

    $self->{msg}->replace_header ("Subject", $_);
  }

  # add some headers...

  $_ = sprintf ("Yes, hits=%2.1f required=%2.1f tests=%s version=%s",
	$self->{hits}, $self->{conf}->{required_hits},
	$self->get_names_of_tests_hit(),
	$Mail::SpamAssassin::VERSION);

  $self->{msg}->put_header ("X-Spam-Status", $_);
  $self->{msg}->put_header ("X-Spam-Flag", 'YES');
  if($self->{main}->{conf}->{spam_level_stars} == 1) 
  {
      $self->{msg}->put_header("X-Spam-Level", "*"x int($self->{hits}));
  }

  $self->{msg}->put_header ("X-Spam-Checker-Version",
  	"SpamAssassin $Mail::SpamAssassin::VERSION ".
	"($Mail::SpamAssassin::SUB_VERSION)");

  # defang HTML mail; change it to text-only.
  if ($self->{conf}->{defang_mime}) {
    my $ct = $srcmsg->get_header ("Content-Type");

    if (defined $ct && $ct ne '' && $ct ne 'text/plain') {
      $self->{msg}->replace_header ("Content-Type", "text/plain");
      $self->{msg}->replace_header ("X-Spam-Prev-Content-Type", $ct);

    }

    my $cte = $srcmsg->get_header ("Content-Transfer-Encoding");

    if (defined $cte && $cte ne '' && $ct ne '7bit') {
      $self->{msg}->replace_header ("Content-Transfer-Encoding", "7bit");
      $self->{msg}->replace_header ("X-Spam-Prev-Content-Transfer-Encoding", $cte);
    }
  }

  if ($self->{conf}->{report_header}) {
    my $report = $self->{report};
    $report =~ s/(?:\n|^)\s*\n//gm;	# Empty lines not allowed in header.
    $report =~ s/\n\s*/\n  /gm;	# Ensure each line begins with whitespace.

    if ($self->{conf}->{use_terse_report}) {
      # Strip the superfluous SPAM: messages if we're being terse.
      # The header can still be stripped without them.
      $report =~ s/^\s*SPAM: /  /gm;
      # strip start and end lines
      $report =~ s/^\s*----[^\n]+\n//gs;
      $report =~ s/\s*\n  ----[^\n]+\s*$//gs;
    } else {
      $report = "Detailed Report\n" . $report;
    }
    
    $self->{msg}->put_header ("X-Spam-Report", $report);

  } else {
    my $lines = $srcmsg->get_body();

    my $rep = $self->{report};
    my $cte = $self->{msg}->get_header ('Content-Transfer-Encoding');
    if (defined $cte && $cte =~ /quoted-printable/) {
      $rep =~ s/=/=3D/gs;               # quote the = chars
    }

    my $content_type = $self->{msg}->get_header('Content-Type');
    if (defined($content_type) and $content_type =~ /boundary\s*=\s*["']?(.*)["']?(?:;|$)/i) {
      # Deal with MIME "null block".  If this is a multipart MIME mail,
      # peel off the MIME header for the main part of the message,
      # stick in the report, then put the MIME header back in front,
      # so that the report is *after* the MIME header.
      my $boundary = "--" . quotemeta($1);
      my @main_part;

      if (grep(/^$boundary/i, @{$lines})) {
        # If, for some reason, the boundry marker doesn't appear in the
        # body of the text, don't bother with the following three lines,
        # because otherwise @{$lines} will go down to zero size, so
        # $lines->[0] will be undefined, and Perl (or at least some versions
        # of it) will go into an infinite loop of throwing warnings.
        push(@main_part, shift(@{$lines})) while ($lines->[0] !~ /^$boundary/i);
        push(@main_part, shift(@{$lines})) while ($lines->[0] !~ /^$/);
        push(@main_part, shift(@{$lines}));
      }

      unshift (@{$lines}, split (/$/, $rep));
      $lines->[0] =~ s/\n//;
      unshift (@{$lines}, @main_part);
    }
    else {
      unshift (@{$lines}, split (/$/, $rep));
      $lines->[0] =~ s/\n//;
    }

    $self->{msg}->replace_body ($lines);
  }

  $self->{msg}->get_mail_object;
}

sub rewrite_as_non_spam {
  my ($self) = @_;

  $self->{test_names_hit} =~ s/,$//;

  $_ = sprintf ("No, hits=%2.1f required=%2.1f tests=%s version=%s",
	$self->{hits}, $self->{conf}->{required_hits},
	$self->get_names_of_tests_hit(),
	$Mail::SpamAssassin::VERSION);

  $self->{msg}->put_header ("X-Spam-Status", $_);
  if($self->{main}->{conf}->{spam_level_stars} == 1)
  {
	  $self->{msg}->put_header("X-Spam-Level", "*"x int($self->{hits}));
  }
  $self->{msg}->get_mail_object;
}

###########################################################################

=item $messagestring = $status->get_full_message_as_text ()

Returns the mail message as a string, including headers and raw body text.

If the message has been rewritten using C<rewrite_mail()>, these changes
will be reflected in the string.

Note: this is simply a helper method which calls methods on the mail message
object.  It is provided because Mail::Audit uses an unusual (ie. not quite
intuitive) interface to do this, and it has been a common stumbling block for
authors of scripts which use SpamAssassin.

=cut

sub get_full_message_as_text {
  my ($self) = @_;
  return join ("", $self->{msg}->get_all_headers(), "\n",
			@{$self->{msg}->get_body()});
}

###########################################################################

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

###########################################################################

=item $status->finish ()

Indicate that this C<$status> object is finished with, and can be destroyed.

If you are using SpamAssassin in a persistent environment, or checking many
mail messages from one L<Mail::SpamAssassin> factory, this method should be
called to ensure Perl's garbage collection will clean up old status objects.

=cut

sub finish {
  my ($self) = @_;

  delete $self->{body_text_array};
  delete $self->{main};
  delete $self->{msg};
  delete $self->{conf};
  delete $self->{res};
  delete $self->{hits};
  delete $self->{test_names_hit};
  delete $self->{test_logs};
  delete $self->{replacelines};

  $self = { };
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
  $ctype ||=  '';

  # if it's non-text, just return an empty body rather than the base64-encoded
  # data.  If spammers start using images to spam, we'll block 'em then!
  if ($ctype =~ /^(?:image\/|application\/|video\/)/) {
    $self->{body_text_array} = [ ];
    return $self->{body_text_array};
  }

  # if it's a multipart MIME message, skip non-text parts and
  # just assemble the body array from the text bits.
  my $multipart_boundary;
  my $end_boundary;
  if ($ctype =~ /boundary\s*=\s*"(.*)"/) {
    $multipart_boundary = "--$1\n";
    $end_boundary = "--$1--\n";
  }

  my $ctypeistext = 1;

  # we build up our own copy from the Mail::Audit message-body array
  # reference, skipping MIME parts. this should help keep down in-memory
  # text size.
  my $bodyref = $self->{msg}->get_body();
  $self->{body_text_array} = [ ];

  my $line;
  for ($line = 0; defined($_ = $bodyref->[$line]); $line++)
  {
    # we run into a perl bug if the lines are astronomically long (probably due
    # to lots of regexp backtracking); so cut short any individual line over 4096
    # bytes in length.  This can wreck HTML totally -- but IMHO the only reason a
    # luser would use 4096-byte lines is to crash filters, anyway.

    while (length ($_) > 4096) {
      push (@{$self->{body_text_array}}, substr($_, 0, 4096));
      substr($_, 0, 4096) = '';
    }

    push (@{$self->{body_text_array}}, $_);

    next unless defined ($multipart_boundary);
    # MIME-only from here on.

    if (/^Content-Transfer-Encoding: /) {
      if (/quoted-printable/) {
	$self->{found_encoding_quoted_printable} = 1;
      } elsif (/base64/) {
	$self->{found_encoding_base64} = 1;
      }
    }

    if ($multipart_boundary eq $_) {
      my $starting_line = $line;
      for ($line++; defined($_ = $bodyref->[$line]); $line++) {
	push (@{$self->{body_text_array}}, $_);

	if (/^$/) { last; }

	if (/^Content-[Tt]ype: (\S+?\/\S+?)(?:\;|\s|$)/) {
	  $ctype = $1;
	  if ($ctype =~ /^(text\/\S+|message\/\S+|multipart\/alternative)/) {
	    $ctypeistext = 1; next;
	  } else {
	    $ctypeistext = 0; next;
	  }
	}
      }

      $line = $starting_line;

      last unless defined $_;

      if (!$ctypeistext) {
	# skip this attachment, it's non-text.
	push (@{$self->{body_text_array}}, "[skipped $ctype attachment]\n");

	for ($line++; defined($_ = $bodyref->[$line]); $line++) {
	  if ($end_boundary eq $_) { last; }
	  if ($multipart_boundary eq $_) { $line--; last; }
	}
      }
    }
  }

  #print "JMD ".join ("", @{$self->{body_text_array}})."\n\n\n";
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
    my $lastlinelength = 0;
    my $b64lines = 0;
    foreach my $line (@{$textary}) {
      if ($line =~ /[ \t]/ or $line =~ /^--/) {  # base64 can't have whitespace on the line or start --
        $_ = "";
        $foundb64 = 0;
        next;
      }

      if (length($line) != $lastlinelength && !$foundb64) { # This line is a different length from the last one
        $_ = $line;                                         # Could be the first line of a base 64 part
        $lastlinelength = length($line);
        next;
      }

      if ($lastlinelength == length ($line)) {              # Same length as the last line.  Starting to look like a base64 encoding
        if ($b64lines++ == 5) {                             # Five lines the same length, with no spaces in them
          $foundb64 = 1;                                    # Sounds like base64 to me!
        }
        $_ .= $line;
        next;
      }

      if ($foundb64) {                                      # Last line is shorter, so we are done.
        $_ .= $line;
        last;
      }
    }

    $_ = $self->generic_base64_decode ($_);
    # print "decoded: $_\n";
    my @ary = split (/^/, $_);
    return \@ary;

  } elsif ($self->{found_encoding_quoted_printable}) {
    $_ = join ('', @{$textary});
    s/\=\r?\n//gs;
    s/\=([0-9A-Fa-f]{2})/chr(hex($1))/ge;
    my @ary = split (/^/, $_);
    return \@ary;

  } else {
    return $textary;
  }
}

###########################################################################

# A URI can be like:
#
#   href=foo.htm
#   href = foo.htm
#   href="foo.htm"
#   href='foo.htm'
#   href = 'foo.htm'
#   href = ' foo.htm '
#
# and such.  Have to deal with all of it.
#
# Also, mail with non-Quoted-Printable encoding might still have the
# "=3D" obfuscation trick, since many email clients will decode
# QP escape codes regardless of where and when they occur.
#
my $URI_in_tag = qr/\s*=(?:3[Dd])?\s*["']?\s*([^'">\s]*)\s*["']?[^>]*/;

sub get_decoded_stripped_body_text_array {
  my ($self) = @_;
  local ($_);

  my $bodytext = $self->get_decoded_body_text_array();

   my $ctype = $self->{msg}->get_header ('Content-Type');
   $ctype ||=  '';
 
   # if it's a multipart MIME message, skip the MIME-definition stuff
   my $boundary;
   if ($ctype =~ /boundary="(.*)"/) {
     $boundary = $1;
   }
 
  my $text = "Subject: " . $self->get('subject', '') . "\n\n";
  my $lastwasmime = 0;
  foreach $_ (@{$bodytext}) {
    /^SPAM: / and next;         # SpamAssassin markup

    defined $boundary and $_ eq "--$boundary\n" and $lastwasmime=1 and next;           # MIME start
    defined $boundary and $_ eq "--$boundary--\n" and next;                            # MIME end

    if ($lastwasmime) {
      /^$/ and $lastwasmime=0;
      /Content-.*: / and next;
      /^\s/ and next;
    }

    $text .= $_;
  }

  # Get rid of comments.  Isn't the non-greedy ".*?" awful expensive?
  #
  # There might be things in comments we'd want to look at, like
  # SCRIPT and STYLE content, but that can be taken care of with
  # rawbody tests.
  $text =~ s/<!--.*?-->//gs;

  # Try to put paragraph breaks where'd they'd be in HTML.  There's
  # an optional "/" before the ends of some tags in case it's XML style.
  $text =~ s/<BR\/?>\s*<BR\/?>/\n\n/gis; # Two line breaks
  $text =~ s/<HR\/?>/\n\n/gis;           # Horizontal line

  # Keep paragraph breaks
  $text =~ s/\n\n+/<p>/gs;

  # Convert hex entities to decimal equivalents, so that the specific
  # decimal regexps will match
  $text =~ s/\&\#x([a-f0-9]+);/"&#" . hex($1) . ";"/ieg;

  # Convert specific HTML entities
  $text =~ s/(?:\&nbsp;|\&\#0?160;)/ /gis;
  $text =~ s/(?:\&reg;|\&\#0?174;)/(R)/gis;
  $text =~ s/(?:\&copy;|\&\#0?169;)/(C)/gis;
  $text =~ s/\&\#0?153;/(TM)/gs;
  $text =~ s/(?:\&\#0?147;|\&\#0?148;|\&\#0?132|\&quot;)/"/gis;
  $text =~ s/\&\#0?146;/'/gs;
  $text =~ s/\&\#0?145;/`/gs;
  $text =~ s/\&\#0?150;/-/gs;  # En-dash
  $text =~ s/\&\#0?151;/--/gs; # Em-dash
  $text =~ s/\&\#0?152;/~/gs;
  $text =~ s/\&\#82(?:16|17|20|11);//gs;
  
  # Convert <Q> tags
  $text =~ s/<\/?Q\b[^>]*>/"/gis;
    
  # Convert decimal entities to their characters
  $text =~ s/\&\#(\d+);/chr($1)/eg;
  
  # Strip all remaining HTML entities
  $text =~ s/\&[-_a-zA-Z0-9]+;/ /gs;
  
  # join all consecutive whitespace into a single space
  $text =~ s/\s+/ /sg;
  
  # reinsert para breaks
  $text =~ s/<p>/\n\n/gis;

  # Get rid of "BASEURI:" in case spammers insert it raw to try to
  # mess us up
  $text =~ s/BASEURI://sg;

  # Extract URIs from various HTML tags, so that they'll still be there
  # when the URI tests are done.
  # <A>, <AREA>, <BASE> and <LINK> use "href=URI".
  # <IMG>, <FRAME>, <IFRAME>, <EMBED> and <SCRIPT> use "src=URI"
  # <FORM> uses "action=URI"
  $text =~ s/<base\s[^>]*\bhref$URI_in_tag>/BASEURI:$1 /ogis;
  $text =~ s/<(?:a|area|link)\s[^>]*\bhref$URI_in_tag>/URI:$1 /ogis;
  $text =~ s/<(?:img|i?frame|embed|script)\s[^>]*\bsrc$URI_in_tag>/URI:$1 /ogis;
  $text =~ s/<form\s[^>]*\baction$URI_in_tag>/URI:$1 /ogis;
  
  # Get rid of all remaing HTML and XML tags
  $text =~ s/<[?!\s]*[:a-z0-9]+\b[^>]*>//gis;
  $text =~ s/<\/[:a-z0-9]+>//gis;

  my @textary = split (/^/, $text);
  return \@textary;
}

###########################################################################

sub get {
  my ($self, $hdrname, $defval) = @_;
  local ($_);

  if ($hdrname eq 'ALL') { return $self->{msg}->get_all_headers(); }

  my $getaddr = 0;
  if ($hdrname =~ s/:addr$//) { $getaddr = 1; }

  my $getname = 0;
  if ($hdrname =~ s/:name$//) { $getname = 1; }

  my @hdrs = $self->{msg}->get_header ($hdrname);
  if ($#hdrs >= 0) {
    $_ = join ("\n", @hdrs);
  } else {
    $_ = undef;
  }

  if ($hdrname eq 'Message-Id' && (!defined($_) || $_ eq '')) {
    $_ = join ("\n", $self->{msg}->get_header ('Message-ID'));	# news-ish
    if ($_ eq '') { undef $_; }
  }

  if ($hdrname eq 'Cc' && (!defined($_) || $_ eq '')) {
    $_ = join ("\n", $self->{msg}->get_header ('CC'));		# common enough
    if ($_ eq '') { undef $_; }
  }

  if (!defined $_) {
    $defval ||= '';
    $_ = $defval;
  }

  if ($getaddr) {
    chomp; s/\r?\n//gs;
    s/\(.*?\)//g;               # strip out the (comments)
    s/^.*?<(.*?)>\s*$/$1/;      # "Foo Blah" <jm@foo> or <jm@foo>

  } elsif ($getname) {
    chomp; s/\r?\n//gs;
    s/^[\'\"]*(.*?)[\'\"]*\s*<.+>\s*$/$1/g # Foo Blah <jm@foo>
    	or s/^.+\s\((.*?)\)\s*$/$1/g;	   # jm@foo (Foo Blah)

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

  if ($enc =~ s{\s*=\?([^\?]+)\?[Qq]\?([^\?]+)\?=}{
    		$self->decode_mime_bit ($1, $2);
	      }eg)
  {
    my $rawenc = $enc;

    # Sitck lines back together when the encoded header wraps a line eg:
    #
    # Subject: =?iso-2022-jp?B?WxskQjsoM1gyI0N6GyhCIBskQk4iREwkahsoQiAy?=
    #   =?iso-2022-jp?B?MDAyLzAzLzE5GyRCOWYbKEJd?=

    $enc = "";
    my $splitenc;

    foreach $splitenc (split (/\n/, $rawenc)) {
      $enc .= $splitenc;
    }
    dbg ("decoded MIME header: \"$enc\"");
  }

  # handle base64-encoded headers. eg:
  # =?UTF-8?B?Rlc6IFBhc3NpbmcgcGFyYW1ldGVycyBiZXR3ZWVuIHhtbHMgdXNp?=
  # =?UTF-8?B?bmcgY29jb29uIC0gcmVzZW50IA==?=   (yuck)

  if ($enc =~ s{\s*=\?([^\?]+)\?[Bb]\?([^\?]+)\?=}{
    		$self->generic_base64_decode ($2);
	      }eg)
  {
    my $rawenc = $enc;

    # Sitck lines back together when the encoded header wraps a line

    $enc = "";
    my $splitenc;

    foreach $splitenc (split (/\n/, $rawenc)) {
      $enc .= $splitenc;
    }
    dbg ("decoded MIME header: \"$enc\"");
  }

  return $enc;
}

sub decode_mime_bit {
  my ($self, $encoding, $text) = @_;
  local ($_) = $text;

  if ($encoding =~ /^US-ASCII$/i
  	|| $encoding =~ /^ISO646-US/i
  	|| $encoding =~ /^ISO-8859-\d+$/i
  	|| $encoding =~ /^UTF-8$/i
	|| $encoding =~ /KOI8-\w$/i
	|| $encoding =~ /^WINDOWS-125\d$/i
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

  # note: we do this only once for all head pattern tests.  Only
  # eval tests need to use stuff in here.
  $self->clear_test_state();

  dbg ("running header regexp tests; score so far=".$self->{hits});

  # speedup code provided by Matt Sergeant
  if (defined &Mail::SpamAssassin::PerMsgStatus::_head_tests) {
      Mail::SpamAssassin::PerMsgStatus::_head_tests($self);
      return;
  }

  my ($rulename, $rule);
  my $evalstr = '';

  my @tests = keys %{$self->{conf}{head_tests}};
  my @negative_tests;
  my @positive_tests;
  # add negative tests;
  foreach my $test (@tests) {
    if ($self->{conf}{scores}{$test} < 0) {
      push @negative_tests, $test;
    }
    else {
      push @positive_tests, $test;
    }
  }
  @negative_tests = sort { $self->{conf}{scores}{$a} <=> $self->{conf}{scores}{$b} } @negative_tests;
  @positive_tests = sort { $self->{conf}{scores}{$b} <=> $self->{conf}{scores}{$a} } @positive_tests;

  foreach $rulename (@negative_tests, @positive_tests) {
    $rule = $self->{conf}->{head_tests}->{$rulename};
    my $def = '';
    my ($hdrname, $testtype, $pat) =
        $rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    if ($pat =~ s/\s+\[if-unset:\s+(.+)\]\s*$//) { $def = $1; }
    $hdrname =~ s/#/[HASH]/g;		# avoid probs with eval below
    $def =~ s/#/[HASH]/g;

    # dbg ("header regexp test '.$rulename.'");
    $evalstr .= '
      return if $self->{stop_at_threshold} && $self->is_spam;
      if ($self->{conf}->{scores}->{q#'.$rulename.'#}) {
        # warn("testing: ", $self->get(q#'.$hdrname.'#,q#'.$def.'#), " vs '.$rulename.' ($self->{conf}->{scores}->{q{'.$rulename.'}})\n");
        if ($self->get(q#'.$hdrname.'#, q#'.$def.'#) '.$testtype.'~ '.$pat.') {
          $self->got_hit (q#'.$rulename.'#, q{});
        }
      }
    ';
  }

  $evalstr = <<"EOT";
{
    package Mail::SpamAssassin::PerMsgStatus;

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
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_head_tests($self);
  }
}

sub do_body_tests {
  my ($self, $textary) = @_;
  my ($rulename, $pat);
  local ($_);

  dbg ("running body-text per-line regexp tests; score so far=".$self->{hits});

  $self->clear_test_state();
  if ( defined &Mail::SpamAssassin::PerMsgStatus::_body_tests ) {
    # ok, we've compiled this before.
    Mail::SpamAssassin::PerMsgStatus::_body_tests($self, @$textary);
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my @tests = keys %{$self->{conf}{body_tests}};
  my @negative_tests;
  my @positive_tests;
  # add negative tests;
  foreach my $test (@tests) {
    if ($self->{conf}{scores}{$test} < 0) {
      push @negative_tests, $test;
    }
    else {
      push @positive_tests, $test;
    }
  }
  @negative_tests = sort { $self->{conf}{scores}{$a} <=> $self->{conf}{scores}{$b} } @negative_tests;
  @positive_tests = sort { $self->{conf}{scores}{$b} <=> $self->{conf}{scores}{$a} } @positive_tests;

  foreach $rulename (@negative_tests, @positive_tests) {
    $pat = $self->{conf}->{body_tests}->{$rulename};
    $evalstr .= '
      return if $self->{stop_at_threshold} && $self->is_spam;
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        if ('.$pat.') { $self->got_body_pattern_hit (q{'.$rulename.'}); }
      }
    ';
  }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  sub _body_tests {
    my \$self = shift;
    foreach (\@_) {
        $evalstr
	;
    }
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
      warn("Failed to compile body SpamAssassin tests, skipping:\n".
	      "\t($@)\n");
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_body_tests($self, @$textary);
  }
}

# Taken from URI and URI::Find
my $reserved   = q(;/?:@&=+$,[]\#);
my $mark       = q(-_.!~*'());                                    #'; emacs
my $unreserved = "A-Za-z0-9\Q$mark\E";
my $uricSet = quotemeta($reserved) . $unreserved . "%";

my $schemeRE = '[a-zA-Z][a-zA-Z0-9.+\-]*';

my $uricCheat = $uricSet;
$uricCheat =~ tr/://d;

my $schemelessRE = qr/(?<!\.)(?:www\.|ftp\.)/;
my $uriRe = qr/(?:$schemeRE:[$uricCheat]|$schemelessRE)[$uricSet#]*/;

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
my $atom        = qq<$atom_char+(?!$atom_char)>;
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
my $Addr_spec_re   = qr<$local_part\s*\@\s*$domain>;

sub do_body_uri_tests {
  my ($self, $textary) = @_;
  my ($rulename, $pat, @uris);
  local ($_);

  dbg ("running uri tests; score so far=".$self->{hits});
  
  my $text = join('', @$textary);
  # warn("spam: /$uriRe/ $text\n");

  my $base_uri = "http://";
  while ($text =~ /\G.*?(<$uriRe>|$uriRe)/gsoc) {
      my $uri = $1;

      $uri =~ s/^<(.*)>$/$1/;

      # Use <BASE HREF="URI"> to turn relative links into
      # absolute links.
      #
      # Even If it is a base URI, Leave $uri alone, and test it like a
      # normal in case our munging of $base_uri messes something up
      if ($uri =~ s/^BASEURI://i) {
        # A base URI will be ignored by browsers unless it is an
        # absolute URI of a standrd protocol
        if ($uri =~ m{^(?:ftp|https?)://}i) {
          $base_uri = $uri;

          # Remove trailing filename, if any; base URIs can have the
          # form of "http://foo.com/index.html"
          $base_uri =~ s{^([a-z]+://[^/]+/.*?)[^/\.]+\.[^/\.]{2,4}$} {$1}i;

          # Make sure it ends in a slash
          $base_uri .= "/" unless($base_uri =~ m{/$});
        } # if ($uri =~ m{^(?:ftp|https?)://})
      } # if ($uri =~ s/^BASEURI://i)

      $uri =~ s/^URI://i;

      # Does the uri start with "http://", "mailto:", "javascript:" or
      # such?  If not, we probaly need to put the base URI in front
      # of it.
      if ($uri !~ /^[a-z]+:/i) {
        # If it's a hostname that was just sitting out in the
        # open, without a protocol, and not inside of an HTML tag,
        # the we should add the proper protocol in front, rather
        # than using the base URI.
        if ($uri =~ /^www\d?\./i) {
          $uri = "http://$uri";
        }
        elsif ($uri =~ /^ftp\./i) {
          $uri = "ftp://$uri";
        }
        else {
          $uri = "${base_uri}$uri";
        }
      } # if ($uri !~ /^[a-z]+:/i)

      # warn("Got URI: $uri\n");
      push @uris, $uri;
  }
  
  while ($text =~ /\G.*?($Addr_spec_re)/gsoc) {
      my $uri = $1;
      $uri =~ s/^URI://i;
      $uri = "mailto:$uri";
      # warn("Got URI: $uri\n");
      push @uris, $uri;
  }

  $self->clear_test_state();
  if ( defined &Mail::SpamAssassin::PerMsgStatus::_body_uri_tests ) {
    # ok, we've compiled this before.
    Mail::SpamAssassin::PerMsgStatus::_body_uri_tests($self, @uris);
    return;
  }

  # otherwise build up the eval string...
  my $evalstr = '';
  my @tests = keys %{$self->{conf}{uri_tests}};
  my @negative_tests;
  my @positive_tests;
  # add negative tests;
  foreach my $test (@tests) {
    if ($self->{conf}{scores}{$test} < 0) {
      push @negative_tests, $test;
    }
    else {
      push @positive_tests, $test;
    }
  }
  @negative_tests = sort { $self->{conf}{scores}{$a} <=> $self->{conf}{scores}{$b} } @negative_tests;
  @positive_tests = sort { $self->{conf}{scores}{$b} <=> $self->{conf}{scores}{$a} } @positive_tests;

  foreach $rulename (@negative_tests, @positive_tests) {
    $pat = $self->{conf}->{uri_tests}->{$rulename};
    $evalstr .= '
      return if $self->{stop_at_threshold} && $self->is_spam;
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        if ('.$pat.') { $self->got_uri_pattern_hit (q{'.$rulename.'}); }
      }
    ';
  }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  sub _body_uri_tests {
    my \$self = shift;
    foreach (\@_) {
        $evalstr
    ;
    }
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
      warn("Failed to compile URI SpamAssassin tests, skipping:\n".
          "\t($@)\n");
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_body_uri_tests($self, @uris);
  }
}

sub do_rawbody_tests {
  my ($self, $textary) = @_;
  my ($rulename, $pat);
  local ($_);

  dbg ("running raw-body-text per-line regexp tests; score so far=".$self->{hits});

  $self->clear_test_state();
  if ( defined &Mail::SpamAssassin::PerMsgStatus::_rawbody_tests ) {
    # ok, we've compiled this before.
    Mail::SpamAssassin::PerMsgStatus::_rawbody_tests($self, @$textary);
    return;
  }

  # build up the eval string...
  my $evalstr = '';
  my @tests = keys %{$self->{conf}{rawbody_tests}};
  my @negative_tests;
  my @positive_tests;
  # add negative tests;
  foreach my $test (@tests) {
    if ($self->{conf}{scores}{$test} < 0) {
      push @negative_tests, $test;
    }
    else {
      push @positive_tests, $test;
    }
  }
  @negative_tests = sort { $self->{conf}{scores}{$a} <=> $self->{conf}{scores}{$b} } @negative_tests;
  @positive_tests = sort { $self->{conf}{scores}{$b} <=> $self->{conf}{scores}{$a} } @positive_tests;

  foreach $rulename (@negative_tests, @positive_tests) {
    $pat = $self->{conf}->{rawbody_tests}->{$rulename};
    $evalstr .= '
      return if $self->{stop_at_threshold} && $self->is_spam;
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
        if ('.$pat.') { $self->got_body_pattern_hit (q{'.$rulename.'}); }
      }
    ';
  }

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
{
  package Mail::SpamAssassin::PerMsgStatus;

  sub _rawbody_tests {
    my \$self = shift;
    foreach (\@_) {
        $evalstr
	;
    }
  }

  1;
}
EOT

  # and run it.
  eval $evalstr;
  if ($@) {
      warn("Failed to compile body SpamAssassin tests, skipping:\n".
	      "\t($@)\n");
  }
  else {
    Mail::SpamAssassin::PerMsgStatus::_rawbody_tests($self, @$textary);
  }
}

sub do_full_tests {
  my ($self, $fullmsgref) = @_;
  my ($rulename, $pat);
  local ($_);
  
  dbg ("running full-text regexp tests; score so far=".$self->{hits});

  $self->clear_test_state();

  if (defined &Mail::SpamAssassin::PerMsgStatus::_full_tests) {
      Mail::SpamAssassin::PerMsgStatus::_full_tests($self, $fullmsgref);
      return;
  }

  # build up the eval string...
  my $evalstr = '';
  my @tests = keys %{$self->{conf}{full_tests}};
  my @negative_tests;
  my @positive_tests;
  # add negative tests;
  foreach my $test (@tests) {
    if ($self->{conf}{scores}{$test} < 0) {
      push @negative_tests, $test;
    }
    else {
      push @positive_tests, $test;
    }
  }
  @negative_tests = sort { $self->{conf}{scores}{$a} <=> $self->{conf}{scores}{$b} } @negative_tests;
  @positive_tests = sort { $self->{conf}{scores}{$b} <=> $self->{conf}{scores}{$a} } @positive_tests;
  
  foreach $rulename (@negative_tests, @positive_tests) {
    $pat = $self->{conf}->{full_tests}->{$rulename};
    $evalstr .= '
      return if $self->{stop_at_threshold} && $self->is_spam;
      if ($self->{conf}->{scores}->{q{'.$rulename.'}}) {
	if ($$fullmsgref =~ '.$pat.') {
	  $self->got_body_pattern_hit (q{'.$rulename.'});
	}
      }
    ';
  }

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

sub do_awl_tests {
    my($self) = @_;

    local $_ = lc $self->get('From:addr');
    return 0 unless /\S/;

    # Create the AWL object, then check
    $self->{auto_whitelist} = Mail::SpamAssassin::AutoWhitelist->new($self->{main});

    my $meanscore = $self->{auto_whitelist}->check_address($_);
    my $delta = 0;

    dbg("AWL active, pre-score: ".$self->{hits}.", mean: ".($meanscore||'undef'));

    if(defined($meanscore))
    {
	$delta = ($meanscore - $self->{hits})*$self->{main}->{conf}->{auto_whitelist_factor};
    }

    if($delta != 0)
    {
	$self->_handle_hit("AWL",$delta,"AWL: ","Auto-whitelist adjustment");
    }

    dbg("Post AWL score: ".$self->{hits});

    # Update the AWL
    $self->{auto_whitelist}->add_score($self->{hits});
    $self->{auto_whitelist}->finish();		# done with this now
}

###########################################################################

sub mk_param {
  my $param = shift;

  my @ret = ();
  while ($param =~ s/^\s*['"](.*?)['"](?:,|)\s*//) {
    push (@ret, $1);
  }
  return @ret;
}

sub run_eval_tests {
  my ($self, $evalhash, $prepend2desc, @extraevalargs) = @_;
  my ($rulename, $pat, @args);
  local ($_);

  foreach my $rulename (sort keys %{$evalhash}) {
    next unless ($self->{conf}->{scores}->{$rulename});
    return if $self->{stop_at_threshold} && $self->is_spam;
    my $evalsub = $evalhash->{$rulename};

    my $result;
    $self->clear_test_state();

    @args = ();
    if (scalar @extraevalargs >= 0) { push (@args, @extraevalargs); }

    $evalsub =~ s/\s*\((.*?)\)\s*$//;
    if (defined $1 && $1 ne '') { push (@args, mk_param($1)); }

    eval {
        $result = $self->$evalsub(@args);
    };
    if ($@) {
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

sub got_uri_pattern_hit {
  my ($self, $rulename) = @_;

  # only allow each test to hit once per mail
  # TODO: Move this into the rule matcher
  return if (defined $self->{tests_already_hit}->{$rulename});
  $self->{tests_already_hit}->{$rulename} = 1;

  $self->got_hit ($rulename, 'URI: ');
}

###########################################################################

# note: only eval tests should store state in here; pattern tests do
# not.
sub clear_test_state {
  my ($self) = @_;
  $self->{test_log_msgs} = '';
}

sub _handle_hit {
    my ($self, $rule, $score, $area, $desc) = @_;

    $score = sprintf("%2.1f",$score);
    $self->{hits} += $score;
    $self->{test_names_hit} .= $rule.',';

    if ($self->{conf}->{use_terse_report}) {
	$self->{test_logs} .= sprintf ("* % 2.1f -- %s%s\n%s",
				       $score, $area, $desc, $self->{test_log_msgs});
    } else {
	$self->{test_logs} .= sprintf ("%-18s %s%s\n%s",
				       "Hit! (".$score." point".($score == 1 ? "":"s").")",
				       $area, $desc, $self->{test_log_msgs});
    }
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
  if ($self->{conf}->{use_terse_report}) {
    $self->{test_log_msgs} .= sprintf ("%9s [%s]\n", "", $msg);
  } else {
    $self->{test_log_msgs} .= sprintf ("%18s [%s]\n", "", $msg);
  }
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
  my $self = shift;
  local $_ = shift;

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

# contributed by Matt: a wrapper for slow_base64_decode() which uses
# MIME::Base64 if it's installed.
sub generic_base64_decode {
    my ($self, $to_decode) = @_;
    
    my $retval;
    eval {
        require MIME::Base64;
        $retval = MIME::Base64::decode_base64($to_decode);
    };
    if ($@) {
        return $self->slow_base64_decode($to_decode);
    }
    else {
        return $retval;
    }
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

sub remove_unwanted_headers {
  my ($self) = @_;
  $self->{msg}->delete_header ("X-Spam-Status");
  $self->{msg}->delete_header ("X-Spam-Checker-Version");
  $self->{msg}->delete_header ("X-Spam-Flag");
  $self->{msg}->delete_header ("X-Spam-Report");
}

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

