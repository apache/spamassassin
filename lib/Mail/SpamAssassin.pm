=head1 NAME

Mail::SpamAssassin - Mail::Audit spam detector plugin

=head1 SYNOPSIS

  my $mail = Mail::Audit->new();

  my $spamtest = Mail::SpamAssassin->new();
  my $status = $spamtest->check ($mail);

  if ($status->is_spam ()) {
    $status->rewrite_mail ();
    $mail->accept("spamfolder");

  } else {
    $mail->accept();		# to default incoming mailbox
  }
  ...


=head1 DESCRIPTION

Mail::SpamAssassin is a Mail::Audit plugin to identify spam using text
analysis and several internet-based realtime blacklists.

Using its rule base, it uses a wide range of heuristic tests on mail headers
and body text to identify "spam", also known as unsolicited commercial email.

Once identified, the mail can then be optionally tagged as spam for later
filtering using the user's own mail user-agent application.

This module implements a Mail::Audit plugin, allowing SpamAssassin to be used
in a Mail::Audit filter.  If you wish to use a command-line filter tool,
try the L<spamassassin> tool provided.

SpamAssassin also includes support for reporting spam messages to collaborative
filtering databases, such as Vipul's Razor ( http://razor.sourceforge.net/ ).

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Reporter;
use Mail::SpamAssassin::Replier;
use Carp;
use File::Basename;
use File::Path;
use File::Spec;
use File::Copy;
use Cwd;
use Config;
use strict;

use vars	qw{
  	@ISA $VERSION $HOME_URL $DEBUG
	@default_rules_path @default_prefs_path @default_userprefs_path
};

@ISA = qw();

$VERSION = "1.2";
sub Version { $VERSION; }

$HOME_URL = "http://spamassassin.taint.org/";

$DEBUG = 0;

@default_rules_path = qw(
        ./spamassassin.cf
        ../spamassassin.cf
        /etc/spamassassin.cf
        __installsitelib__/spamassassin.cf
);
    
@default_prefs_path = qw(
        /etc/spamassassin.prefs
        __installsitelib__/spamassassin.prefs
);
    
@default_userprefs_path = qw(
        ./spamassassin.prefs 
        ../spamassassin.prefs
        ~/.spamassassin.cf
);

###########################################################################

=item $f = new Mail::SpamAssassin( [ { opt => val, ... } ] )

Constructs a new C<Mail::SpamAssassin> object.  You may pass the
following attribute-value pairs to the constructor.

=over 4

=item rules_filename

The filename to load spam-identifying rules from. (optional)

=item userprefs_filename

The filename to load preferences from. (optional)

=item config_text

The text of all rules and preferences.  If you prefer not to load the rules
from files, read them in yourself and set this instead.

If none of rules_filename, userprefs_filename, or config_text is set,
the C<Mail::SpamAssassin> module will search for the configuration files
in the usual installed locations.

=item local_tests_only

If set to 1, no tests that require internet access will be performed.

=back

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  if (defined $self->{debug}) { $DEBUG = $self->{debug}+0; }

  $self->{conf} = new Mail::SpamAssassin::Conf ($self);
  $self;
}

###########################################################################

=item $status = $f->check ($mail)

Check a mail, encapsulated in a C<Mail::Audit> object, to determine if
it is spam or not.

Returns a C<Mail::SpamAssassin::PerMsgStatus> object which can be
used to test or manipulate the mail message.

Note that the C<Mail::SpamAssassin> object can be re-used for further messages
without affecting this check; in OO terminology, the C<Mail::SpamAssassin>
object is a "factory".

=cut

sub check {
  my ($self, $audit) = @_;
  local ($_);

  $self->init();
  my $mail = $self->encapsulate_audit ($audit);
  my $msg = new Mail::SpamAssassin::PerMsgStatus ($self, $mail);
  $msg->check();
  $msg;
}

###########################################################################

=item $f->report_as_spam ($mail)

Report a mail, encapsulated in a C<Mail::Audit> object, as human-verified spam.
This will submit the mail message to live, collaborative, spam-blocker
databases, allowing other users to block this message.

=cut

sub report_as_spam {
  my ($self, $audit) = @_;
  local ($_);

  $self->init();
  my $mail = $self->encapsulate_audit ($audit);
  my $msg = new Mail::SpamAssassin::Reporter ($self, $mail);
  $msg->report();
}

###########################################################################

=item $f->reply_with_warning ($mail, $replysender)

Reply to the sender of a mail, encapsulated in a C<Mail::Audit> object,
explaining that their message has been added to spam-tracking databases
and deleted.  To be used in conjunction with C<report_as_spam>.  The
C<$replysender> argument should contain an email address to use as the
sender of the reply message.

=cut

sub reply_with_warning {
  my ($self, $audit, $replysender) = @_;
  local ($_);

  $self->init();
  my $mail = $self->encapsulate_audit ($audit);
  my $msg = new Mail::SpamAssassin::Replier ($self, $mail);
  $msg->reply ($replysender);
}

###########################################################################

=item $text = $f->remove_spamassassin_markup ($mail)

Returns the text of the message, with any SpamAssassin-added text (such
as the report, or X-Spam-Status headers) stripped.

=cut

sub remove_spamassassin_markup {
  my ($self, $audit) = @_;
  local ($_);

  $self->init();
  my $mail = $self->encapsulate_audit ($audit);

  my $hdrs = $mail->get_all_headers();

  # reinstate the old content type
  if ($hdrs =~ /^X-Spam-Prev-Content-Type: /m) {
    $hdrs =~ s/\nContent-Type: [^\n]*?\n/\n/gs;
    $hdrs =~ s/\nX-Spam-Prev-(Content-Type: [^\n]*?\n)/\n$1/gs;
  }

  # remove the headers we added
  1 while $hdrs =~ s/\nX-Spam-[^\n]*?\n/\n/gs;
  1 while $hdrs =~ s/^Subject: \*+SPAM\*+ /Subject: /gm;

  # ok, next, the report.
  # This is a little tricky since we can have either 0, 1 or 2 reports;
  # 0 for the non-spam case, 1 for normal filtering, and 2 for -t (where
  # an extra report is appended at the end of the mail).

  my @newbody = ();
  my $inreport = 0;
  foreach $_ (@{$mail->get_body()})
  {
    if (/^SPAM: ----/ && $inreport == 0) {
      # we've just entered a report.  If there's a blank line before the
      # report, get rid of it...
      if ($#newbody > 0 && $newbody[$#newbody-1] =~ /^$/) {
	pop (@newbody);
      }
      # and skip on to the next line...
      $inreport = 1; next;
    }

    if ($inreport && /^$/) {
      # blank line at end of report; skip it.  Also note that we're
      # now out of the report.
      $inreport = 0; next;
    }

    # finally, if we're not in the report, add it to the body array
    if (!$inreport) {
      push (@newbody, $_);
    }
  }

  return $hdrs."\n".join ('', @newbody);
}

###########################################################################
# non-public methods.

sub init {
  my ($self) = @_;

  if ($self->{_initted}) { return; }
  $self->{_initted} = 1;

  if (!defined $self->{config_text}) {
    $self->{config_text} = '';

    my $fname = $self->{rules_filename};
    if (!defined $fname) {
      $fname = $self->first_existing_path (@default_rules_path);
    }
    dbg ("using \"$fname\" for rules file");

    if (defined $fname) {
      open (IN, "<".$fname) or
		  warn "cannot open \"$fname\"\n";
      $self->{config_text} .= join ('', <IN>);
      close IN;
    }

    $fname = $self->{userprefs_filename};
    if (!defined $fname) {
      $fname = $self->first_existing_path (@default_userprefs_path);
      dbg ("using \"$fname\" for user prefs file");

      if (!-f $fname) {
	# copy in the default one for later editing

	my $defprefs = $self->first_existing_path
				 (@Mail::SpamAssassin::default_prefs_path);
	use File::Copy;
	if (copy ($defprefs, $fname)) {
	  warn "Created user preferences file: $fname\n";
	} else {
	  warn "Failed to create user preferences file\n".
		    "\"$fname\" from default \"$defprefs\".\n";
	}
      }
    }

    if (defined $fname) {
      open (IN, "<".$fname) or
		  warn "cannot open \"$fname\"\n";
      $self->{config_text} .= join ('', <IN>);
      close IN;
    }
  }

  $self->{conf}->parse_rules ($self->{config_text});
  $self->{conf}->finish_parsing ();

  # TODO -- open DNS cache etc.
}

###########################################################################

sub expand_name ($) {
  my $self = shift;
  my $name = shift;
  return (getpwnam($name))[7] if ($name ne '');
  return $ENV{'HOME'} if defined $ENV{'HOME'};
  return (getpwuid($>))[7];
}

sub sed_path {
  my $self = shift;
  my $path = shift;
  $path =~ s/__installsitelib__/$Config{installsitelib}/gs;
  $path =~ s/^\~([^\/]*)/$self->expand_name($1)/es;
  $path;
}

sub first_existing_path {
  my $self = shift;
  my $path;
  foreach my $p (@_) {
    $path = $self->sed_path ($p);
    if (-e $path) { return $path; }
  }
  $path;
}

###########################################################################

sub encapsulate_audit {
  my ($self, $audit) = @_;

  # first, check to see if this is not actually a Mail::Audit object;
  # it could also be an already-encapsulated Mail::Audit wrapped inside
  # a Mail::SpamAssassin::Message.
  if ($audit->{is_spamassassin_wrapper_object}) {
    return $audit;
  }

  if (!defined $self->{mail_audit_supports_encapsulation}) {
    # test Mail::Audit for new-style encapsulation of the Mail::Internet
    # message object.
    my ($hdr, $val);
    foreach my $hdrtest (qw(From To Subject Message-Id Date Sender)) {
      $val = $audit->get ($hdrtest);
      if (defined $val) { $hdr = $hdrtest; last; }
    }

    if (!defined $val) {                  # ah, just make one up
      $hdr = 'X-SpamAssassin-Test-Header'; $val = 'x';
    }

    # now try using one of the new methods...
    if (eval q{
		  $audit->replace_header ($hdr, $val);
		  1;
	  })
    {
      dbg ("using Mail::Audit message-encapsulation code");
      $self->{mail_audit_supports_encapsulation} = 1;
    } else {
      dbg ("using Mail::Audit exposed-message-object code");
      $self->{mail_audit_supports_encapsulation} = 0;
    }
  }

  if ($self->{mail_audit_supports_encapsulation}) {
    return new Mail::SpamAssassin::EncappedMessage ($self, $audit);
  } else {
    return new Mail::SpamAssassin::ExposedMessage ($self, $audit);
  }
}

sub dbg {
  if ($Mail::SpamAssassin::DEBUG > 0) { warn "debug: ".join('',@_)."\n"; }
}

1;
__END__

###########################################################################

=back

=head1 PREREQUISITES

C<Mail::Audit>
C<Mail::Internet>

=head1 COREQUISITES

C<Net::DNS>

=head1 MORE DOCUMENTATION

See also http://spamassassin.taint.org/ for more information.

=head1 SEE ALSO

C<Mail::SpamAssassin::PerMsgStatus>
C<spamassassin>

=head1 AUTHOR

Justin Mason E<lt>jm /at/ jmason.orgE<gt>

=head1 COPYRIGHT

SpamAssassin is distributed under Perl's Artistic license.

=head1 AVAILABILITY

The latest version of this library is likely to be available from CPAN
as well as:

  http://spamassassin.taint.org/

=cut


