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
use Cwd;
use strict;

use vars	qw{
  	@ISA $VERSION $HOME_URL $DEBUG
};

@ISA = qw();

$VERSION = "1.0";
sub Version { $VERSION; }

$HOME_URL = "http://spamassassin.taint.org/";

$DEBUG = 0;

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
from files, read them in yourself and set this instead.  This is optional, but
note that at least one of C<rules_filename>, C<userprefs_filename> or
C<config_text> must be specified to provide configuration, otherwise
SpamAssassin will not do anything!

The L<spamassassin> command-line tool includes quite a lot of logic to find its
configuration files in a variety of locations, so see its documentation for
more details on how it loads its configuration.   (It is assumed that users of
the C<Mail::SpamAssassin> module will wish to load a ''canned'' configuration,
which is why the config-searching logic is not included here.)

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
  my $body = join ('', @{$mail->get_body()});

  while ($body =~ /^SPAM: /m)
  {
    # strip off all the SPAM: lines
    1 while $body =~ s/\n*SPAM: [^\n]*?\n//gs;

    # and finally, strip off an extra blank line at the start of the
    # mail; the template is always added with an NL before and after it
    $body =~ s/^\n//gs;
  }

  return $hdrs."\n".$body;
}

###########################################################################
# non-public methods.

sub init {
  my ($self) = @_;

  if ($self->{_initted}) { return; }
  $self->{_initted} = 1;

  $self->{config_text} ||= '';

  if (defined $self->{rules_filename}) {
    open (IN, "<".$self->{rules_filename}) or
		warn "cannot open \"$self->{rules_filename}\"\n";
    $self->{config_text} .= join ('', <IN>);
    close IN;
  }

  if (defined $self->{userprefs_filename}) {
    open (IN, "<".$self->{userprefs_filename}) or
		warn "cannot open \"$self->{userprefs_filename}\"\n";
    $self->{config_text} .= join ('', <IN>);
    close IN;
  }

  $self->{conf}->parse_rules ($self->{config_text});

  # TODO -- open DNS cache etc.
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


