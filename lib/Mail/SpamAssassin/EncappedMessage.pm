# Mail::SpamAssassin::EncappedMessage - interface to Mail::Audit message text,
# for versions of Mail::Audit with methods to encapsulate the message text
# itself (ie. not exposing a Mail::Internet object).

package Mail::SpamAssassin::EncappedMessage;

use Carp;
use strict;

use Mail::SpamAssassin::AuditMessage;

use vars	qw{
  	@ISA
};

@ISA = qw(Mail::SpamAssassin::AuditMessage);

###########################################################################

sub replace_header {
  my ($self, $hdr, $text) = @_;
  $self->{mail_object}->replace_header ($hdr, $text);
}

sub delete_header {
  my ($self, $hdr) = @_;
  $self->{mail_object}->delete_header ($hdr);
}

sub get_body {
  my ($self) = @_;
  $self->{mail_object}->body();
}

sub replace_body {
  my ($self, $aryref) = @_;
  $self->{mail_object}->body ($aryref);
}

1;
