# Mail::SpamAssassin::ExposedMessage - interface to Mail::Audit message text,
# for Mail::Audit versions up to 1.9.

package Mail::SpamAssassin::ExposedMessage;

use Carp;
use strict;
eval "use bytes";

use Mail::SpamAssassin::AuditMessage;

use vars	qw{
  	@ISA
};

@ISA = qw(Mail::SpamAssassin::AuditMessage);

###########################################################################

sub replace_header {
  my ($self, $hdr, $val) = @_;
  $self->{mail_object}->{obj}->head->replace ($hdr, $val);
}

sub delete_header {
  my ($self, $hdr) = @_;
  $self->{mail_object}->{obj}->head->delete ($hdr);
}

sub get_header {
    my ($self, $hdr) = @_;
      $self->{mail_object}->get ($hdr);
}

sub get_body {
  my ($self) = @_;
  $self->{mail_object}->{obj}->body();
}

sub replace_body {
  my ($self, $aryref) = @_;
  $self->{mail_object}->{obj}->body ($aryref);
  undef $aryref;		# help in GC'ing
}

1;
