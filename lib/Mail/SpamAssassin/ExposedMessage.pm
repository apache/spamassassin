=head1 NAME

Mail::SpamAssassin::ExposedMessage - interface to Mail::Audit message text,
for Mail::Audit versions up to 1.9.

=cut

package Mail::SpamAssassin::ExposedMessage;

use Carp;
use strict;

use Mail::Audit;
use Mail::SpamAssassin::Message;

use vars	qw{
  	@ISA
};

@ISA = qw(Mail::SpamAssassin::Message);

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new (@_);
  bless ($self, $class);
  $self;
}

###########################################################################

sub get_header {
  my ($self, $hdr) = @_;
  my $mail = $self->{audit};
  $mail->get ($hdr);
}

sub put_header {
  my ($self, $hdr, $text) = @_;
  my $mail = $self->{audit};
  $mail->put_header ($hdr, $text);
}

sub replace_header {
  my ($self, $hdr, $text) = @_;
  my $mail = $self->{audit};
  $mail->{obj}->head->replace ($hdr, $text);
}

sub delete_header {
  my ($self, $hdr) = @_;
  my $mail = $self->{audit};
  $mail->{obj}->head->delete ($hdr);
}

sub get_body {
  my ($self) = @_;
  my $mail = $self->{audit};
  $mail->{obj}->body();
}

sub replace_body {
  my ($self, $aryref) = @_;
  my $mail = $self->{audit};
  $mail->{obj}->body ($aryref);
}

1;
