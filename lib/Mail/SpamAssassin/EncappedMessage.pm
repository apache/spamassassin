=head1 NAME

Mail::SpamAssassin::EncappedMessage - interface to Mail::Audit message text,
for versions of Mail::Audit with methods to encapsulate the message text
itself (ie. not exposing a Mail::Internet object).

=cut

package Mail::SpamAssassin::EncappedMessage;

use Carp;
use strict;

use Mail::Audit;

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
  $mail->replace_header ($hdr, $text);
}

sub delete_header {
  my ($self, $hdr) = @_;
  my $mail = $self->{audit};
  $mail->delete_header ($hdr);
}

sub get_body {
  my ($self) = @_;
  my $mail = $self->{audit};
  $mail->body();
}

sub replace_body {
  my ($self, $aryref) = @_;
  my $mail = $self->{audit};
  $mail->body ($aryref);
}

1;
