=head1 NON-PUBLIC CLASS NAME

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

sub replace_header {
  my ($self, $hdr, $val) = @_;
  $self->{audit}->{obj}->head->replace ($hdr, $val);
}

sub delete_header {
  my ($self, $hdr) = @_;
  $self->{audit}->{obj}->head->delete ($hdr);
}

sub get_body {
  my ($self) = @_;
  $self->{audit}->{obj}->body();
}

sub replace_body {
  my ($self, $aryref) = @_;
  $self->{audit}->{obj}->body ($aryref);
}

1;
