# Mail::SpamAssassin::Message - interface to Mail::Audit message text

package Mail::SpamAssassin::Message;

use Carp;
use strict;

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
  };
  bless ($self, $class);
  $self;
}

###########################################################################

sub get_header {
  my ($self, $hdr) = @_;
  $self->{audit}->get ($hdr);
}

sub put_header {
  my ($self, $hdr, $text) = @_;
  $self->{audit}->put_header ($hdr, $text);
}

sub get_all_headers {
  my ($self) = @_;
  $self->{audit}->header();
}

sub replace_header {
  die "unimpled base method";
}

sub delete_header {
  die "unimpled base method";
}

sub get_body {
  die "unimpled base method";
}

sub replace_body {
  die "unimpled base method";
}

1;
