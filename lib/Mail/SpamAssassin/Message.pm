=head1 NAME

Mail::SpamAssassin::Message - interface to Mail::Audit message text

=head1 NOTES

I could have done this more OO, using subclasses; but this is faster,
both to code and to run (less class files to load).

=cut

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
  die "unimpled base method";
}

sub put_header {
  die "unimpled base method";
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
