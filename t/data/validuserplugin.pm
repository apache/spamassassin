=head1 WARNING

This is a sample plugin, it may not work at all, so buyer beware.

=cut

package validuserplugin;

use strict;
use bytes;

use Mail::SpamAssassin::Plugin;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  return $self;
}

# test the method.  only allow if the username is NOT iwillfail

sub services_allowed_for_username {
  my ($self, $options) = @_;

  my $username = $options->{username};

  my $services = $options->{services};

  $services->{bayessql} = 1 unless ($username eq 'iwillfail');
      
  return;
}

1;
