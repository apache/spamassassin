=head1 WARNING

This is a sample plugin, it may not work at all, so buyer beware.

=cut

package reporterplugin;

use strict;
use bytes;
use Cwd;

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

sub plugin_report {
  my ($self, $options) = @_;

  if (-e 'log/rptfail') {
    $options->{report}->{report_available} = 0;
    $options->{report}->{report_return} = 0;
  }
  else {
    $options->{report}->{report_available} = 1;
    $options->{report}->{report_return} = 1;
  }

  return;
}

sub plugin_revoke {
  my ($self, $options) = @_;

  if (-e 'log/rptfail') {
    $options->{revoke}->{revoke_available} = 0;
    $options->{revoke}->{revoke_return} = 0;
  }
  else {
    $options->{revoke}->{revoke_available} = 1;
    $options->{revoke}->{revoke_return} = 1;
  }

  return;
}

1;
