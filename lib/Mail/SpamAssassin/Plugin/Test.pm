=head1 

To try this out, write these lines to /etc/mail/spamassassin/plugintest.cf:

  loadplugin     Mail::SpamAssassin::Plugin::Test
  header         MY_TEST_PLUGIN eval:check_test_plugin()

=cut

package Mail::SpamAssassin::Plugin::Test;

use Mail::SpamAssassin::Plugin;
use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule ("check_test_plugin");

  print "registered Mail::SpamAssassin::Plugin::Test: $self\n";
  return $self;
}

# and the eval rule itself
sub check_test_plugin {
  my ($self, $permsgstatus) = @_;
  print "Mail::SpamAssassin::Plugin::Test eval test called: $self\n";
  # ... hard work goes here...
  return 1;
}

1;
