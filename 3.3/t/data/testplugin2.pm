=head1 testplugin2.pm

To try this out, write these lines to /etc/mail/spamassassin/plugintest.cf:

  loadplugin     myTestPlugin
  header         MY_TEST_PLUGIN eval:check_test_plugin()

=cut

package myTestPlugin2;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use bytes;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_method_priority('extract_metadata', 200);

  print "registered myTestPlugin2: $self\n";
  return $self;
}

sub extract_metadata {
  my ($self, $opts) = @_;
  my $msg = $opts->{msg};
  print "myTestPlugin2 extract_metadata: $self\n";

  # note: this has to run after myTestPlugin has run, via the magic
  # of priorities, otherwise 'Plugin-Meta-Test2' will not contain
  # 'bar2'.

  if ($msg->get_metadata("Plugin-Meta-Test") =~ /bar/) {
    $msg->put_metadata("Plugin-Meta-Test2", "bar2");
  }
  return 1;
}

1;
