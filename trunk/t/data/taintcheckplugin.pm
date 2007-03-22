=head1 

To try this out, write these lines to /etc/mail/spamassassin/plugintest.cf:

  loadplugin     myTestPlugin
  header         MY_TEST_PLUGIN eval:check_test_plugin()

=cut

package myTestPlugin;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use bytes;
use Test;

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  print "registered myTestPlugin: $self\n";
  return $self;
}

sub check_post_learn {
  my ($self, $opts) = @_;
  print "running check_end: $self\n";
  my $m = $opts->{permsgstatus}->{msg};

  print "tainted get_header found\n"
    if (is_tainted($m->get_header("Subject")));

  # TODO?
  # print "tainted get_all_metadata found\n"
  # if (is_tainted($m->get_all_metadata()));

  print "tainted get_pristine_header found\n"
    if (is_tainted($m->get_pristine_header("Subject")));
  print "tainted get_pristine found\n"
    if (is_tainted($m->get_pristine()));
  print "tainted get_pristine_body found\n"
    if (is_tainted($m->get_pristine_body()));

  print "tainted get_body found\n"
    if (is_tainted($m->get_body()->[0]));
  print "tainted get_visible_rendered_body_text_array found\n"
    if (is_tainted($m->get_visible_rendered_body_text_array()->[0]));

  # skip get_invisible_rendered_body_text_array; it produces no output
  # on that msg (TODO)

  print "tainted get_decoded_body_text_array found\n"
    if (is_tainted($m->get_decoded_body_text_array()->[0]));
  print "tainted get_rendered_body_text_array found\n"
    if (is_tainted($m->get_rendered_body_text_array()->[0]));
 
  return 1;
}


sub is_tainted {
  # from perldoc perlsec
  return ! eval { eval("#" . substr(join("", @_), 0, 0)); 1 };
}


1;
