=head1 testplugin.pm

To try this out, write these lines to /etc/mail/spamassassin/plugintest.cf:

  loadplugin     myTestPlugin
  header         MY_TEST_PLUGIN eval:check_test_plugin()

=cut

package myTestPlugin;

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

  # the important bit!
  $self->register_eval_rule ("check_test_plugin");
  $self->register_eval_rule ("check_return_2");
  $self->register_eval_rule ("sleep_based_on_header");

  print "registered myTestPlugin: $self\n";
  return $self;
}

# and the eval rule itself
sub check_test_plugin {
  my ($self, $permsgstatus) = @_;
  print "myTestPlugin eval test called: $self\n";

  print "test: plugins loaded: ".
        join(" ", sort $self->{main}->get_loaded_plugins_list()).
        "\n";

  my $file = $ENV{'SPAMD_PLUGIN_COUNTER_FILE'};
  if ($file) {
    open (IN, "<$file") or warn;
    my $count = <IN>; $count += 0;
    close IN;

    dbg("test: called myTestPlugin, round $count");

    open (OUT, ">$file") or warn;
    print OUT ++$count;
    close OUT or warn;
  }

  return 1;
}

sub sleep_based_on_header {
  my ($self, $permsgstatus) = @_;
  my $secs = $permsgstatus->{msg}->get_header("Sleep-Time");
  chop $secs;

  if ($secs) {
    warn "sleeping for $secs seconds...";
    sleep ($secs+0);
  }

  return 1;
}

sub check_return_2 {
  return 2;
}

sub extract_metadata {
  my ($self, $opts) = @_;
  my $msg = $opts->{msg};
  print "myTestPlugin extract_metadata: $self\n";
  $msg->put_metadata("Plugin-Meta-Test", "bar");
  return 1;
}

sub per_msg_finish {
  my ($self, $permsgstatus) = @_;
  print "myTestPlugin finishing: $self\n";
  return 1;
}

1;
