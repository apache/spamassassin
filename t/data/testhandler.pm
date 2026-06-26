=head1 testhandler.pm

A minimal plugin used by t/handler.t to exercise the MIME-part handler
framework end-to-end: text injection, per-message metadata + an eval rule, and
child-part chaining/recursion.  It also exercises registering two different
handler methods for two different types via register_handler.

To try it out:

  loadplugin myTestHandler ../../../data/testhandler.pm
  body HANDLER_A /HANDLER_SENTINEL_A/
  body HANDLER_B /HANDLER_SENTINEL_B/
  header HANDLER_EVAL eval:check_test_handler()

=cut

package myTestHandler;

use strict;
use warnings;

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Handler);

sub new {
  my ($class, $main) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($main);
  bless ($self, $class);

  # Two handler methods for two types -- proves register_handler's per-method
  # signature.
  $self->register_handler('text/plain',            'handle_text');
  $self->register_handler('application/x-sa-test', 'handle_child');

  $self->register_eval_rule('check_test_handler');

  return $self;
}

sub handle_text {
  my ($self, $node, $pms) = @_;

  # Append sentinel A to the part's rendered text and emit a synthetic child of
  # a second type to drive chaining.  Record a per-message flag for the eval
  # rule to read off $pms (never off $self -- the plugin is a singleton).
  my (undef, $rnd) = $node->rendered();
  $rnd = '' unless defined $rnd;
  $node->set_rendered($rnd . "\nHANDLER_SENTINEL_A\n");
  $pms->{handlers}{TestHandler}{test_fired} = 1;
  dbg("handler: testhandler fired on text/plain, emitting child");
  return [ { type => 'application/x-sa-test',
             data => "child payload bytes",
             name => 'child.dat' } ];
}

sub handle_child {
  my ($self, $node, $pms) = @_;

  # This part only exists because handle_text emitted it and the dispatcher
  # re-queued it -- proving chaining/recursion.
  $node->set_rendered("HANDLER_SENTINEL_B\n");
  dbg("handler: testhandler fired on chained application/x-sa-test");
  return [];
}

sub check_test_handler {
  my ($self, $pms) = @_;
  return $pms->{handlers}{TestHandler}{test_fired} ? 1 : 0;
}

1;
