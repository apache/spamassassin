=head1 mockimagehandler.pm

A minimal plugin used by t/handler_html.t to prove that inline
C<data:> images embedded in HTML are surfaced to the MIME-part handler
framework as pseudo parts.

The plugin registers a handler for C<image/*>.  When the HTML parser extracts
an inline C<data:image/...;base64,...> image, the renderer builds a synthetic
leaf part for it and apply_handlers() dispatches it here.  We verify the
decoded bytes (PNG magic) and content type reached us, then record a
per-message flag for an eval rule to read.

To try it out:

  loadhandler myTestImageHandler ../../../data/mockimagehandler.pm
  header DATA_IMAGE_SEEN eval:check_data_image_handler()

=cut

package myTestImageHandler;

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

  $self->register_handler('image/*', 'handle_image');
  $self->register_eval_rule('check_data_image_handler');

  return $self;
}

sub handle_image {
  my ($self, $node, $pms) = @_;

  my $data = $node->decode();
  my $type = $node->{type} || '';

  # PNG magic: \x89PNG\r\n\x1a\n
  my $is_png = defined $data && substr($data, 0, 8) eq "\x89PNG\r\n\x1a\n";

  if ($is_png && $type eq 'image/png' && $node->{synthetic}) {
    $pms->{handlers}{TestImage}{data_image_seen} = 1;
    dbg("handler: mockimagehandler saw inline data: PNG (%d bytes)",
        length $data);
  }
  return [];
}

sub check_data_image_handler {
  my ($self, $pms) = @_;
  return $pms->{handlers}{TestImage}{data_image_seen} ? 1 : 0;
}

1;
