# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Handler::HTML - a MIME-part handler for text/html parts

=head1 SYNOPSIS

  loadhandler    Mail::SpamAssassin::Handler::HTML

=head1 DESCRIPTION

This handler registers as the MIME-part handler for C<text/html>.  It
renders each HTML part by calling C<rendered()> on it -- which parses the HTML
and caches the rendered text and C<html_results>.

=head1 RETURNS

The handler returns synthetic child parts that the HTML parser extracted but
that have no MIME part of their own, such as:

=over 4

=item *

Images embedded inline as C<data:> URIs (e.g.
C<< <img src="data:image/png;base64,..."> >>), returned as C<image/*> parts and
dispatched to any registered image handler.

=item *

Embedded JavaScript -- both C<< <script> >> element bodies and attribute-level
JS (C<on*> handlers, C<javascript:> URIs) -- returned as C<text/javascript>
parts for the JavaScript handler.  Because script in a rendered message body is
inert (no MUA executes it), these are surfaced B<only when the HTML part is
itself an attachment>; body script is dropped.

=back

=cut

package Mail::SpamAssassin::Handler::HTML;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Handler);

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_handler('text/html', 'handle_html');

  return $self;
}

# MIME-part handler for text/html.  Render the part (warming the cache for the
# lazy callers that come later) and return any inline data: images the HTML
# parser extracted, as child-part specs for the framework to dispatch.
sub handle_html {
  my ($self, $node, $pms) = @_;

  # The ultimate goal is to do the HTML rendering here in the handler, so that
  # Mail::SpamAssassin::Message::Node::rendered() becomes a plain accessor for
  # the cached result.  For now we just reuse the rendering code already in
  # rendered(): it parses the HTML and caches the result (and html_results), so
  # later lazy callers of rendered() get a cache hit.  Idempotent.
  $node->rendered();

  my $results = $node->{html_results}  or return [];

  my @parts;

  # Typed pseudo-parts the HTML parser extracted, each already a
  # { type => '<mediatype>', data => $bytes } child-part spec: inline data: URIs
  # AND script content (carried under its declared type; see HTML::html_text /
  # html_tag / html_attributes).  Both <script> element bodies and attribute-level
  # JS (on* handlers, javascript: URIs) are buffered under text/javascript.  The
  # framework dispatches each by type (image/* -> image handler, text/html -> back
  # to this handler, text/javascript -> JavaScript handler, application/ld+json ->
  # elsewhere or nowhere, ...).  This is how a <script type="application/ld+json">
  # data block stays out of the JavaScript handler.
  #
  # JavaScript in a *rendered message body* is inert -- no MUA executes <script>
  # in displayed HTML -- so we do NOT surface body script to the JavaScript
  # handler at all.  Only script that lives in an attachment can actually run if
  # the user opens it, so we emit the text/javascript parts only when this HTML
  # part is itself an attachment (Content-Disposition: attachment, or it carries a
  # filename).  Script from a .js attachment or an archive member reaches the
  # JavaScript handler by other dispatch paths and is unaffected by this gate.
  # Non-script parts (inline data: images, ld+json, ...) are always surfaced.
  my $is_attach = (defined $node->{disposition} && $node->{disposition} eq 'attachment')
                  || defined $node->{name};
  my $data_parts = $results->{data_parts};
  if (ref $data_parts eq 'ARRAY') {
    push @parts,
      grep { $is_attach || ($_->{type} // '') ne 'text/javascript' } @$data_parts;
  }

  return \@parts;
}

1;
