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
parses and renders each HTML part, publishing the rendered text back onto the
part with C<set_rendered()> and caching the parser's findings in
C<html_results>.

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
use Mail::SpamAssassin::HTML;
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

  # Parse and render the HTML.  Idempotent: a part can reach the handler twice
  # (identical content re-dispatched as a synthetic child), and re-parsing would
  # just rebuild the same results, so skip straight to the harvest below.
  $self->_render($node)  if !$node->{html_results};

  my $results = $node->{html_results}  or return [];

  # Harvest URIs the HTML parser found into the URI detail list (type 'html')
  my $detail = $results->{uri_detail} || {};
  $pms->{'uri_truncated'} = 1 if $results->{uri_truncated};
  while (my ($uri, $info) = each %$detail) {
    if ($pms->add_uri_detail_list($uri, $info->{types}, 'html', 0)) {
      # Copy and uniq the anchor text, collapsing whitespace (Bug 8268/8310).
      if (exists $info->{anchor_text}) {
        for (@{$info->{anchor_text}}) {
          s/^\s+|\s+$//g;
          s/\s+/ /g;
          utf8::encode($_) if utf8::is_utf8($_);
        }
        my %seen;
        foreach (grep { !$seen{$_}++ } @{$info->{anchor_text}}) {
          push @{$pms->{uri_detail_list}->{$uri}->{anchor_text}}, $_;
        }
      }
    }
  }

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

# Parse one text/html part and publish what the parser produced onto the node:
# the rendered text (all of it, plus the visible-only and invisible-only
# streams) via set_rendered(), and the parser's findings in {html_results} for
# the HTML eval rules.  Body rules, Bayes and the html_* rules all read these
# back later; nothing here touches $pms.
sub _render {
  my ($self, $node) = @_;

  # Length of the part's decoded bytes, before any charset transcoding -- the
  # denominator of the html_length/text-length ratio below.
  my $text_len = length($node->decode // '');

  # An empty part has nothing to parse, but still renders as empty text rather
  # than as "not rendered at all" -- callers counting text vs. HTML parts (e.g.
  # BodyEval::check_for_mime_html) have always seen it, and skipping it here
  # would silently drop it from those counts.
  if (!$text_len) {
    $node->set_rendered('', 'text/html');
    return;
  }

  # Feed the parser characters where the charset lets us decode them, and tell
  # it which it is getting: HTML::Parser handles either, but its utf8_mode (and
  # our own NBSP and word-boundary handling) has to match the actual input.
  my ($text, $character_semantics) = $node->decode_and_normalize();
  return  if !defined $text || $text eq '';

  # the 1 requires decoded HTML results to be in characters (utf8 flag on)
  my $html = Mail::SpamAssassin::HTML->new($character_semantics, 1); # object

  $html->parse($text);  # parse+render text

  # resulting HTML-decoded text is in perl characters (utf8 flag on)
  my $rendered = $html->get_rendered_text();
  my $results  = $html->get_results();

  # end-of-document result values that require looking at the text

  # count the number of spaces in the rendered text
  my $space;
  if (utf8::is_utf8($rendered)) {
    my $str = $rendered;
    $str =~ s/\S+//g;  # delete non-whitespace Unicode characters
    $space = length $str;  # count remaining Unicode space characters
    undef $str;  # deallocate storage
    dbg("message: spaces (Unicode) in HTML: %d out of %d%s",
        $space, length $rendered,
        $character_semantics ? '' : ', octets!?');
  } else {
    my $str = $rendered;
    $space = $str =~ tr/ \t\n\r\x0b//;
    dbg("message: spaces (octets) in HTML: %d out of %d%s",
        $space, length $rendered,
        $character_semantics ? ', chars!?' : '');
  }
  # we may want to add the count of other Unicode whitespace characters

  $results->{html_length} = length $rendered;  # perl characters count
  $results->{non_space_len} = $results->{html_length} - $space;
  $results->{ratio} = ($text_len - $results->{html_length}) / $text_len;

  $node->{html_results} = $results;
  # Pass the type explicitly: an HTML part renders as text/html whatever its
  # declared type was, and Message::get_body_text_array_common keys the
  # {metadata}{html} bookkeeping off that.
  $node->set_rendered($rendered, 'text/html',
                      $html->get_rendered_text(invisible => 1),
                      $html->get_rendered_text(invisible => 0));
}

1;
