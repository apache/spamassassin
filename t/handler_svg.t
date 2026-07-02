#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_svg");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::SVG.
#
# handler_svg attaches an image/svg+xml part that is really a text/link canvas
# (no graphics elements) carrying a docusign phishing lure and an embedded
# <script>.  We confirm:
#   * svgtext rules match the SVG text (and only the SVG, not HTML);
#   * check_svg_text_ratio() fires (text words but no graphics elements);
#   * the embedded <script> is surfaced as a text/javascript sub-part and the
#     JavaScript handler's script rules match it.
#
# The handler is pure Perl (no external binary), so this test runs everywhere.

plan tests => 7;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::SVG
  loadhandler Mail::SpamAssassin::Handler::JavaScript
");

tstlocalrules ('
  svgtext SVG_SENTINEL    /SVGSENTINEL/
  score   SVG_SENTINEL    1.0
  describe SVG_SENTINEL   SVG text reached the SVG handler

  svgtext SVG_SUSP        /\b(docusign|secure link)\b/i
  score   SVG_SUSP        1.0
  describe SVG_SUSP       suspicious phishing terms in SVG text

  body    SVG_TEXT_HEAVY  eval:check_svg_text_ratio()
  score   SVG_TEXT_HEAVY  1.0
  describe SVG_TEXT_HEAVY  SVG text-word to graphics-element ratio is high

  script  SVG_SCRIPT      /SVGSCRIPT/
  score   SVG_SCRIPT      1.0
  describe SVG_SCRIPT     embedded SVG script reached the JavaScript handler

  uri-detail SVG_LINK     type =~ /^svg$/  raw =~ /phish\.example/
  score   SVG_LINK        1.0
  describe SVG_LINK       an <a href> link inside the SVG reached the URI list

  body    SVG_ORIG        /ORIGINAL_BODY_MARKER/
  score   SVG_ORIG        1.0
  describe SVG_ORIG       original body preserved
');

%patterns = (
  ' 1.0 SVG_SENTINEL ', 'svg_text',
  ' 1.0 SVG_SUSP ',     'svg_suspicious_text',
  ' 1.0 SVG_TEXT_HEAVY ', 'svg_text_ratio',
  ' 1.0 SVG_SCRIPT ',   'svg_script_to_js_handler',
  ' 1.0 SVG_LINK ',     'svg_uri_detail',
  ' 1.0 SVG_ORIG ',     'original_body_preserved',
);

ok (sarun ("-L -t < data/nice/handler_svg", \&patterns_run_cb));
ok_all_patterns();
