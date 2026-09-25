#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_decode_normalize");

use Test::More;

# ---------------------------------------------------------------------------
# Text handlers (HTML, JavaScript, SVG, ICS) read their part with
# decode_and_normalize(), so they see UTF-8 whatever the part's charset, and
# whether it is a real MIME part or a synthetic one.
#
#   - a UTF-16LE .js attached directly (no BOM, no charset) is detected as
#     UTF-16 and transcoded; with normalize_charset 0 it is left alone
#   - <script> in an HTML attachment, which the HTML handler parses as perl
#     characters, is passed on to the JavaScript handler as UTF-8 bytes
#   - SVG text declared windows-1251 is transcoded to UTF-8
#   - SVG text declared UTF-8, with a numeric entity, is UTF-8 with
#     normalize_charset on or off (declared UTF-8 is decoded even when off)
#   - with normalize_charset 0, a numeric entity in plain-ASCII SVG decodes to
#     UTF-8 bytes rather than perl characters
#   - an ICS part declared windows-1251 is transcoded to UTF-8
# ---------------------------------------------------------------------------

plan tests => 17;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::HTML
  loadhandler Mail::SpamAssassin::Handler::JavaScript
  loadhandler Mail::SpamAssassin::Handler::SVG
  loadhandler Mail::SpamAssassin::Handler::ICS
");

tstlocalrules ('
  script  JS_UTF16_ATTACH  /UTF16ATTACHSENTINEL/
  score   JS_UTF16_ATTACH  1.0

  script  HTML_JS_UTF8     /HTMLJS caf\xc3\xa9/
  score   HTML_JS_UTF8     1.0

  svgtext SVG_UTF8         /SVGTEXT caf\xc3\xa9 \xe4\xb8\xad/
  score   SVG_UTF8         1.0

  svgtext SVG_ENTITY       /SVGENTITY \xe4\xb8\xad/
  score   SVG_ENTITY       1.0

  svgtext SVG_CP1251_UTF8  /SVGTEXT \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82/
  score   SVG_CP1251_UTF8  1.0

  svgtext SVG_CP1251_RAW   /SVGTEXT \xcf\xf0\xe8\xe2\xe5\xf2/
  score   SVG_CP1251_RAW   1.0

  icstext ICS_CP1251       /ICSTEXT \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82/
  score   ICS_CP1251       1.0
');

# --- UTF-16LE .js attachment -----------------------------------------------
%patterns = ( ' 1.0 JS_UTF16_ATTACH ', 'utf16_attachment_normalized' );
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_javascript_utf16_attach", \&patterns_run_cb));
ok_all_patterns();

%patterns = ();
%anti_patterns = ( ' JS_UTF16_ATTACH ', 'utf16_attachment_not_normalized_when_off' );
ok (sarun ("-L -t --cf='normalize_charset 0' < data/nice/handler_javascript_utf16_attach",
           \&patterns_run_cb));
ok_all_patterns();

# --- <script> in an HTML attachment -----------------------------------------
%patterns = ( ' 1.0 HTML_JS_UTF8 ', 'html_script_is_utf8_bytes' );
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_javascript_html_utf8", \&patterns_run_cb));
ok_all_patterns();

# --- SVG declared windows-1251 ---------------------------------------------
%patterns = ( ' 1.0 SVG_CP1251_UTF8 ', 'svg_cp1251_transcoded' );
%anti_patterns = ( ' SVG_CP1251_RAW ', 'svg_cp1251_not_raw' );
ok (sarun ("-L -t < data/nice/handler_svg_cp1251", \&patterns_run_cb));
ok_all_patterns();

# --- SVG declared UTF-8, normalize_charset on and off -----------------------
# Declared UTF-8 is decoded to characters even with normalize_charset 0, so
# both cases take the character path.
%patterns = ( ' 1.0 SVG_UTF8 ', 'svg_text_utf8' );
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_svg_utf8", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( ' 1.0 SVG_UTF8 ', 'svg_text_utf8_when_off' );
%anti_patterns = ();
ok (sarun ("-L -t --cf='normalize_charset 0' < data/nice/handler_svg_utf8",
           \&patterns_run_cb));
ok_all_patterns();

# --- entity in plain-ASCII SVG, normalize_charset 0 -------------------------
# Byte input: the handler sets utf8_mode so &#x4e2d; decodes to UTF-8 bytes.
%patterns = ( ' 1.0 SVG_ENTITY ', 'svg_entity_utf8_when_off' );
%anti_patterns = ();
ok (sarun ("-L -t --cf='normalize_charset 0' < data/nice/handler_svg_entity",
           \&patterns_run_cb));
ok_all_patterns();

# --- ICS declared windows-1251 ----------------------------------------------
%patterns = ( ' 1.0 ICS_CP1251 ', 'ics_cp1251_transcoded' );
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_ics_cp1251", \&patterns_run_cb));
ok_all_patterns();
