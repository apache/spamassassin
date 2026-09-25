#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_javascript_utf16");

use Test::More;

# ---------------------------------------------------------------------------
# UTF-16 -> UTF-8 normalization of a .js extracted from an archive.
#
# A .js file extracted from an archive is handed to the JavaScript handler as a
# synthetic child part carrying its raw bytes.  When those bytes are UTF-16 (a
# common malware trick -- a .js dropped inside a rar/zip), the handler must see
# UTF-8 so 'script' regexes can match; otherwise every ASCII character is
# interleaved with a NUL byte and no rule fires.
#
# The JavaScript handler reads the part with decode_and_normalize(), which
# detects undeclared UTF-16 (BOM'd or BOM-less) and transcodes it.  It is gated
# on normalize_charset (default on); with it off, the raw bytes are left
# untouched and the rule must NOT fire.
#
# The fixtures embed a real .zip (pure-Perl extraction), so this runs everywhere
# without any external binary.  Each zip holds inner.js (a UTF-16 script whose
# body contains UTF16JSSENTINEL) and inner.html (INNERHTML).
# ---------------------------------------------------------------------------

plan tests => 7;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Archive
  loadhandler Mail::SpamAssassin::Handler::HTML
  loadhandler Mail::SpamAssassin::Handler::JavaScript
");

tstlocalrules ('
  script JS_UTF16       /UTF16JSSENTINEL/
  score  JS_UTF16       1.0
  describe JS_UTF16     a UTF-16 inner .js was normalized to UTF-8 and matched

  body   ARC_ORIG       /ORIGINAL_BODY_MARKER/
  score  ARC_ORIG       1.0
  describe ARC_ORIG     original outer body preserved
');

# --- BOM UTF-16LE inner.js --------------------------------------------------
%patterns = (
  ' 1.0 JS_UTF16 ', 'utf16le_bom_js_normalized',
  ' 1.0 ARC_ORIG ', 'bom_original_body_preserved',
);
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_archive_utf16_bom", \&patterns_run_cb));
ok_all_patterns();

# --- BOM-less UTF-16BE inner.js (endianness sniffed via detect_utf16) -------
%patterns = (
  ' 1.0 JS_UTF16 ', 'utf16be_nobom_js_normalized',
);
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_archive_utf16_nobom", \&patterns_run_cb));
ok_all_patterns();

# --- normalize_charset 0 disables the transcode -----------------------------
# With charset normalization off, the synthetic .js keeps its raw UTF-16 bytes,
# so the 'script' rule must NOT match (mirrors rendered()'s own gate).
%patterns = ();
%anti_patterns = (
  ' JS_UTF16 ', 'utf16_not_normalized_when_off',
);
ok (sarun ("-L -t --cf='normalize_charset 0' < data/nice/handler_archive_utf16_bom",
           \&patterns_run_cb));
ok_all_patterns();
