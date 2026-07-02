#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_javascript");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::JavaScript.
#
#  * handler_javascript            - an inline text/html BODY whose <script> tag,
#                                    javascript: URI and onerror= handler carry
#                                    sentinels.  Body script is inert in MUAs, so
#                                    the HTML handler does NOT surface it to the
#                                    JavaScript handler: none of the script rules
#                                    fire, only the rendered body text survives.
#
#  * handler_javascript_attach     - a *.js file attached as application/octet-
#                                    stream.  The js->text/javascript file-type
#                                    mapping routes it straight to the JavaScript
#                                    handler, so script rules DO fire.
#
#  * handler_javascript_html_attach - a text/html ATTACHMENT (Content-Disposition:
#                                    attachment) whose <script> carries a sentinel
#                                    and an overlong token.  Attachment HTML is
#                                    scrutinised, so script rules DO fire.
#
# The handler is pure Perl (no external binary), so this test runs everywhere.

plan tests => 13;

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::HTML
  loadhandler Mail::SpamAssassin::Handler::JavaScript
");

tstlocalrules ('
  script JS_SENTINEL      /JSSENTINEL/
  score  JS_SENTINEL      1.0
  describe JS_SENTINEL    script tag text reached the JavaScript handler

  script JS_URI           /JSURI_SENTINEL/
  score  JS_URI           1.0
  describe JS_URI         javascript: URI reached the JavaScript handler

  script JS_ONERROR       /onErrorSentinel/
  score  JS_ONERROR       1.0
  describe JS_ONERROR     event-handler attribute reached the JavaScript handler

  script JS_ATOB          /\b(atob|eval)\(/
  score  JS_ATOB          1.0
  describe JS_ATOB        obfuscation function call seen in script

  script JS_HAS_RECIP     eval:check_script_contains_recip_addr()
  score  JS_HAS_RECIP     1.0
  describe JS_HAS_RECIP   recipient address appears in script

  body   JS_ORIG          /ORIGINAL_BODY_MARKER/
  score  JS_ORIG          1.0
  describe JS_ORIG        original body preserved

  uri-detail JS_REDIRECT  type =~ /^script$/  raw =~ /redirect\.example/
  score  JS_REDIRECT      1.0
  describe JS_REDIRECT    a window.location redirect URL reached the URI list
');

# --- inline HTML body: script is inert, so it must NOT reach the JS handler ---
# The body <script>, javascript: URI and onerror= handler all carry sentinels and
# an overlong token, but body script is dropped by the HTML handler, so none of
# the script rules (nor the token-length rule) may fire.  Only the rendered body
# text (JS_ORIG) survives.
%patterns = (
  ' 1.0 JS_ORIG ',      'original_body_preserved',
);
%anti_patterns = (
  ' JS_SENTINEL ',      'body_script_not_collected',
  ' JS_URI ',           'body_uri_not_collected',
  ' JS_ONERROR ',       'body_onerror_not_collected',
  ' JS_ATOB ',          'body_atob_not_collected',
  ' JS_HAS_RECIP ',     'body_email_not_collected',
);
ok (sarun ("-L -t < data/nice/handler_javascript", \&patterns_run_cb));
ok_all_patterns();

# --- attached *.js (application/octet-stream named payload.js) ---------------
%anti_patterns = ();
%patterns = (
  ' 1.0 JS_SENTINEL ',  'js_attach_script',
  ' 1.0 JS_ATOB ',      'js_attach_eval',
  ' 1.0 JS_REDIRECT ',  'js_redirect_uri',
);
ok (sarun ("-L -t < data/nice/handler_javascript_attach", \&patterns_run_cb));
ok_all_patterns();

# --- text/html ATTACHMENT: its script IS scrutinised ------------------------
# Same drop-the-body logic must NOT apply when the HTML is an attachment, so the
# attached page's <script> reaches the JS handler: sentinel and overlong token
# both fire.
%anti_patterns = ();
%patterns = (
  ' 1.0 JS_SENTINEL ',  'html_attach_script',
);
ok (sarun ("-L -t < data/nice/handler_javascript_html_attach", \&patterns_run_cb));
ok_all_patterns();
