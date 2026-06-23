#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler");

use Test::More tests => 5;

# ---------------------------------------------------------------------------
# Exercise the MIME-part handler framework end-to-end:
#   - a plugin registers handle_text for text/plain, which injects
#     HANDLER_SENTINEL_A into the body (proves set_rendered text reaches body
#     rules through the renderer),
#   - it emits a synthetic application/x-sa-test child, dispatched to a second
#     registered method handle_child which injects HANDLER_SENTINEL_B (proves
#     child-part dispatch / chaining / recursion AND per-method registration),
#   - it sets a per-message flag on $pms that the plugin's eval rule reads
#     (proves a plugin can be both a handler and an eval-rule provider).

tstpre ('
  loadplugin myTestHandler ../../../data/testhandler.pm
');

tstlocalrules ('
  body HANDLER_A        /HANDLER_SENTINEL_A/
  score HANDLER_A       1.0
  describe HANDLER_A    handler-injected text reached body rules

  body HANDLER_B        /HANDLER_SENTINEL_B/
  score HANDLER_B       1.0
  describe HANDLER_B    chained handler-injected text reached body rules

  body HANDLER_ORIG     /ORIGINAL_BODY_MARKER/
  score HANDLER_ORIG    1.0
  describe HANDLER_ORIG original body text is preserved

  header HANDLER_EVAL   eval:check_test_handler()
  score HANDLER_EVAL    1.0
  describe HANDLER_EVAL handler-owned eval rule fired
');

%patterns = (
  ' 1.0 HANDLER_A ',     'text_injected',
  ' 1.0 HANDLER_B ',     'chained_child_injected',
  ' 1.0 HANDLER_ORIG ',  'original_body_preserved',
  ' 1.0 HANDLER_EVAL ',  'handler_eval_rule',
);

ok (sarun ("-L -t < data/nice/handler_textplain", \&patterns_run_cb));
ok_all_patterns();
