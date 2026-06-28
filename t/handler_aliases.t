#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_aliases");
use Test::More tests => 4;

# ---------------------------------------------------------------------------
# loadhandler / tryhandler / ifhandler are aliases for loadplugin / tryplugin /
# ifplugin.  A MIME-part handler is an ordinary plugin, so the aliases just give
# handler configuration its own vocabulary while behaving identically.  We reuse
# the generic test plugin (data/testplugin.pm) to prove that:
#   * loadhandler loads the module and its eval rule runs (MY_TEST_HANDLER);
#   * ifhandler <loaded>  enters the block;
#   * ifhandler <missing> skips the block (SHOULD_NOT_BE_CALLED never defined);
#   * tryhandler <missing> is silently ignored (no fatal error -> lint/run works).

%patterns = (
  q{ 1.0 MY_TEST_HANDLER },          'handler_eval_called',
  'registered myTestPlugin',         'registered',
);

%anti_patterns = (
  'SHOULD_NOT_BE_CALLED',            'ifhandler_missing_skipped',
);

tstlocalrules ("
  loadhandler myTestPlugin ../../../data/testplugin.pm
  tryhandler  NoSuchHandlerModuleXYZ
  ifhandler FooHandlerNotLoaded
    header SHOULD_NOT_BE_CALLED eval:doesnt_exist()
  endif
  ifhandler myTestPlugin
    header MY_TEST_HANDLER  eval:check_test_plugin()
  endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();
