#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("plugin");
use Test::More tests => 6;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1000 GTUBE }, 'gtube',
  q{ 1.0 MY_TEST_PLUGIN }, 'plugin_called',
  'registered Mail::SpamAssassin::Plugin::Test', 'registered',
  'Mail::SpamAssassin::Plugin::Test eval test called', 'test_called',
);

%anti_patterns = (
  'SHOULD_NOT_BE_CALLED', '',
);

tstlocalrules ("
  loadplugin Mail::SpamAssassin::Plugin::Test
  ifplugin FooPlugin
    header SHOULD_NOT_BE_CALLED eval:doesnt_exist()
  endif
  if plugin(Mail::SpamAssassin::Plugin::Test)
    header MY_TEST_PLUGIN eval:check_test_plugin()
  endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

