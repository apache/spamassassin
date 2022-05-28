#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("plugin_file");
use Test::More tests => 9;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1000 GTUBE },		'gtube',
  q{ 1.0 MY_TEST_PLUGIN },	'plugin_called',
  'registered myTestPlugin',	'registered',
  'myTestPlugin eval test called', 'test_called',
  'myTestPlugin finishing',	'plugin_finished',
  'test: plugins loaded: Mail::SpamAssassin::Plugin::ASN=HASH', 'plugins_loaded',
  'myTestPlugin=HASH',		'plugins_loaded2',
);

%anti_patterns = (
  'SHOULD_NOT_BE_CALLED', 'should_not_be_called'
);

tstlocalrules ("
  loadplugin myTestPlugin ../../../data/testplugin.pm
  ifplugin FooPlugin
    header SHOULD_NOT_BE_CALLED eval:doesnt_exist()
  endif
  if plugin(myTestPlugin)
    header MY_TEST_PLUGIN  eval:check_test_plugin()
  endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

