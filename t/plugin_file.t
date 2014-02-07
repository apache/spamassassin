#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("plugin_file");
use Test; BEGIN { plan tests => 9 };

# ---------------------------------------------------------------------------

%patterns = (

q{ GTUBE }, 'gtube',
q{ MY_TEST_PLUGIN }, 'plugin_called',
q{ registered myTestPlugin }, 'registered',
q{ myTestPlugin eval test called }, 'test_called',
q{ myTestPlugin finishing }, 'plugin_finished',

q{ test: plugins loaded: Mail::SpamAssassin::Plugin::AWL=HASH }, 'plugins_loaded',
q{ myTestPlugin=HASH }, 'plugins_loaded2',

);

%anti_patterns = (

q{ SHOULD_NOT_BE_CALLED }, 'should_not_be_called'

);

tstlocalrules ("
	loadplugin myTestPlugin ../../data/testplugin.pm
	ifplugin FooPlugin
	  header SHOULD_NOT_BE_CALLED	eval:doesnt_exist()
	endif
	if plugin(myTestPlugin)
	  header MY_TEST_PLUGIN		eval:check_test_plugin()
	endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

