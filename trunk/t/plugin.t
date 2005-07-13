#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("plugin");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (

q{ GTUBE }, 'gtube',
q{ MY_TEST_PLUGIN }, 'plugin_called',
q{ registered Mail::SpamAssassin::Plugin::Test }, 'registered',
q{ Mail::SpamAssassin::Plugin::Test eval test called }, 'test_called',

);

%anti_patterns = (

q{ SHOULD_NOT_BE_CALLED }, 'should_not_be_called'

);

tstlocalrules ("
	loadplugin     Mail::SpamAssassin::Plugin::Test
	ifplugin FooPlugin
	  header SHOULD_NOT_BE_CALLED	eval:doesnt_exist()
	endif
	if plugin(Mail::SpamAssassin::Plugin::Test)
	  header MY_TEST_PLUGIN		eval:check_test_plugin()
	endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

