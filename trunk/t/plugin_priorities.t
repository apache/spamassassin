#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("plugin_priorities");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ META2_FOUND } => '',

);

%anti_patterns = ();

tstlocalrules ("
        loadplugin myTestPlugin ../../data/testplugin.pm
        loadplugin myTestPlugin2 ../../data/testplugin2.pm
        header META2_FOUND       Plugin-Meta-Test2 =~ /bar2/

");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

