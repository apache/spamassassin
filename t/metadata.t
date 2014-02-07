#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("metadata");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ GTUBE }, 'gtube',
q{ META_FOUND }, 'META_FOUND',

);

tstlocalrules ("
        loadplugin myTestPlugin ../../data/testplugin.pm
        header META_FOUND	Plugin-Meta-Test =~ /bar/
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

