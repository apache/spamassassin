#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("get_all_headers");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ MIME-Version: 1.0 }, 'no-extra-space',

);

%anti_patterns = (

q{/MIME-Version:  1\.0/}, 'extra-space'

);

tstlocalrules ("
	loadplugin Dumpheaders ../../data/Dumpheaders.pm
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

