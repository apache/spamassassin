#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("lang_pl_tests");
use Test; BEGIN { plan tests => 14 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Analiza zawarto¶ci: }, 'report',

);

$ENV{'LANG'} = 'pl';
sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
