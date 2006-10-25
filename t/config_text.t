#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("config_text");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ FOO } => 'FOO',
q{ BAR } => 'BAR',

);

sarun ("-L -t ".
    "--cf='body FOO /VFS/' ".
    "--cf='body BAR /source/' ".
    "< data/nice/001", \&patterns_run_cb);

ok_all_patterns();

