#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ hello world }, 'spamc',

);

ok (scrun ("-p 0 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

