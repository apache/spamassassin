#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Listed in Razor }, 'spam',

);

sarun ("-t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();
%anti_patterns = (

q{ Listed in Razor }, 'nonspam',

);

sarun ("-t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
