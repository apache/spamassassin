#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

q{  }, 'anything',

);

sarun ("-L --lint", \&patterns_run_cb);
ok_all_patterns();
