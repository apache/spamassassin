#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("nonspam");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

  q{ X-Spam-Status: No, }, 'nonspam'

);

ok (sarun ("-t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
