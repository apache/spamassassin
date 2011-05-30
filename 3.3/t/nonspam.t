#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("nonspam");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

  q{ X-Spam-Status: No, }, 'nonspam'

);

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
