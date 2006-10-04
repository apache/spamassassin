#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("utf8");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: ****}, 'stars',

);

ok (sarun ("-L -t < data/spam/009", \&patterns_run_cb));
ok_all_patterns();
