#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 8 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ FROM_ENDS_IN_NUMS }, 'endsinnums',
q{ NO_REAL_NAME }, 'noreal',
q{ REMOVE_SUBJ }, 'removesubject',


);

ok (sarun ("-L -t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
