#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_port");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: *****SPAM***** There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

ok(sdrun ("-L -p 18972", "-p 18972 < data/spam/001", \&patterns_run_cb));
ok_all_patterns();


