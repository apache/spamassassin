#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_unix");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

start_spamd("-L --socketpath=log/spamd.sock");
ok (spamcrun ("-U log/spamd.sock < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

