#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_maxsize");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE! }, 'subj',

);

sdrun ("-L", "-s 512 < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

