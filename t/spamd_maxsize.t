#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_maxsize");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE! }, 'subj',

);

ok (sdrun ("", "-s 512 < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

