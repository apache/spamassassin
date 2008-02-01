#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_maxsize");

# TODO JMD remove once DB_File bug is fixed
use Test; BEGIN { plan tests => 0 }; exit; # ($SKIP_SPAMD_TESTS ? 0 : 1) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE! }, 'subj',

);

sdrun ("-L", "-s 512 < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

