#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_maxsize");

# this test was disabled, probably due to Bug 5731; re-enabling it for SA 3.4.0
# (was: TODO JMD remove once DB_File bug is fixed)
use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 1;

# ---------------------------------------------------------------------------
# test for size limit issues like in Bug 5412

%patterns = (

q{ Subject: There yours for FREE! }, 'subj',

);

sdrun ("-L", "-s 512 < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

