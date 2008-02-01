#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_maxsize");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 1) };

exit if $SKIP_SPAMD_TESTS;
exit if (-f "/home/jm/capture_spamd_straces");  # TODO JMD remove once DB_File bug is fixed

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE! }, 'subj',

);

sdrun ("-L", "-s 512 < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

