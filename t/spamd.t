#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 9) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Return-Path: sb55sb55@yahoo.com}, 'firstline',
q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',
q{ This must be the very last line}, 'lastline',


);

ok (sdrun ("-L", "< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

