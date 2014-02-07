#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_sslv3");
use Test; plan tests => (($SKIP_SPAMD_TESTS || !$SSL_AVAILABLE) ? 0 : 9);

exit if ($SKIP_SPAMD_TESTS || !$SSL_AVAILABLE);

# ---------------------------------------------------------------------------

%patterns = (

q{ Return-Path: sb55sb55@yahoo.com}, 'firstline',
q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',
q{ This must be the very last line}, 'lastline',


);

ok (sdrun ("-L --ssl --ssl-version=sslv3 --server-key data/etc/testhost.key --server-cert data/etc/testhost.cert",
           "--ssl=sslv3 < data/spam/001",
           \&patterns_run_cb));
ok_all_patterns();
