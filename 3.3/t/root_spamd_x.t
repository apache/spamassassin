#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_x");
use Test;

use constant TEST_ENABLED => conf_bool('run_root_tests');
use constant IS_ROOT => eval { ($> == 0); };
use constant RUN_TESTS => (TEST_ENABLED && IS_ROOT);

BEGIN { plan tests => (RUN_TESTS ? 14 : 0) };
exit unless RUN_TESTS;

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

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

ok(start_spamd("-L --create-prefs -x"));

ok(spamcrun("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
             );


ok (spamcrun("< data/spam/018", \&patterns_run_cb));
ok_all_patterns();

ok(stop_spamd());
