#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report_ifspam");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 10) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ TEST_INVALID_DATE}, 'date',
q{ TEST_ENDSNUMS}, 'endsinnums',
q{ TEST_NOREALNAME}, 'noreal',

);

%patterns = %is_spam_patterns;
ok (start_spamd ("-L"));
ok (spamcrun ("-r < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ();
%anti_patterns = %is_spam_patterns;
ok (spamcrun ("-r < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

ok (stop_spamd());

