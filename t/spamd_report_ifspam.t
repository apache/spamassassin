#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_report_ifspam");
use Test; BEGIN { plan tests => (!$SKIP_SPAMD_TESTS? 10 : 0) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%is_spam_patterns = (

q{ INVALID_DATE}, 'date',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',

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

