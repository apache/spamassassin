#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_from");

use constant TEST_ENABLED => conf_bool('run_long_tests');

use Test;
BEGIN { plan tests => TEST_ENABLED ? 32 : 0 };
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

tstprefs ("
        def_whitelist_from_rcvd *\@paypal.com paypal.com
        def_whitelist_from_rcvd *\@paypal.com ebay.com
        def_whitelist_from_rcvd mumble\@example.com example.com
        whitelist_from_rcvd foo\@example.com spamassassin.org
        whitelist_from_rcvd foo\@example.com example.com
        whitelist_from_rcvd bar\@example.com example.com
        whitelist_allows_relays bar\@example.com
        whitelist_from baz\@example.com
        whitelist_from bam\@example.com
        unwhitelist_from bam\@example.com
        unwhitelist_from_rcvd mumble\@example.com
	");

# tests 1 - 4 does whitelist_from work?
%patterns = (
             q{ USER_IN_WHITELIST }, 'w1'
             );

%anti_patterns = (
             q{ FORGED_IN_WHITELIST }, 'a2',
             q{ USER_IN_DEF_WHITELIST }, 'a3',
             q{ FORGED_IN_DEF_WHITELIST }, 'a4'
             );
sarun ("-L -t < data/nice/008", \&patterns_run_cb);
ok_all_patterns();

# tests 5 - 8 does whitelist_from_rcvd work?
sarun ("-L -t < data/nice/009", \&patterns_run_cb);
ok_all_patterns();

# tests 9 - 12 second relay specified for same addr in whitelist_from_rcvd
sarun ("-L -t < data/nice/010", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
             q{ USER_IN_DEF_WHITELIST }, 'w5'
             );

%anti_patterns = (
             q{ USER_IN_WHITELIST }, 'a6',
             q{ FORGED_IN_WHITELIST }, 'a7',
             q{ FORGED_IN_DEF_WHITELIST }, 'a8'
             );

# tests 13 - 16 does def_whitelist_from_rcvd work?
sarun ("-L -t < data/nice/011", \&patterns_run_cb);
ok_all_patterns();

# tests 17 - 20 second relay specified for same addr in def_whitelist_from_rcvd
sarun ("-L -t < data/nice/012", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();

%anti_patterns = (
             q{ USER_IN_WHITELIST }, 'a9',
             q{ FORGED_IN_WHITELIST }, 'a10',
             q{ USER_IN_DEF_WHITELIST }, 'a11',
             q{ FORGED_IN_DEF_WHITELIST }, 'a12'
             );
# tests 21 - 24 does whitelist_allows_relays suppress the forged rule without
#  putting the address on the whitelist?
sarun ("-L -t < data/nice/013", \&patterns_run_cb);
ok_all_patterns();

# tests 25 - 28 does unwhitelist_from work?
sarun ("-L -t < data/nice/014", \&patterns_run_cb);
ok_all_patterns();

# tests 29 - 32 does unwhitelist_from_rcvd work?
sarun ("-L -t < data/nice/015", \&patterns_run_cb);
ok_all_patterns();

