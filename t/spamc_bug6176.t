#!/usr/bin/perl
#
# bug 6176 comment 14: regression test

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_bug6176");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (

q{ TO GET THE EVOLUTION PREVIEW RELEASE }, 'evolution',

);

# connect on port 9 (discard): should always fail.
# fake "username" is used so that the SATest.pm code which adds -F
# is inhibited, to trigger the bug.
ok (scrun ("-p 9 --username=ignore_-F_switch < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

