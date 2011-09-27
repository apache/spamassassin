#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("sa-check_spamd");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 7) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',

);

ok(start_spamd("-L"));

ok(spamcrun("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

my $p = $spamdport;
system("../sa-check_spamd --hostname $spamdhost --port $p --verbose");
ok (($? >> 8) == 0);

ok(stop_spamd());

system("../sa-check_spamd --hostname $spamdhost --port $p --verbose");
ok (($? >> 8) != 0);
