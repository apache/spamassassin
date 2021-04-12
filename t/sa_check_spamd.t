#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("sa_check_spamd");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 7;

# ---------------------------------------------------------------------------

%patterns = (
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
);

ok(start_spamd("-L"));

ok(spamcrun("< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

my $p = $spamdport;
sacheckspamdrun("--hostname $spamdhost --port $p --verbose");
ok (($? >> 8) == 0);

ok(stop_spamd());

sacheckspamdrun("--hostname $spamdhost --port $p --verbose");
ok (($? >> 8) != 0);

