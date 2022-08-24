#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_headers");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (
  qr/^Message-Id: <78w08\.t365th3y6x7h\@yahoo\.com>/m => 'msgid',
  qr/^X-Spam-Status: Yes/m => 'xss',
  'TEST_NOREALNAME', 'noreal',
  'subscription cancelable at anytime' => 'body',
);

%anti_patterns = (
);

start_spamd("-L --cf='report_safe 0'");
ok (spamcrun ("--headers < data/spam/009", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

