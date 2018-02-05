#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_headers");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (

  q{ Message-Id: <78w08.t365th3y6x7h@yahoo.com> } => 'msgid',
  q{ X-Spam-Status: Yes, } => 'xss',
  q{ TEST_NOREALNAME}, 'noreal',
  q{ subscription cancelable at anytime } => 'body',

);

%anti_patterns = (

);

start_spamd("-L --cf='report_safe 0'");
ok (spamcrun ("--headers < data/spam/009", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

