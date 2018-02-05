#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_B");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 9;

# ---------------------------------------------------------------------------

%patterns = (
  q{HELO example.com},
    'helo',
  q{MAIL FROM:<pertand@email.mondolink.com>},
    'mailfrom',
  q{RCPT TO:<somebody@example.com>},
    'rcptto',
  q{DATA},
    'data',
  q{X-Spam-Flag: YES},
    'spamflag',
  q{KIFF},
    'status',
  q{QUIT},
    'quit'
);

start_spamd("-L");
ok (spamcrun ("-B < data/spam/bsmtpnull", \&patterns_run_cb));
ok (spamcrun ("-B < data/spam/bsmtp", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

