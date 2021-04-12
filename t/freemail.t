#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("freemail");

use Test::More;

plan tests => 4;

# ---------------------------------------------------------------------------

tstprefs ("
  freemail_domains gmail.com
  freemail_import_whitelist_auth 0
  whitelist_auth test\@gmail.com
  header FREEMAIL_FROM eval:check_freemail_from()
");

%patterns = (
  q{ FREEMAIL_FROM }, 'FREEMAIL_FROM',
);

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

## Now test with freemail_import_whitelist_auth, should not hit

%patterns = ();
%anti_patterns = (
  q{ FREEMAIL_FROM }, 'FREEMAIL_FROM',
);

tstprefs ("
  freemail_domains gmail.com
  freemail_import_whitelist_auth 1
  whitelist_auth test\@gmail.com
  header FREEMAIL_FROM eval:check_freemail_from()
");

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();

