#!/usr/bin/perl -T

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

use lib '.'; use lib 't';
use SATest; sa_t_init("freemail");

use Test::More;

plan tests => 4;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::FreeMail
");

tstprefs ("
        header FREEMAIL_FROM eval:check_freemail_from()
        freemail_domains gmail.com
        freemail_import_whitelist_auth 0
        whitelist_auth test\@gmail.com
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
        header FREEMAIL_FROM eval:check_freemail_from()
        freemail_domains gmail.com
        freemail_import_whitelist_auth 1
        whitelist_auth test\@gmail.com
");

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
