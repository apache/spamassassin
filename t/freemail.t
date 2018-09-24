#!/usr/bin/perl

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

plan tests => 2;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::FreeMail
");

%patterns = (
        q{ FREEMAIL_FROM },
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
