#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("local_tests_only");

use Test::More;
plan tests => 1;

# ---------------------------------------------------------------------------

# Make sure no plugin is sending DNS with -L

%anti_patterns = (
 'dns: bgsend' => 'dns',
);

tstprefs("
  header DNSBL_TEST_TOP eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
  tflags DNSBL_TEST_TOP net
");

# we need -D output for patterns
sarun ("-D -L -t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

