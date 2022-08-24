#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");
use Test::More tests => 9;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 MILLION_EMAIL } => '',
  q{ 1.0 GUARANTEE } => '',
  q{ 1.0 NATURAL } => '',
  q{ 1.0 OUR_AFFILIATE_PARTNERS } => '',
  q{ 1.0 VIAGRA } => '',
);

%anti_patterns = (
  q{ OPPORTUNITY } => '',
  q{ BUG5749_P_H2 } => '',
  q{ BUG5749_H2_H3 } => '',
  q{ BUG6168_EXAMPLE } => '',
);

tstlocalrules ('
  body NATURAL		/\b(?:100.|completely|totally|all) natural/i
  body GUARANTEE	/\bGUARANTEE\b/
  body MILLION_EMAIL	/million (?:\w+ )?(?:e-?mail )?addresses/i
  body OUR_AFFILIATE_PARTNERS	/our affiliate partners/i
  body VIAGRA		/viagra/i
  body OPPORTUNITY	/OPPORTUNITY/

  body BUG5749_P_H2	/foobar/
  body BUG5749_H2_H3	/foobaz/
  body BUG6168_EXAMPLE	/example.orgexample.net/
');

sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();

