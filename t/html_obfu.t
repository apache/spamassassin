#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (
q{ MILLION_EMAIL } => 'MILLION_EMAIL',
q{ GUARANTEE } => 'GUARANTEE',
q{ NATURAL } => 'NATURAL',
q{ OUR_AFFILIATE_PARTNERS } => 'OUR_AFFILIATE_PARTNERS',
q{ VIAGRA } => 'VIAGRA',
);

%anti_patterns = (
q{ OPPORTUNITY } => 'OPPORTUNITY',
);

tstlocalrules ('
body NATURAL	/\b(?:100.|completely|totally|all) natural/i
body GUARANTEE	/\bGUARANTEE\b/
body MILLION_EMAIL	/million (?:\w+ )?(?:e-?mail )?addresses/i
body OUR_AFFILIATE_PARTNERS	/our affiliate partners/i
body VIAGRA	/viagra/i
body OPPORTUNITY	/OPPORTUNITY/
');
sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();
