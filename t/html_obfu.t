#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (
q{ MILLION_EMAIL } => 'MILLION_EMAIL',
q{ GUARANTEE } => 'GUARANTEE',
q{ ALL_NATURAL } => 'ALL_NATURAL',
q{ OUR_AFFILIATE_PARTNERS } => 'OUR_AFFILIATE_PARTNERS',
q{ VIAGRA } => 'VIAGRA',
);

%anti_patterns = (
q{ OPPORTUNITY } => 'OPPORTUNITY',
);

tstlocalrules ("
        score OUR_AFFILIATE_PARTNERS 1
");
sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();
