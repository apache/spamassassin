#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (
q{ EXCUSE_13 } => 'EXCUSE_13',
q{ HERBAL_VIAGRA } => 'HERBAL_VIAGRA',
q{ GUARANTEE } => 'GUARANTEE',
q{ ALL_NATURAL } => 'ALL_NATURAL',
q{ PENNIES_A_DAY } => 'PENNIES_A_DAY',
);

%anti_patterns = (
q{ OPPORTUNITY } => 'OPPORTUNITY',
);

sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();
