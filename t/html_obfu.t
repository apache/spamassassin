#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("html_obfu");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (
q{ BULK_EMAIL } => '',
q{ GUARANTEED_100_PERCENT } => '',
q{ NEVER_ANOTHER } => '',
q{ NATURAL_VIAGRA } => '',
q{ UCE_MAIL_ACT } => '',
q{ EXCUSE_13 } => ''
);

sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();

