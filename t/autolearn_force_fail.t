#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn_force_fail");

use constant HAS_DB_FILE => eval { require DB_File; };

use Test::More;

plan skip_all => 'Need DB_File for this test' unless HAS_DB_FILE;
plan tests => 3;

# ---------------------------------------------------------------------------

%patterns = (
q{ autolearn=no } => 'autolearn no',
);

%anti_patterns = (
q{ autolearn=spam } => 'autolearned as spam',
);

tstprefs ('

header	 AUTOLEARNTEST_FROM_HEADER	From =~ /@/
score	 AUTOLEARNTEST_FROM_HEADER	13.0
describe AUTOLEARNTEST_FROM_HEADER	Test rule for Autolearning 

use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_spam 12.0

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
