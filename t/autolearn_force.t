#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn_force");

use constant HAS_DB_FILE => eval { require DB_File; };

use Test::More;

plan skip_all => 'Need DB_File for this test' unless HAS_DB_FILE;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (

q{ autolearn=spam autolearn_force=yes } => 'autolearned as spam with autolearn_force'

);

%anti_patterns = (
);

tstprefs ('

body	AUTOLEARNTEST_BODY	/EVOLUTION PREVIEW RELEASE/
score	AUTOLEARNTEST_BODY	7.0
tflags	AUTOLEARNTEST_BODY	autolearn_force

use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_spam 6.0

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
