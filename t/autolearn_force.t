#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn_force");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (

q{ autolearn=spam } => 'autolearned as spam'

);

%anti_patterns = (
);

tstprefs ('

body	WEIGHT	/EVOLUTION PREVIEW RELEASE/
score	WEIGHT	7.0
tflags	WEIGHT	autolearn_force

use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_spam 6.0

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
