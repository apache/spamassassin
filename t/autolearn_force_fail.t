#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn_force_fail");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (
q{ autolearn=no } => 'autolearn no',
);

%anti_patterns = (
q{ autolearn=spam } => 'autolearned as spam',
);

tstprefs ('

header	WEIGHT	From =~ /@/
score	WEIGHT	13.0

use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_spam 12.0

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
