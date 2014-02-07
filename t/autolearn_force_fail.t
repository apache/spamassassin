#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn_force_fail");
use Test; 

use Test;

use constant TEST_ENABLED => eval { require DB_File; };

BEGIN {
  plan tests => (TEST_ENABLED ? 3 : 0);
};

exit unless TEST_ENABLED;

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
