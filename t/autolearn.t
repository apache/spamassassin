#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("autolearn");

use constant HAS_DB_FILE => eval { require DB_File; };

use Test::More;

plan skip_all => 'Need DB_File for this test' unless HAS_DB_FILE;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (

q{ autolearn=spam } => 'autolearned as spam'

);

%anti_patterns = (
);

tstprefs ('

body	AUTOLEARNTEST_BODY	/EVOLUTION PREVIEW RELEASE/
score	AUTOLEARNTEST_BODY	1.5

body    AUTOLEARNTEST_BODY2     /GET SOURCE CODE/
score   AUTOLEARNTEST_BODY2     1.5

body    AUTOLEARNTEST_BODY3     /RELEASE NOTES/
score   AUTOLEARNTEST_BODY3     1.5

header  AUTOLEARNTEST_HEAD      From =~ /@/
score   AUTOLEARNTEST_HEAD      1.5

header  AUTOLEARNTEST_HEAD2     Subject =~ /HC Announce/
score   AUTOLEARNTEST_HEAD2     1.5

header  AUTOLEARNTEST_HEAD3	Precedence =~ /bulk/
score	AUTOLEARNTEST_HEAD3	1.5

use_bayes 1
bayes_auto_learn 1
bayes_auto_learn_threshold_spam 6.0

');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();
