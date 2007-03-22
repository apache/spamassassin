#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_subject");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%is_whitelist_patterns = (
q{ SUBJECT_IN_WHITELIST }, 'whitelist-subject'
);

%is_blacklist_patterns = (
q{ SUBJECT_IN_BLACKLIST }, 'blacklist-subject'
);

tstpre("
loadplugin Mail::SpamAssassin::Plugin::WhiteListSubject
");

tstprefs ("
use_bayes 0
use_auto_whitelist 0
$default_cf_lines
whitelist_subject [HC Anno*]
blacklist_subject whitelist test
	");

%patterns = %is_whitelist_patterns;

ok(sarun ("-L -t < data/nice/016", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_blacklist_patterns;

# force us to blacklist a nice msg
ok(sarun ("-L -t < data/nice/015", \&patterns_run_cb));
ok_all_patterns();
