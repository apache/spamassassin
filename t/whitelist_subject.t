#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_subject");
use Test::More tests => 4;

# ---------------------------------------------------------------------------

disable_compat "welcomelist_blocklist";

%is_whitelist_patterns = (
  q{ SUBJECT_IN_WHITELIST }, 'whitelist-subject'
);

%is_blacklist_patterns = (
  q{ SUBJECT_IN_BLACKLIST }, 'blacklist-subject'
);

tstprefs ("
  loadplugin Mail::SpamAssassin::Plugin::WhiteListSubject

  # Check that rename backwards compatibility works with if's
  ifplugin Mail::SpamAssassin::Plugin::WhiteListSubject
  if plugin(Mail::SpamAssassin::Plugin::WelcomeListSubject)
  whitelist_subject [HC Anno*]
  blacklist_subject whitelist test
  endif
  endif
");

%patterns = %is_whitelist_patterns;

ok(sarun ("-L -t < data/nice/016", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_blacklist_patterns;

# force us to blacklist a nice msg
ok(sarun ("-L -t < data/nice/015", \&patterns_run_cb));
ok_all_patterns();

