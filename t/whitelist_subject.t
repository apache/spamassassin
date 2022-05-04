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
  header SUBJECT_IN_WELCOMELIST		eval:check_subject_in_welcomelist()
  tflags SUBJECT_IN_WELCOMELIST		userconf nice noautolearn
  score SUBJECT_IN_WELCOMELIST		-100

  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta SUBJECT_IN_WHITELIST		(SUBJECT_IN_WELCOMELIST)
    tflags SUBJECT_IN_WHITELIST		userconf nice noautolearn
    score SUBJECT_IN_WHITELIST		-100
    score SUBJECT_IN_WELCOMELIST	-0.01
  endif

  header SUBJECT_IN_BLOCKLIST		eval:check_subject_in_blocklist()
  tflags SUBJECT_IN_BLOCKLIST		userconf noautolearn
  score SUBJECT_IN_BLOCKLIST		100

  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta SUBJECT_IN_BLACKLIST		(SUBJECT_IN_BLOCKLIST)
    tflags SUBJECT_IN_BLACKLIST		userconf noautolearn
    score SUBJECT_IN_BLACKLIST		100
    score SUBJECT_IN_BLOCKLIST		0.01
  endif

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

