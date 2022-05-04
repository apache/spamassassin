#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("welcomelist_subject");
use Test::More tests => 4;

# ---------------------------------------------------------------------------

%is_welcomelist_patterns = (
  q{ SUBJECT_IN_WELCOMELIST }, 'welcomelist-subject'
);

%is_blocklist_patterns = (
  q{ SUBJECT_IN_BLOCKLIST }, 'blocklist-subject'
);

tstprefs ("
  loadplugin Mail::SpamAssassin::Plugin::WelcomeListSubject
  header SUBJECT_IN_WELCOMELIST		eval:check_subject_in_welcomelist()
  tflags SUBJECT_IN_WELCOMELIST		userconf nice noautolearn
  score SUBJECT_IN_WELCOMELIST		-100
  header SUBJECT_IN_BLOCKLIST		eval:check_subject_in_blocklist()
  tflags SUBJECT_IN_BLOCKLIST		userconf noautolearn
  score SUBJECT_IN_BLOCKLIST		100

  # Check that rename backwards compatibility works with if's
  ifplugin Mail::SpamAssassin::Plugin::WhiteListSubject
  if plugin(Mail::SpamAssassin::Plugin::WelcomeListSubject)
  welcomelist_subject [HC Anno*]
  blocklist_subject whitelist test
  endif
  endif
");

%patterns = %is_welcomelist_patterns;

ok(sarun ("-L -t < data/nice/016", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_blocklist_patterns;

# force us to blocklist a nice msg
ok(sarun ("-L -t < data/nice/015", \&patterns_run_cb));
ok_all_patterns();

