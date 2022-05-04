#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_to");
use Test::More tests => 1;

# ---------------------------------------------------------------------------

%patterns = (
  q{ USER_IN_WELCOMELIST_TO }, 'hit-wl',
);

tstprefs ("
  header USER_IN_WELCOMELIST_TO		eval:check_to_in_welcomelist()
  tflags USER_IN_WELCOMELIST_TO		userconf nice noautolearn
  score USER_IN_WELCOMELIST_TO		-6
  whitelist_to announce*
");

sarun ("-L -t < data/nice/016", \&patterns_run_cb);
ok_all_patterns();

