#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("blacklist_autolearn");
use Test::More tests => 3;

# ---------------------------------------------------------------------------

disable_compat "welcomelist_blocklist";

%patterns = (
  q{ USER_IN_BLACKLIST }, 'blacklisted',
);

%anti_patterns = (
  q{ autolearn=ham } => 'autolearned as ham'
);

tstprefs ('
  header USER_IN_BLOCKLIST		eval:check_from_in_blocklist()
  tflags USER_IN_BLOCKLIST		userconf nice noautolearn
  meta USER_IN_BLACKLIST		(USER_IN_BLOCKLIST)
  tflags USER_IN_BLACKLIST		userconf nice noautolearn
  score USER_IN_BLACKLIST		100
  score USER_IN_BLOCKLIST		0.01
  blacklist_from *@ximian.com
');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

