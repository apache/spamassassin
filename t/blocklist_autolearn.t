#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("blocklist_autolearn");
use Test::More tests => 3;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 100 USER_IN_BLOCKLIST }, 'blocklisted',
);

%anti_patterns = (
  'autolearn=ham' => 'autolearned as ham'
);

tstprefs ('
  header USER_IN_BLOCKLIST		eval:check_from_in_blocklist()
  tflags USER_IN_BLOCKLIST		userconf nice noautolearn
  score USER_IN_BLOCKLIST		100
  blacklist_from *@ximian.com
');

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

