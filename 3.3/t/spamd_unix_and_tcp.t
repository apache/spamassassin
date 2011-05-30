#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_unix_and_tcp");

use Test; BEGIN { plan tests => ((!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS)? 10 : 0) };

exit unless (!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS);

# ---------------------------------------------------------------------------

my $sockpath = mk_safe_tmpdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath --port $spamdport");
%patterns = (
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Flag: YES}, 'flag',
);
ok (spamcrun ("-U $sockpath < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

clear_pattern_counters();
%patterns = (
  q{ GTUBE }, 'gtube',
);
ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

clear_pattern_counters();
%patterns = (
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Flag: YES}, 'flag',
);
ok (spamcrun ("-U $sockpath < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

clear_pattern_counters();
%patterns = (
  q{ GTUBE }, 'gtube',
);
ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

stop_spamd();
cleanup_safe_tmpdir();

