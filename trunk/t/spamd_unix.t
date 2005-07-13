#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_unix");

use Test; BEGIN { plan tests => ((!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS)? 4 : 0) };

exit unless (!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS);

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

my $sockpath = mk_safe_tmpdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath");
ok (spamcrun ("-U $sockpath < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();
cleanup_safe_tmpdir();

