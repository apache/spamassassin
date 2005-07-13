#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_cf");
use Test; plan tests => ($SKIP_SPAMC_TESTS ? 0 : 4);

exit if $SKIP_SPAMC_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

my $sockpath = mk_safe_tmpdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath");

open (OUT, ">log/spamc_cf.cf");
print OUT "-U $sockpath\n";
close OUT;

ok (spamcrun ("-F log/spamc_cf.cf < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();
cleanup_safe_tmpdir();

