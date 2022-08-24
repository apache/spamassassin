#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_cf");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 4;

# ---------------------------------------------------------------------------

%patterns = (
  q{ Subject: There yours for FREE!}, 'subj',
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
);

my $sockpath = mk_socket_tempdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath");

open (OUT, ">$workdir/spamc_cf.cf");
print OUT "-U $sockpath\n";
close OUT;

ok (spamcrun ("-F $workdir/spamc_cf.cf < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();

