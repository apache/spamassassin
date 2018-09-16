#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_unix");

use Test::More;
plan skip_all => "Spamd tests disabled"        if $SKIP_SPAMD_TESTS;
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan tests => 4;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

tstlocalrules("
      use_auto_whitelist 0
    ");

my $sockpath = mk_safe_tmpdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath");
ok (spamcrun ("-U $sockpath < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
stop_spamd();
cleanup_safe_tmpdir();

