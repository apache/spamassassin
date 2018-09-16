#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_optC");

use Test::More;
plan skip_all => "No SPAMC exe" if $SKIP_SPAMC_TESTS;
plan tests => 9;

# ---------------------------------------------------------------------------

tstlocalrules ("
	loadplugin reporterplugin ../../data/reporterplugin.pm
");

start_spamd("-L --allow-tell");

%patterns = ( 'Message successfully reported/revoked' => 'reported spam' );

ok (spamcrun ("-C report < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully reported/revoked' => 'revoked ham' );

ok (spamcrun ("-C revoke < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

open (OUT, ">log/rptfail");
print OUT "file created to trigger a reporterplugin failure";
close OUT;

%patterns = ( 'Unable to report/revoke message' => 'failed to report spam' );

ok (spamcrun ("-C report < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Unable to report/revoke message' => 'failed to revoke ham' );

ok (spamcrun ("-C revoke < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

stop_spamd();

ok(unlink 'log/rptfail'); # need a little cleanup
