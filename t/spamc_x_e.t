#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_x_e");

our $DO_RUN = !$SKIP_SPAMD_TESTS;

use Test; plan tests => ($DO_RUN ? 7 : 0);

exit unless $DO_RUN;

# ---------------------------------------------------------------------------
# test case for bug 5478: spamc -x -e

%patterns = ( 'Fine' => 'Fine' );

ok start_spamd("-L");
ok spamcrun("-x -e /bin/echo Fine < data/nice/001", \&patterns_run_cb);
ok ok_all_patterns();
stop_spamd();

%patterns = ( );
%anti_patterns = ( 'Fine' => 'Fine' );
$spamdhost = '255.255.255.255'; # cause "connection failed" errors

ok !spamcrun("-x -e /bin/echo Fine < data/nice/001", \&patterns_run_cb);
ok ok_all_patterns();

