#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_L");
use Test; plan tests => ($SKIP_SPAMC_TESTS ? 0 : 16);

exit if $SKIP_SPAMC_TESTS;

# ---------------------------------------------------------------------------

start_spamd("-L");

%patterns = ( 'Message successfully un/learned' => 'learned spam' );
ok (spamclearnrun ("-L spam < data/spam/001", \&patterns_run_cb) == 5);
ok_all_patterns();

%patterns = ( 'Message was already un/learned' => 'already learned spam' );
ok (spamclearnrun ("-L spam < data/spam/001", \&patterns_run_cb) == 6);
ok_all_patterns();

%patterns = ( '1 0  non-token data: nspam' => 'spam in database' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'forget spam' );
ok (spamclearnrun ("-L forget < data/spam/001", \&patterns_run_cb) == 5);
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'learned ham' );
ok (spamclearnrun ("-L ham < data/nice/001", \&patterns_run_cb) == 5);
ok_all_patterns();

%patterns = ( 'Message was already un/learned' => 'already learned ham' );
ok (spamclearnrun ("-L ham < data/nice/001", \&patterns_run_cb) == 6);
ok_all_patterns();

%patterns = ( '1 0  non-token data: nham' => 'ham in database' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'learned ham' );
ok (spamclearnrun ("-L forget < data/nice/001", \&patterns_run_cb) == 5);
ok_all_patterns();

stop_spamd();
