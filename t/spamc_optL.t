#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_optL");
use constant HAS_SDBM_FILE => eval { require SDBM_File; };

use Test; plan tests => (!HAS_SDBM_FILE || $SKIP_SPAMC_TESTS ? 0 : 16);

exit if (!HAS_SDBM_FILE || $SKIP_SPAMC_TESTS);

# ---------------------------------------------------------------------------

tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
");

start_spamd("-L --allow-tell");

%patterns = ( 'Message successfully un/learned' => 'learned spam' );
ok (spamcrun ("-L spam < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message was already un/learned' => 'already learned spam' );
ok (spamcrun ("-L spam < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( '1 0  non-token data: nspam' => 'spam in database' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'forget spam' );
ok (spamcrun ("-L forget < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'learned ham' );
ok (spamcrun ("-L ham < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message was already un/learned' => 'already learned ham' );
ok (spamcrun ("-L ham < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( '1 0  non-token data: nham' => 'ham in database' );
ok(salearnrun("--dump magic", \&patterns_run_cb));
ok_all_patterns();

%patterns = ( 'Message successfully un/learned' => 'learned ham' );
ok (spamcrun ("-L forget < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

stop_spamd();
