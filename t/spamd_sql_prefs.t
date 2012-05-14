#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_sql_prefs");
use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; };

our $DO_RUN = !$SKIP_SPAMD_TESTS && conf_bool('run_sql_pref_tests')
    && HAS_DBI && HAS_DBD_SQLITE;

use Test; plan tests => ($DO_RUN ? 32 : 0);

exit unless $DO_RUN;

# ---------------------------------------------------------------------------

my $userprefdb = mk_safe_tmpdir()."/userpref.db";

my $dbh = DBI->connect("dbi:SQLite:dbname=$userprefdb","","");
ok($dbh);
$dbh->{AutoCommit} = 1;
ok($dbh->do("CREATE TABLE userpref (username, preference, value)"));
ok($dbh->do("INSERT INTO userpref VALUES('\@GLOBAL', 'add_header', 'all tTEST1 FOO1')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'GTUBE 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'MSGID_RANDY 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'DATE_IN_PAST_03_06 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'add_header', 'all tTEST2 FOO2')"));

tstlocalrules ("
    user_scores_dsn dbi:SQLite:dbname=$userprefdb
");

ok(start_spamd("-L --sql-config -u $spamd_run_as_user"));

%patterns = (
	     q{ X-Spam-tTEST1: FOO1 }, 'Added Header tTEST1',
	     q{ X-Spam-Flag: YES}, 'Spam Flag',
	     q{ BODY: Generic Test for Unsolicited Bulk Email }, 'GTUBE Test',
	     q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'GTUBE String',
);

%anti_patterns = (
		  q{ X-Spam-tTEST2: FOO2 }, 'Added Header',
		  );
ok (spamcrun("-u nobody < data/spam/018", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
	     q{ X-Spam-tTEST1: FOO1 }, 'Added Header tTEST1',
	     q{ X-Spam-tTEST2: FOO2 }, 'Added Header tTEST2',
	     q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'GTUBE String',
	     );
%anti_patterns = (
	     q{ BODY: Generic Test for Unsolicited Bulk Email }, 'GTUBE Test',
	     q{ X-Spam-Flag: YES}, 'Spam Flag',
	     );

ok (spamcrun("-u testuser < data/spam/018", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'required_score', '1000')"));

%patterns = (
	     q{ X-Spam-tTEST1: FOO1 }, 'Added Header tTEST1',
	     q{ X-Spam-tTEST2: FOO2 }, 'Added Header tTEST2',
	     q{ X-Spam-Status: No }, 'Spam Status No',
	     q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'GTUBE String',
	     );
%anti_patterns = (
		  q{ X-Spam-Flag: YES}, 'Spam Flag YES',
		  q{ BODY: Generic Test for Unsolicited Bulk Email }, 'GTUBE Test',
		  );

ok (spamcrun("-u testuser < data/spam/018", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
	     q{ dbg: config: retrieving prefs for }, 'Retrieving Prefs',
	     );
%anti_patterns = (
		  q{ warn: closing dbh with active statement handles }, 'Closing Active Handles',
		  );

checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

ok(stop_spamd());

cleanup_safe_tmpdir();

ok($dbh->disconnect());
