#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_sql_prefs");
use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; DBD::SQLite->VERSION(1.59_01); };

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "SQL Pref tests disabled" unless conf_bool('run_sql_pref_tests');
plan skip_all => "DBI is unavailble" unless HAS_DBI;
plan skip_all => "SQLite is unavailble" unless HAS_DBD_SQLITE;
plan tests => 32;

# ---------------------------------------------------------------------------

my $userprefdb = $workdir."/userpref.db";

my $dbh = DBI->connect("dbi:SQLite:dbname=$userprefdb","","");
ok($dbh);
$dbh->{AutoCommit} = 1;
ok($dbh->do("CREATE TABLE userpref (username, preference, value)"));
ok($dbh->do("INSERT INTO userpref VALUES('\@GLOBAL', 'add_header', 'all tTEST1 FOO1')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'GTUBE 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'MSGID_RANDY 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'score', 'DATE_IN_PAST_03_06 0')"));
ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'add_header', 'all tTEST2 FOO2')"));

tstprefs ("
  user_scores_dsn dbi:SQLite:dbname=$userprefdb
");

ok(start_spamd("-L --sql-config -u $spamd_run_as_user"));

%patterns = (
  qr/^X-Spam-tTEST1: FOO1$/m, 'Added Header tTEST1',
  qr/^X-Spam-Flag: YES/m, 'Spam Flag',
  q{ 1000 GTUBE }, 'GTUBE Test',
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'GTUBE String',
);
%anti_patterns = (
  'X-Spam-tTEST2: FOO2', 'Added Header',
);
ok (spamcrun("-u nobody < data/spam/018", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  qr/^X-Spam-tTEST1: FOO1$/m, 'Added Header tTEST1',
  qr/^X-Spam-tTEST2: FOO2$/m, 'Added Header tTEST2',
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'GTUBE String',
);
%anti_patterns = (
  q{ 1000 GTUBE }, 'GTUBE Test',
  'X-Spam-Flag: YES', 'Spam Flag',
);
ok (spamcrun("-u testuser < data/spam/018", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

ok($dbh->do("INSERT INTO userpref VALUES('testuser', 'required_score', '1000')"));

%patterns = (
  qr/^X-Spam-tTEST1: FOO1\n/m, 'Added Header tTEST1',
  qr/^X-Spam-tTEST2: FOO2\n/m, 'Added Header tTEST2',
  qr/^X-Spam-Status: No/m, 'Spam Status No',
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'GTUBE String',
);
%anti_patterns = (
  'X-Spam-Flag: YES', 'Spam Flag YES',
  q{ 1000 GTUBE }, 'GTUBE Test',
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

ok($dbh->disconnect());

