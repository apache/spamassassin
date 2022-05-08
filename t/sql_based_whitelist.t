#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest;
use Test::More;

use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; };

use constant SQLITE => (HAS_DBI && HAS_DBD_SQLITE);
use constant SQL => conf_bool('run_awl_sql_tests');

plan skip_all => "run_awl_sql_tests not enabled or DBI/SQLite not found" unless (SQLITE || SQL);

my $tests = 0;
$tests += 23 if (SQLITE);
$tests += 23 if (SQL);
plan tests => $tests;

diag "Note: If there is a failure it may be due to an incorrect SQL configuration.";

sa_t_init("sql_based_whitelist");

# only use rules defined here in tstprefs()
clear_localrules();

my $rules = q(
    add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"
    # Needed for AWL to run
    header AWL eval:check_from_in_auto_whitelist()
    priority AWL 1000
    # Fixed message scores to keep track of correct scoring
    body NICE_002 /happy mailing list/
    score NICE_002 -1.2
    body SPAM_004_007 /MAKE MONEY FAST/
    score SPAM_004_007 5.5
);

if (SQLITE) {
  my $dbh = DBI->connect("dbi:SQLite:dbname=$workdir/awl.db","","");
  $dbh->do("
  CREATE TABLE awl (
    username varchar(100) NOT NULL default '',
    email varchar(255) NOT NULL default '',
    ip varchar(40) NOT NULL default '',
    msgcount bigint NOT NULL default '0',
    totscore float NOT NULL default '0',
    signedby varchar(255) NOT NULL default '',
    last_hit timestamp NOT NULL default CURRENT_TIMESTAMP,
    PRIMARY KEY (username,email,signedby,ip)
  );
  ") or die "Failed to create $workdir/awl.db";

  tstprefs ("
    use_auto_whitelist 1
    auto_whitelist_factory Mail::SpamAssassin::SQLBasedAddrList
    user_awl_dsn dbi:SQLite:dbname=$workdir/awl.db
    $rules
  ");

  run_awl();
}

if (SQL) {
  my $dbconfig = '';
  foreach my $setting (qw(
      user_awl_dsn
      user_awl_sql_username
      user_awl_sql_password
      user_awl_sql_table
      )) {
    my $val = conf($setting);
    $dbconfig .= "$setting $val\n" if $val;
  }

  my $testuser = 'tstusr.'.$$.'.'.time();

  tstprefs ("
    use_auto_whitelist 1
    auto_whitelist_factory Mail::SpamAssassin::SQLBasedAddrList
    $dbconfig
    user_awl_sql_override_username $testuser
    $rules
  ");

  run_awl();
}

# ---------------------------------------------------------------------------
sub run_awl {

%is_nonspam_patterns = (
  q{ Subject: Re: [SAtalk] auto-whitelisting}, 'subj',
);
%is_spam_patterns = (
  q{Subject: 4000           Your Vacation Winning !}, 'subj',
);
%is_spam_patterns2 = (
  q{ X-Spam-Status: Yes}, 'status',
);

%patterns = %is_nonspam_patterns;
ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));

# 3 times, to get into the whitelist: # verify correct ip/score/msgcount from debug output
%patterns = (%is_nonspam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores 0, msgcount 0'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();
%patterns = (%is_nonspam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores -1.2, msgcount 1'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();
%patterns = (%is_nonspam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores -2.4, msgcount 2'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();

# Now check
%patterns = (%is_nonspam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores -3.6, msgcount 3'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();

%patterns = (%is_spam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores -4.8, msgcount 4'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/spam/004 2>&1", \&patterns_run_cb));
ok_all_patterns();

# Should be raised after last spam
%patterns = (%is_spam_patterns,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|144.137 scores 0.7, msgcount 5'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/spam/004 2>&1", \&patterns_run_cb));
ok_all_patterns();

%patterns = (%is_spam_patterns2,
  (q{'sql-based whitelist_test@whitelist.spamassassin.taint.org|210.73 scores 0, msgcount 0'} => 'scores'));
ok(sarun ("-L -t -D auto-welcomelist < data/spam/007 2>&1", \&patterns_run_cb));
ok_all_patterns();

ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));

}
# ---------------------------------------------------------------------------
