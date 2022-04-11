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

diag "Note: Failure may be due to an incorrect config";

sa_t_init("sql_based_whitelist");

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

# 3 times, to get into the whitelist:
%patterns = (%is_nonspam_patterns, (q{'144.137 scores 0, msgcount 0'} => 'scores'));
ok(sarun ("-L -t -D auto-whitelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();
%patterns = (%is_nonspam_patterns, (q{'144.137 scores -2, msgcount 1'} => 'scores'));
ok(sarun ("-L -t -D auto-whitelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();
%patterns = (%is_nonspam_patterns, (q{'144.137 scores -4, msgcount 2'} => 'scores'));
ok(sarun ("-L -t -D auto-whitelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();

# Now check
%patterns = (%is_nonspam_patterns, (q{'144.137 scores -6, msgcount 3'} => 'scores'));
ok(sarun ("-L -t -D auto-whitelist < data/nice/002 2>&1", \&patterns_run_cb));
ok_all_patterns();

%patterns = (%is_spam_patterns, (q{'144.137 scores -8, msgcount 4'} => 'scores'));;
ok(sarun ("-L -t -D auto-whitelist < data/spam/004 2>&1", \&patterns_run_cb));
ok_all_patterns();

# Should be raised after last spam
%patterns = (%is_spam_patterns, (q{'144.137 scores 9.837, msgcount 5'} => 'scores'));;
ok(sarun ("-L -t -D auto-whitelist < data/spam/004 2>&1", \&patterns_run_cb));
ok_all_patterns();

%patterns = (%is_spam_patterns2, (q{'210.73 scores 0, msgcount 0'} => 'scores'));;
ok(sarun ("-L -t -D auto-whitelist < data/spam/007 2>&1", \&patterns_run_cb));
ok_all_patterns();

ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));

}
# ---------------------------------------------------------------------------
