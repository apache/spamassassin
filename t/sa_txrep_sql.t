#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest;
use Test::More;

sa_t_init("sa_txrep_sql");

use constant HAS_DBI => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; DBD::SQLite->VERSION(1.59_01); };

use constant SQLITE => (HAS_DBI && HAS_DBD_SQLITE);
use constant SQL => conf_bool('run_awl_sql_tests');

plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "run_awl_sql_tests not enabled or DBI/SQLite not found" unless (SQLITE || SQL);

diag "Note: If there is a failure it may be due to an incorrect SQL configuration." if (SQL);

my $tests = 0;
$tests += 2 if (SQLITE);
$tests += 2 if (SQL);
plan tests => $tests;

# ---------------------------------------------------------------------------
my $rules = q(
    add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"
    # Needed for TXREP to run
    header TXREP eval:check_senders_reputation()
    priority TXREP 1000
    # Fixed message scores to keep track of correct scoring
    header   FORGED_GMAIL_RCVD  eval:check_for_forged_gmail_received_headers()

    full     DKIM_SIGNED        eval:check_dkim_signed()
    full     DKIM_VALID         eval:check_dkim_valid()
    meta     DKIM_INVALID       DKIM_SIGNED && !DKIM_VALID
    full     DKIM_VALID_AU      eval:check_dkim_valid_author_sig()
    full     DKIM_VALID_EF      eval:check_dkim_valid_envelopefrom()
    score    DKIM_SIGNED        0.1
    score    DKIM_VALID         -0.1
    score    DKIM_INVALID       0.1
    score    DKIM_VALID_AU      -0.1
    score    DKIM_VALID_EF      -0.1

    body     GTUBE              /XJS\*C4JDBQADN1\.NSBN3\*2IDNEN\*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL\*C\.34X/
    score    GTUBE              1000

    header   SPF_PASS           eval:check_for_spf_pass()
    header   SPF_NEUTRAL        eval:check_for_spf_neutral()
    header   SPF_FAIL           eval:check_for_spf_fail()
    header   SPF_SOFTFAIL       eval:check_for_spf_softfail()
    score    SPF_PASS           -0.001
    score    SPF_NEUTRAL        0.001
    score    SPF_FAIL           0.001
    score    SPF_SOFTFAIL       0.001
);

tstpre ("
  loadplugin Mail::SpamAssassin::Plugin::TxRep
  loadplugin Mail::SpamAssassin::Plugin::SPF
  loadplugin Mail::SpamAssassin::Plugin::DKIM
");

# only use rules defined here in tstprefs()
clear_localrules();

%txrep_pattern0 = (
  q{ 98 TXREP } => 'Score normalizing',
);
if (SQLITE) {
  my $db = "$workdir/txrep.db";
  unlink($db) if -f $db;

  my $dbh = DBI->connect("dbi:SQLite:dbname=$db","","");
  $dbh->do("
  CREATE TABLE txrep (
    username varchar(100) NOT NULL default '',
    email varchar(255) NOT NULL default '',
    ip varchar(40) NOT NULL default '',
    msgcount int(11) NOT NULL default '0',
    totscore float NOT NULL default '0',
    signedby varchar(255) NOT NULL default '',
    last_hit timestamp NOT NULL default CURRENT_TIMESTAMP,
    PRIMARY KEY (username,email,signedby,ip)
  );
  CREATE INDEX last_hit ON txrep (last_hit);
  CREATE TRIGGER [UpdateLastHit]
    AFTER UPDATE
    ON txrep
    FOR EACH ROW
    WHEN NEW.last_hit < OLD.last_hit
  BEGIN
    UPDATE txrep SET last_hit=CURRENT_TIMESTAMP
    WHERE (username=OLD.username AND email=OLD.email AND signedby=OLD.signedby AND ip=OLD.ip);
  END;
  ") or die "Failed to create $db";

  tstprefs ("
    use_txrep 1
    txrep_factory Mail::SpamAssassin::SQLBasedAddrList
    auto_welcomelist_distinguish_signed 1
    user_awl_dsn dbi:SQLite:dbname=$workdir/txrep.db
    $rules
  ");

  %anti_patterns = %txrep_pattern0;
  %patterns = ();
  sarun ("-t < data/txrep/6", \&patterns_run_cb);
  ok_all_patterns();

  %anti_patterns = ();
  %patterns = %txrep_pattern0;
  sarun ("-t < data/txrep/7", \&patterns_run_cb);
  ok_all_patterns();
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
    use_txrep 1
    txrep_factory Mail::SpamAssassin::SQLBasedAddrList
    auto_welcomelist_distinguish_signed 1
    $dbconfig
    user_awl_sql_override_username $testuser
    $rules
  ");

  %anti_patterns = %txrep_pattern0;
  %patterns = ();
  sarun ("-t -D all < data/txrep/6 2>/tmp/2_6", \&patterns_run_cb);
  ok_all_patterns();

  %anti_patterns = ();
  %patterns = %txrep_pattern0;
  sarun ("-t -D all < data/txrep/7 2>/tmp/2_7", \&patterns_run_cb);
  ok_all_patterns();
}
