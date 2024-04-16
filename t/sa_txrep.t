#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("sa_txrep");

use Test::More;

my @dbmods = grep eval "require $_", ('DB_File', 'GDBM_File', 'SDBM_File');
plan skip_all => "No db module is available" unless @dbmods;
plan tests => 8 * @dbmods;

# ---------------------------------------------------------------------------

my $rules = q(
    add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ autolearn=_AUTOLEARN_ version=_VERSION_"
    # Needed for TXREP to run
    header TXREP eval:check_senders_reputation()
    priority TXREP 1000
    # Fixed message scores to keep track of correct scoring
    header   FORGED_GMAIL_RCVD	eval:check_for_forged_gmail_received_headers()

    header   TEST_NOREALNAME    From =~ /^["\s]*\<?\S+\@\S+\>?\s*$/
    score    TEST_NOREALNAME    5

    header   FROM_2_EMAILS      From =~ /(?:^|<|"| )([\w+.-]+\@[\w.-]+\.\w\w++)(?:[^\n\w<]{0,80})?<(?!\1)[^\n\s]*\@/i
);

%txrep_pattern0 = (
  q{ 0.0 TXREP } => 'Score normalizing',
);

%txrep_pattern1 = (
  q{ 1.2 TXREP } => 'Score normalizing',
);

%txrep_pattern2 = (
  q{ -25 TXREP } => 'Score normalizing',
);

%txrep_pattern3 = (
  q{ -90 TXREP } => 'Score normalizing',
);

%txrep_pattern0a = (
  q{ 0.0 TXREP } => 'Score normalizing',
);

%txrep_pattern1a = (
  q{ 1.1 TXREP } => 'Score normalizing',
);

%txrep_pattern2a = (
  q{ -25 TXREP } => 'Score normalizing',
);

%txrep_pattern3a = (
  q{ -36 TXREP } => 'Score normalizing',
);

tstpre ("
  loadplugin Mail::SpamAssassin::Plugin::TxRep
");

# only use rules defined here in tstprefs()
clear_localrules();

# Run entire set of tests with each available xxx_File module
foreach my $dbmodule (@dbmods) {
  diag "Testing with $dbmodule";

  tstprefs ("
  use_txrep 1
  auto_welcomelist_path ./$userstate/txreptest
  auto_welcomelist_file_mode 0755
  auto_welcomelist_db_modules $dbmodule
  $rules
");
  unlink("./$userstate/txreptest", "./$userstate/txreptest.pag", "./$userstate/txreptest.dir", "./$userstate/txreptest.mutex");

  %patterns = ();
  %anti_patterns = %txrep_pattern0;
  sarun ("-L -t < data/txrep/0", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  # feed TxRep
  sarun ("-L -t < data/txrep/1", \&patterns_run_cb);
  sarun ("-L -t < data/txrep/2", \&patterns_run_cb);

  %patterns = %txrep_pattern1;
  %anti_patterns = ();
  sarun ("-L -t < data/txrep/3", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  %patterns = %txrep_pattern2;
  %anti_patterns = ();
  sarun ("--add-addr-to-welcomelist=test1\@gmail.com");
  sarun ("-L -t < data/txrep/4", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  %patterns = %txrep_pattern3;
  %anti_patterns = ();
  sarun ("-L -t < data/txrep/5", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  tstprefs("
  use_txrep 1
  auto_welcomelist_path ./$userstate/txreptest
  auto_welcomelist_file_mode 0755
  auto_welcomelist_db_modules $dbmodule
  txrep_weight_email 10
  $rules
");
  unlink("./$userstate/txreptest", "./$userstate/txreptest.pag", "./$userstate/txreptest.dir", "./$userstate/txreptest.mutex");

  %patterns = ();
  %anti_patterns = %txrep_pattern0a;
  sarun ("-L -t < data/txrep/0", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  # feed TxRep
  sarun ("-L -t < data/txrep/1", \&patterns_run_cb);
  sarun ("-L -t < data/txrep/2", \&patterns_run_cb);

  %patterns = %txrep_pattern1a;
  %anti_patterns = ();
  sarun ("-L -t < data/txrep/3", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  %patterns = %txrep_pattern2a;
  %anti_patterns = ();
  sarun ("--add-addr-to-welcomelist=test1\@gmail.com");
  sarun ("-L -t < data/txrep/4", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  %patterns = %txrep_pattern3a;
  %anti_patterns = ();
  sarun ("-L -t < data/txrep/5", \&patterns_run_cb);
  ok_all_patterns();

}
