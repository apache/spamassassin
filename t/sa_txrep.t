#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("sa_txrep");

use Test::More tests => 12;

# ---------------------------------------------------------------------------

tstpre ("
  loadplugin Mail::SpamAssassin::Plugin::TxRep
");

tstprefs ("
  use_txrep 1
  auto_welcomelist_path ./$userstate/txreptest
  auto_welcomelist_file_mode 0755
");

%txrep_pattern0 = (
  q{ 0.0 TXREP } => 'Score normalizing',
);

%txrep_pattern1 = (
  q{ 0.1 TXREP } => 'Score normalizing',
);

%txrep_pattern2 = (
  q{ 0.9 TXREP } => 'Score normalizing',
);

%txrep_pattern3 = (
  q{ -25 TXREP } => 'Score normalizing',
);

%txrep_pattern4 = (
  q{ -90 TXREP } => 'Score normalizing',
);

%patterns = ();
%anti_patterns = %txrep_pattern0;
sarun ("-L -t < data/txrep/0", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern0;
%anti_patterns = ();
sarun ("-L -t < data/txrep/1", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern1;
%anti_patterns = ();
sarun ("-L -t < data/txrep/2", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern2;
%anti_patterns = ();
sarun ("-L -t < data/txrep/3", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern3;
%anti_patterns = ();
sarun ("--add-addr-to-welcomelist=test1\@gmail.com");
sarun ("-L -t < data/txrep/4", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern4;
%anti_patterns = ();
sarun ("-L -t < data/txrep/5", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

tstprefs("
  use_txrep 1
  auto_welcomelist_path ./$userstate/txreptest
  auto_welcomelist_file_mode 0755
  txrep_weight_email 10
");
unlink("./$userstate/txreptest");

%txrep_pattern0 = (
  q{ 0.0 TXREP } => 'Score normalizing',
);

%txrep_pattern1 = (
  q{ 0.1 TXREP } => 'Score normalizing',
);

%txrep_pattern2 = (
  q{ 0.9 TXREP } => 'Score normalizing',
);

%txrep_pattern3 = (
  q{ -26 TXREP } => 'Score normalizing',
);

%txrep_pattern4 = (
  q{ -36 TXREP } => 'Score normalizing',
);

%patterns = ();
%anti_patterns = %txrep_pattern0;
sarun ("-L -t < data/txrep/0", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern0;
%anti_patterns = ();
sarun ("-L -t < data/txrep/1", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern1;
%anti_patterns = ();
sarun ("-L -t < data/txrep/2", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern2;
%anti_patterns = ();
sarun ("-L -t < data/txrep/3", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern3;
%anti_patterns = ();
sarun ("--add-addr-to-welcomelist=test1\@gmail.com");
sarun ("-L -t < data/txrep/4", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = %txrep_pattern4;
%anti_patterns = ();
sarun ("-L -t < data/txrep/5", \&patterns_run_cb);
ok_all_patterns();
