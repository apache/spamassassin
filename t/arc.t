#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("arc");

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Needs Mail::DKIM::ARC::Verifier >= 0.50" unless HAS_DKIM_VERIFIER ;
plan tests => 2;

tstlocalrules (q{
  loadplugin Mail::SpamAssassin::Plugin::DKIM

  full     ARC_SIGNED eval:check_arc_signed()
  score    ARC_SIGNED 0.1

  full     ARC_VALID eval:check_arc_valid()
  score    ARC_VALID 0.1
});


%patterns = (
  q{ 0.1 ARC_SIGNED }, 'ARC_SIGNED',
);
sarun ("-t < data/dkim/arc/ok01.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = ();
%anti_patterns = (
  q{ 0.1 ARC_SIGNED }, 'ARC_SIGNED',
);
sarun ("-t < data/dkim/arc/ko01.eml", \&patterns_run_cb);
ok_all_patterns();
