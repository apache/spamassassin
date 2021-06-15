#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dmarc");

use Test::More;

use vars qw(%patterns %anti_patterns);

use constant HAS_MAILSPF => eval { require Mail::SPF; };
use constant HAS_DKIM_VERIFIER => eval {
  require Mail::DKIM::Verifier;
  version->parse(Mail::DKIM::Verifier->VERSION) >= version->parse(0.31);
};

plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Need Mail::SPF" unless HAS_MAILSPF;
plan skip_all => "Needs Mail::DKIM::Verifier >= 0.31" unless HAS_DKIM_VERIFIER ;
plan tests => 9;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Dmarc
");

tstprefs("
header DMARC_NONE eval:check_dmarc_none()
priority DMARC_NONE 500
describe DMARC_NONE Dmarc none policy

header DMARC_QUAR eval:check_dmarc_quarantine()
priority DMARC_QUAR 500
describe DMARC_QUAR Dmarc quarantine policy

header DMARC_REJECT eval:check_dmarc_reject()
priority DMARC_REJECT 500
describe DMARC_REJECT Dmarc reject policy

header DMARC_MISSING eval:check_dmarc_missing()
priority DMARC_MISSING 500
describe DMARC_MISSING Missing Dmarc policy
");

%patterns = ();
%anti_patterns = (
    q{ DMARC_NONE } => 'Dmarc none policy',
            );

sarun ("-t < data/nice/dmarc/noneok.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%anti_patterns = ();
%patterns = (
    q{ DMARC_NONE } => 'Dmarc none policy',
            );

sarun ("-t < data/spam/dmarc/noneko.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = ();
%anti_patterns = (
    q{ DMARC_QUAR } => 'Dmarc quarantine policy',
            );

sarun ("-t < data/nice/dmarc/quarok.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%anti_patterns = ();
%patterns = (
    q{ DMARC_QUAR } => 'Dmarc quarantine policy',
            );

sarun ("-t < data/spam/dmarc/quarko.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = ();
%anti_patterns = (
    q{ DMARC_REJECT } => 'Dmarc reject policy',
            );

sarun ("-t < data/nice/dmarc/rejectok.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%anti_patterns = ();
%patterns = (
    q{ DMARC_REJECT } => 'Dmarc reject policy',
            );

sarun ("-t < data/spam/dmarc/rejectko.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = ();
%anti_patterns = (
    q{ DMARC_REJECT } => 'Dmarc reject policy',
            );

sarun ("-t < data/nice/dmarc/strictrejectok.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%anti_patterns = ();
%patterns = (
    q{ DMARC_REJECT } => 'Dmarc reject policy',
            );

sarun ("-t < data/spam/dmarc/strictrejectko.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%anti_patterns = ();
%patterns = (
    q{ DMARC_MISSING } => 'Missing Dmarc policy',
            );

sarun ("-t < data/spam/dmarc/nodmarc.eml", \&patterns_run_cb);
ok_all_patterns();
