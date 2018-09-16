#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dcc");

use Test::More;
plan skip_all => "DCC tests disabled" unless conf_bool('run_dcc_tests');
plan tests => 4;

diag('Note: Failure may not be an SpamAssassin bug, as DCC tests can fail due to problems with the DCC servers.');


# ---------------------------------------------------------------------------

%patterns = (

  q{ spam reported to DCC }, 'dcc report',

);

tstpre ("

  loadplugin Mail::SpamAssassin::Plugin::DCC
  dcc_timeout 30

");

ok sarun ("-t -D info -r < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (

  q{ Detected as bulk mail by DCC }, 'dcc',

);

ok sarun ("-t < data/spam/gtubedcc.eml", \&patterns_run_cb);
ok_all_patterns();
