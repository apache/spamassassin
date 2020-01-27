#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dcc");

use constant HAS_DCC => eval { $_ = untaint_cmd("which cdcc"); chomp; -x };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "DCC tests disabled" unless conf_bool('run_dcc_tests');
plan skip_all => "DCC executable not found in path" unless HAS_DCC;
plan tests => 8;

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
ok sarun ("-t -D info -r < data/spam/gtubedcc_crlf.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (

  q{ Detected as bulk mail by DCC }, 'dcc',

);

ok sarun ("-t < data/spam/gtubedcc.eml", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-t < data/spam/gtubedcc_crlf.eml", \&patterns_run_cb);
ok_all_patterns();
