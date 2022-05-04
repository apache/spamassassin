#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dcc");

use constant HAS_DCC => eval { $_ = untaint_cmd("which cdcc"); chomp; -x };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "DCC tests disabled" unless conf_bool('run_dcc_tests');
plan skip_all => "DCC executable not found in path" unless HAS_DCC;
plan tests => 16;

diag('Note: Failure may not be an SpamAssassin bug, as DCC tests can fail due to problems with the DCC servers.');


# ---------------------------------------------------------------------------

%patterns = (
  q{ spam reported to DCC }, 'dcc report',
);

tstprefs ("
  full     DCC_CHECK  eval:check_dcc()
  tflags   DCC_CHECK  net autolearn_body
  priority DCC_CHECK  10
  dns_available no
  use_dcc 1
  meta X_META_POS DCC_CHECK
  meta X_META_NEG !DCC_CHECK
  score DCC_CHECK 3.3
  score X_META_POS 3.3
  score X_META_NEG 3.3
");

ok sarun ("-t -D info -r < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-t -D info -r < data/spam/gtubedcc_crlf.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ 3.3 DCC_CHECK }, 'dcc',
  q{ 3.3 X_META_POS }, 'pos',
);
%anti_patterns = (
  q{ 3.3 X_META_NEG }, 'neg',
);

ok sarun ("-t < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-t < data/spam/gtubedcc_crlf.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

# Local only, metas should not hit as no queries are made
%patterns = (
);
%anti_patterns = (
  q{ 3.3 DCC_CHECK }, 'dcc',
  q{ 3.3 X_META_POS }, 'pos',
  q{ 3.3 X_META_NEG }, 'neg',
);
ok sarun ("-t -L < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

