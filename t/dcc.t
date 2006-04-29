#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dcc");

use constant TEST_ENABLED => conf_bool('run_dcc_tests');

use Test;

BEGIN {
  plan tests => (TEST_ENABLED ? 4 : 0),
  onfail => sub {
    warn "\n\nNote: this may not be an SpamAssassin bug, as DCC tests can" .
	"\nfail due to problems with the DCC servers.\n\n";
  }
};

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

%patterns = (
	q{ spam reported to DCC }, 'dcc report',
            );

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::DCC
");

ok sarun ("-t -D info -r < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
	q{ Listed in DCC }, 'dcc',
            );

ok sarun ("-t < data/spam/gtubedcc.eml", \&patterns_run_cb);
ok_all_patterns();
