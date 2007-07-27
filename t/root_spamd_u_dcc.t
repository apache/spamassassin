#!/usr/bin/perl
#
# test for http://issues.apache.org/SpamAssassin/show_bug.cgi?id=5574#c12 .
# run with:   sudo prove -v t/root_spamd*

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_u_dcc");
use Test;

use constant TEST_ENABLED => conf_bool('run_root_tests');
use constant DCC_TEST_ENABLED => conf_bool('run_dcc_tests');
use constant IS_ROOT => eval { ($> == 0); };
use constant RUN_TESTS => (TEST_ENABLED && DCC_TEST_ENABLED && IS_ROOT);

BEGIN { plan tests => (RUN_TESTS ? 9 : 0) };
exit unless RUN_TESTS;

# ---------------------------------------------------------------------------

%patterns = (
        q{ spam reported to DCC }, 'dcc report',
            );

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::DCC
");

ok sarun ("-t -D info -r < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
# ok_all_patterns();

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ Listed in DCC }, 'dcc',

);

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

$SIG{ALRM} = sub { stop_spamd(); die "timed out"; };
alarm 60;
ok(start_spamd("-c -H"));
alarm 0;

$SIG{ALRM} = sub { stop_spamd(); die "timed out"; };
alarm 10;
ok(spamcrun("< data/spam/gtubedcc.eml", \&patterns_run_cb));
alarm 0;

ok_all_patterns();
ok(stop_spamd());

