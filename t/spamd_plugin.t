#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_plugin");

use constant numtests => 6;
use Test; plan tests => (($SKIP_SPAMD_TESTS || $RUNNING_ON_WINDOWS || $SKIP_SETUID_NOBODY_TESTS) ?
                        0 : numtests);

exit unless !($SKIP_SPAMD_TESTS || $RUNNING_ON_WINDOWS || $SKIP_SETUID_NOBODY_TESTS);

# ---------------------------------------------------------------------------

tstlocalrules ('
        loadplugin myTestPlugin ../../data/testplugin.pm
        header MY_TEST_PLUGIN eval:check_test_plugin()
');

# create a shared counter file for this test
use Cwd;
$ENV{'SPAMD_PLUGIN_COUNTER_FILE'} = getcwd."/log/spamd_plugin.tmp";
open(COUNTER,">log/spamd_plugin.tmp");
print COUNTER "0";
close COUNTER;
chmod (0666, "log/spamd_plugin.tmp");

my $sockpath = mk_safe_tmpdir()."/spamd.sock";
start_spamd("-D -L --socketpath=$sockpath");

%patterns = (
  q{ test: called myTestPlugin, round 1 }, 'called1'
);
ok (spamcrun ("-U $sockpath < data/spam/001", \&patterns_run_cb));

checkfile($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ called myTestPlugin, round 2 }, 'called2'
);
ok (spamcrun ("-U $sockpath < data/nice/001", \&patterns_run_cb));
checkfile($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ called myTestPlugin, round 3 }, 'called3'
);
ok (spamcrun ("-U $sockpath < data/nice/001", \&patterns_run_cb));
checkfile($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

stop_spamd();
cleanup_safe_tmpdir();

