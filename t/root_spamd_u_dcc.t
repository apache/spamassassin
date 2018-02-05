#!/usr/bin/perl
#
# test for http://issues.apache.org/SpamAssassin/show_bug.cgi?id=5574#c12 .
# run with:   sudo prove -v t/root_spamd*

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_u_dcc");

use Test::More;
plan skip_all => "root tests disabled" unless conf_bool('run_root_tests');
plan skip_all => "DCC tests disabled" unless conf_bool('run_dcc_tests');
plan skip_all => "not running tests as root" unless eval { ($> == 0); };
plan tests => 23;

# ---------------------------------------------------------------------------

%patterns = (
        q{ spam reported to DCC }, 'dcc report',
            );

tstpre ("

  loadplugin Mail::SpamAssassin::Plugin::DCC
  dcc_timeout 30

");

ok sarun ("-t -D info -r < data/spam/gtubedcc.eml 2>&1", \&patterns_run_cb);
# ok_all_patterns();

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',

);

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

$SIG{ALRM} = sub { stop_spamd(); die "timed out"; };
alarm 60;
ok(start_spamd("-c -H -m1"));
alarm 0;

# run a few times to ensure that the child can process more than
# one message successfully. do not bother looking for the dcc
# result; we just want to ensure that the check did not cause
# the spamd kids to get hung
for my $try (1 .. 5) {
  $SIG{ALRM} = sub { stop_spamd(); die "timed out"; };
  alarm 10;
  ok(spamcrun("< data/spam/gtubedcc.eml", \&patterns_run_cb));
  alarm 0;
  ok_all_patterns();
}

ok(stop_spamd());

