#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_hup");
use File::Spec;

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan tests => 110;

# ---------------------------------------------------------------------------

my($pid1, $pid2);

dbgprint "Starting spamd...\n";
start_spamd("-L");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = read_from_pidfile($spamd_pidfile));
  ok (-e $spamd_pidfile) or warn "$spamd_pidfile is not there before SIGHUP";
  ok (!-z $spamd_pidfile) or warn "$spamd_pidfile is empty before SIGHUP";
  ok ($pid1 != 0);
  dbgprint "HUPing spamd at pid $pid1, loop try $retry...\n";

  # now, wait for the PID file to change or disappear; the real order
  # is [SIGHUP, unlink, exec, create] but due to race conditions under
  # load we could have missed the unlink, exec, create part.

  dbgprint "Waiting for PID file to change...\n";
  wait_for_file_to_change_or_disappear($spamd_pidfile, 20, sub {
          $pid1 and kill ('HUP', $pid1);
        });

  dbgprint "Waiting for spamd at pid $pid1 to restart...\n";
    # 26 iterations is 98 seconds, RPi ARM6 takes about 66 seconds
  wait_for_file_to_appear ($spamd_pidfile, 26);

  ok (-e $spamd_pidfile) or warn "$spamd_pidfile does not exist post restart";
  ok (!-z $spamd_pidfile) or warn "$spamd_pidfile is empty post restart";

  ok ($pid2 = read_from_pidfile($spamd_pidfile));
  dbgprint "Looking for new spamd at pid $pid2...\n";
  #ok ($pid2 != $pid1);     # no longer guaranteed with SIGHUP
  ok ($pid2 != 0 and kill (0, $pid2));

  dbgprint "A little time to settle...\n";
  sleep 2;

  dbgprint "Checking GTUBE...\n";
  %patterns = (
    q{ X-Spam-Flag: YES } => 'flag',
    q{ GTUBE }            => 'gtube',
  );
  ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
  ok_all_patterns;

  $pid1 = $pid2;
}


dbgprint "Stopping spamd...\n";
stop_spamd;

