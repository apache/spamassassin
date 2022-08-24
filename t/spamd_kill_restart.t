#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_kill_restart");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan tests => 93;

use File::Spec;

# ---------------------------------------------------------------------------

my($pid1, $pid2);

tstprefs("
  use_auto_whitelist 0
");

dbgprint "Starting spamd...\n";
start_spamd("-L");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = read_from_pidfile($spamd_pidfile));
  ok (-e $spamd_pidfile) or warn "$spamd_pidfile is not there before SIGINT";
  ok (!-z $spamd_pidfile) or warn "$spamd_pidfile is empty before SIGINT";
  ok ($pid1 != 0);
  dbgprint "killing spamd at pid $pid1, loop try $retry...\n";

  # now, wait for the PID file to change or disappear; the real order
  # is [SIGINT, unlink, exec, create] but due to race conditions under
  # load we could have missed the unlink, exec, create part.

  dbgprint "Waiting for PID file to change...\n";
  wait_for_file_to_change_or_disappear($spamd_pidfile, 20, sub {
          $pid1 and kill ('INT', $pid1);
        });

  # in the SIGINT case, the file will not change -- it will be unlinked
  ok (!-e $spamd_pidfile);

  # override this so the old logs are still visible and the new
  # spamd will be started even though stop_spamd() was not called
  $spamd_pid = 0;

  dbgprint "starting new spamd, loop try $retry...\n";
  start_spamd("-D -L");

  dbgprint "Waiting for spamd at pid $pid1 to restart...\n";
  wait_for_file_to_appear ($spamd_pidfile, 20);
  ok (-e $spamd_pidfile) or warn "$spamd_pidfile does not exist post restart";
  ok (!-z $spamd_pidfile) or warn "$spamd_pidfile is empty post restart";
  ok ($pid2 = read_from_pidfile($spamd_pidfile));

  dbgprint "Looking for new spamd at pid $pid2...\n";
  ok ($pid2 != 0 and kill (0, $pid2));

  $pid1 = $pid2;
}

  dbgprint "A little time to settle...\n";
  sleep 2;

  dbgprint "Checking GTUBE...\n";
  %patterns = (
    q{ X-Spam-Flag: YES } => 'flag',
    q{ GTUBE }            => 'gtube',
  );
  ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
  ok_all_patterns;


dbgprint "Stopping spamd...\n";
stop_spamd;

