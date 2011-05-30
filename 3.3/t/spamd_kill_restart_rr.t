#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_kill_restart_rr");

use constant TEST_ENABLED => conf_bool('run_long_tests') &&
                                !$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS;

use Test; BEGIN { plan tests => (TEST_ENABLED? 93 : 0) };

use File::Spec;

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

my $pid_file = "log/spamd.pid";
my($pid1, $pid2);

tstlocalrules("
      use_auto_whitelist 0
  ");

dbgprint "Starting spamd...\n";
start_spamd("-L --round-robin -r ${pid_file}");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = read_from_pidfile($pid_file));
  ok (-e $pid_file) or warn "$pid_file is not there before SIGINT";
  ok (!-z $pid_file) or warn "$pid_file is empty before SIGINT";
  ok ($pid1 != 0);
  dbgprint "killing spamd at pid $pid1, loop try $retry...\n";

  # now, wait for the PID file to change or disappear; the real order
  # is [SIGINT, unlink, exec, create] but due to race conditions under
  # load we could have missed the unlink, exec, create part.

  dbgprint "Waiting for PID file to change...\n";
  wait_for_file_to_change_or_disappear($pid_file, 20, sub {
          $pid1 and kill ('INT', $pid1);
        });

  # in the SIGINT case, the file will not change -- it will be unlinked
  ok (!-e $pid_file);

  # override this so the old logs are still visible and the new
  # spamd will be started even though stop_spamd() was not called
  $spamd_pid = 0;

  dbgprint "starting new spamd, loop try $retry...\n";
  my $startat = time;
  start_spamd("-D -L --round-robin -r ${pid_file}");

  dbgprint "Waiting for spamd at pid $pid1 to restart...\n";
  wait_for_file_to_appear ($pid_file, 40);
  ok (-e $pid_file) or warn "$pid_file does not exist post restart; started at $startat, gave up at ".time;

  ok (!-z $pid_file) or warn "$pid_file is empty post restart";
  ok ($pid2 = read_from_pidfile($pid_file));

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


