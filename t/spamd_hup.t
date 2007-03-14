#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_hup");
use constant TEST_ENABLED => !$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS;

use Test; BEGIN { plan tests => (TEST_ENABLED? 110 : 0) };

use File::Spec;

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

my $pid_file = "log/spamd.pid";
my($pid1, $pid2);

dbgprint "Starting spamd...\n";
start_spamd("-L -r ${pid_file}");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = read_from_pidfile($pid_file));
  ok (-e $pid_file) or warn "$pid_file is not there before SIGHUP";
  ok (!-z $pid_file) or warn "$pid_file is empty before SIGHUP";
  ok ($pid1 != 0);
  dbgprint "HUPing spamd at pid $pid1, loop try $retry...\n";

  # now, wait for the PID file to change or disappear; the real order
  # is [SIGHUP, unlink, exec, create] but due to race conditions under
  # load we could have missed the unlink, exec, create part.

  dbgprint "Waiting for PID file to change...\n";
  wait_for_file_to_change_or_disappear($pid_file, 20, sub {
          $pid1 and kill ('HUP', $pid1);
        });

  dbgprint "Waiting for spamd at pid $pid1 to restart...\n";
  wait_for_file_to_appear ($pid_file, 20);
  ok (-e $pid_file) or warn "$pid_file does not exist post restart";
  ok (!-z $pid_file) or warn "$pid_file is empty post restart";

  ok ($pid2 = read_from_pidfile($pid_file));
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

