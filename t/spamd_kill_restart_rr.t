#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_kill_restart_rr");
use constant TEST_ENABLED => !$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS;

use Test; BEGIN { plan tests => (TEST_ENABLED? 63 : 0) };

use File::Spec;

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

my $pid_file = "log/spamd.pid";

my($pid1, $pid2);

sub dbgprint { print STDERR "[".time()."] ".$_[0]; }

dbgprint "Starting spamd...\n";
start_spamd("-L --round-robin -r ${pid_file}");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = get_pid());
  dbgprint "killing spamd at pid $pid1, loop try $retry...\n";
  ok ($pid1 != 0 and kill ('INT', $pid1));

# ensure we wait for the exit to happen; under load, we could
# still be waiting at this point for the spamd to receive the
# signal

  dbgprint "Waiting for spamd at pid $pid1 to exit...\n";
  my $timeout = 20;
  do {
    # no increase in the timeout here
    sleep (1) if $timeout > 0;
    $timeout--;
  } while(-e $pid_file && $timeout);
  ok (!-e $pid_file);

# override these so the old logs are still visible and the new
# spamd will be started even though stop_spamd() was not called
  $spamd_pid = 0;
  $testname = "spamd_kill_restart_rr_retry_".$retry;

  dbgprint "starting new spamd, loop try $retry...\n";
  start_spamd("-D -L --round-robin -r ${pid_file}");
  ok ($pid1 = get_pid());

  dbgprint "Waiting for spamd at pid $pid1 to restart...\n";
# note that the wait period increases the longer it takes,
# 20 retries works out to a total of 60 seconds
  my $timeout = 20;
  my $wait = 0;
  do {
    sleep (int($wait++ / 4) + 1) if $timeout > 0;
    $timeout--;
  } while(!-e $pid_file && $timeout);
  ok (-e $pid_file);

  ok ($pid2 = get_pid($pid1));
  dbgprint "Looking for new spamd at pid $pid2...\n";
  ok ($pid2 != 0 and kill (0, $pid2));

  $pid1 = $pid2;
}

  dbgprint "Checking GTUBE...\n";
  %patterns = (
    q{ X-Spam-Flag: YES } => 'flag',
    q{ GTUBE }            => 'gtube',
  );
  ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
  ok_all_patterns;


dbgprint "Stopping spamd...\n";
stop_spamd;


sub get_pid {
  my($opid, $npid) = (@_, 0, 0);
  #my $timeout = 5;
  #do {
  #  sleep 1;
  #  $timeout--;

    if (open (PID, "< ${pid_file}")) {
      $npid = <PID>;
      chomp $npid;
      close(PID);
    } else {
      die "Could not open pid file ${pid_file}: $!\n";
    }
  #} until ($npid != $opid or $timeout == 0);
  return $npid;
}

