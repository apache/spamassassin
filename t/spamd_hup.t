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

print "[".time."] Starting spamd...\n";
start_spamd("-L -r ${pid_file}");
sleep 1;

for $retry (0 .. 9) {
  ok ($pid1 = get_pid());
  print "[".time."] HUPing spamd at pid $pid1, loop try $retry...\n";
  ok (-e $pid_file) or warn "$pid_file is not there before SIGHUP";
  ok (!-z $pid_file) or warn "$pid_file is empty before SIGHUP";

  my $lastmod = (-M $pid_file);
  ok ($pid1 != 0 and kill ('HUP', $pid1));

  # now, wait for the PID file to change or disappear; the real order
  # is [SIGHUP, unlink, exec, create] but due to race conditions under
  # load we could have missed the unlink, exec, create part.

  print "[".time."] Waiting for PID file to change...\n";
  {
    my $timeout = 20;
    my $wait = 0;
    my $newlastmod;
    do {
      sleep (int($wait++ / 4) + 1) if $timeout > 0;
      $timeout--;
      $newlastmod = (-M $pid_file);
    } while((-e $pid_file) && defined($newlastmod) &&
                  $newlastmod == $lastmod && $timeout);
  }

  print "[".time."] Waiting for spamd at pid $pid1 to restart...\n";
  # note that the wait period increases the longer it takes,
  # 20 retries works out to a total of 60 seconds
  {
    my $timeout = 20;
    my $wait = 0;
    do {
      sleep (int($wait++ / 4) + 1) if $timeout > 0;
      $timeout--;
    } while((!-e $pid_file || -z $pid_file) && $timeout);
  }
  ok (-e $pid_file) or warn "$pid_file does not exist post restart";
  ok (!-z $pid_file) or warn "$pid_file is empty post restart";

  ok ($pid2 = get_pid($pid1));
  print "[".time."] Looking for new spamd at pid $pid2...\n";
  #ok ($pid2 != $pid1);     # no longer guaranteed with SIGHUP
  ok ($pid2 != 0 and kill (0, $pid2));

  print "[".time."] A little time to settle...\n";
  sleep 2;

  print "[".time."] Checking GTUBE...\n";
  %patterns = (
    q{ X-Spam-Flag: YES } => 'flag',
    q{ GTUBE }            => 'gtube',
  );
  ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
  ok_all_patterns;

  $pid1 = $pid2;
}


print "[".time."] Stopping spamd...\n";
stop_spamd;


sub get_pid {
  my($opid, $npid) = (@_, 0, 0);

  my $retries = 5;
  do {
    if ($retries != 5) {
      sleep 1;
      warn "retrying read of pidfile $pid_file, due to short/nonexistent read: ".
            "retry $retries";
    }
    $retries--;

    if (!open (PID, "<".$pid_file)) {
      warn "Could not open pid file ${pid_file}: $!\n";     # and retry
      next;
    }

    $npid = <PID>;
    if (defined $npid) { chomp $npid; }
    close(PID);

    if (!$npid || $npid < 1) {
      warn "failed to read anything sensible from $pid_file, retrying read";
      $npid = 0;
      next;
    }
    if (!kill (0, $npid)) {
      warn "failed to kill -0 $npid, retrying read";
      $npid = 0;
    }

  } until ($npid > 1 or $retries == 0);

  return $npid;
}

