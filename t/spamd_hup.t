#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_hup");
use constant TEST_ENABLED => !$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS && ($] >= 5.006);

use Test; BEGIN { plan tests => (TEST_ENABLED? 8 : 0) };

use File::Spec;

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

my $pid_file = "log/spamd.pid";

my($pid1, $pid2);

print "Starting spamd...\n";
start_spamd("-L -r ${pid_file}");
sleep 1;

ok ($pid1 = get_pid());
print "HUPing spamd at pid $pid1...\n";
ok ($pid1 != 0 and kill ('HUP', $pid1));

print "Waiting for spamd at pid $pid1 to restart...\n";
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
print "Looking for new spamd at pid $pid2...\n";
#ok ($pid2 != $pid1);
ok ($pid2 != 0 and kill (0, $pid2));

print "Checking GTUBE...\n";
%patterns = (
  q{ X-Spam-Flag: YES } => 'flag',
  q{ GTUBE }            => 'gtube',
);
ok (spamcrun ("< data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns;


print "Stopping spamd...\n";
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
      print "Could not open pid file ${pid_file}: $!\n";
    }
  #} until ($npid != $opid or $timeout == 0);
  return $npid;
}
