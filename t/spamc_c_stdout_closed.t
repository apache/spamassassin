#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_c_stdout_closed");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");

sub myrun {
  open (OLDOUT, ">&STDOUT");
  close STDOUT;
  my $ret = spamcrun (@_);
  open (STDOUT, ">&OLDOUT");
  $ret;
}

ok (!myrun ("-c < data/spam/001", \&patterns_run_cb));
ok (myrun ("-c < data/nice/001", \&patterns_run_cb));
stop_spamd();


