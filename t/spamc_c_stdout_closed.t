#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_c_stdout_closed");
use Test; BEGIN { plan tests => (!$SKIP_SPAMD_TESTS? 2 : 0) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (
);

start_spamd("-L");

my @warnings;
sub myrun {
  open (OLDOUT, ">&STDOUT");
  close STDOUT;

  # redirect warnings to (the real) STDOUT
  local($SIG{'__WARN__'}) = sub { print OLDOUT @_ };

  my $ret = spamcrun (@_);

  open (STDOUT, ">&OLDOUT");

  return $ret;
}

ok (!myrun ("-c < data/spam/001", \&patterns_run_cb));
ok (myrun ("-c < data/nice/001", \&patterns_run_cb));
stop_spamd();


