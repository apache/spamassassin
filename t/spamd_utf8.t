#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_utf8");
my $am_running;
my $testlocale;

use Test; BEGIN {
  $testlocale = 'en_US.UTF-8';

  my $havelocale = 1;
  open (IN, "LANG=$testlocale perl -e 'exit 0' 2>&1 |");
  while (<IN>) {
    /Please check that your locale settings/ and ($havelocale = 0);
  }
  close IN;

  $am_running = (!$SKIP_SPAMD_TESTS && $havelocale);
  plan tests => ($am_running ? 3 : 0);
};

exit unless $am_running;
$ENV{'LANG'} = $testlocale;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

ok (sdrun ("-L", "< data/spam/008", \&patterns_run_cb));
ok_all_patterns();
exit;

# ---------------------------------------------------------------------------
