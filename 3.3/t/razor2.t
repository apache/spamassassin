#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("razor2");

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_RAZOR2 => eval { require Razor2::Client::Agent; };

use Test;

BEGIN {
  plan tests => ((TEST_ENABLED && HAS_RAZOR2) ? 2 : 0),
  onfail => sub {
    warn "\n\nNote: this may not be an SpamAssassin bug, as Razor tests can" .
	"\nfail due to problems with the Razor servers.\n\n";
  }
};

exit unless (TEST_ENABLED && HAS_RAZOR2);

# ---------------------------------------------------------------------------

my $ident = $ENV{'HOME'}.'/.razor/identity';
if (! -r $ident) {
  $razor_not_available = "razor-register / razor-admin -register has not been run, or $ident is unreadable.";
  warn "$razor_not_available\n";
}

if (! $razor_not_available) {
  system ("razor-report < data/spam/001");
  if (($? >> 8) != 0) {
    warn "'razor-report < data/spam/001' failed. This may cause this test to fail.\n";
  }
}

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Razor2
");


#TESTING FOR SPAM
%patterns = (
        q{ Listed in Razor2 }, 'spam',
            );

sarun ("-t < data/spam/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);

#TESTING FOR HAM
%patterns = ();
%anti_patterns = (
	q{ Listed in Razor2 }, 'nonspam',
		 );

sarun ("-t < data/nice/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);
