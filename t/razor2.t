#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("razor2");
use constant TEST_ENABLED => (-e 't/do_razor' || -e 'do_razor');
use Test; BEGIN { plan tests => (TEST_ENABLED ? 2 : 0),
        onfail => sub {
          warn "\n\nNote: this may not be an SpamAssassin bug, as Razor tests can\n".
                "fail due to problems with the Razor servers.\n\n";
        }
};

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

my $razor_not_available = 0;

eval {
	require Razor2::Client::Agent;
};

if ($@) {
	$razor_not_available = "Razor2 is not installed.";
}

my $ident = $ENV{'HOME'}.'/.razor/identity';
if (!-r $ident) {
	$razor_not_available = "razor-register has not been run, or $ident is unreadable.";
}


%patterns = (

q{ Listed in Razor2 }, 'spam',

);

if (!$razor_not_available) {
  system ("razor-report < data/spam/001");
  if (($? >> 8) != 0) {
    warn "'razor-report < data/spam/001' failed. This may cause this test to fail.\n";
  }
}

sarun ("-t < data/spam/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);

%patterns = ();
%anti_patterns = (

q{ Listed in Razor2 }, 'nonspam',

);

sarun ("-t < data/nice/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);

