#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("razor2");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

my $razor_not_available = 0;

eval {
	require Razor2::Client::Agent;
};

if ($@) {
	$razor_not_available = "Razor 2 is not installed.";
}



%patterns = (

q{ Listed in Razor }, 'spam',

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

q{ Listed in Razor }, 'nonspam',

);

sarun ("-t < data/nice/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);
