#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

my $razor_not_available = 0;

eval {
	require Razor::Client;
};

if ($@) {
	$razor_not_available = "Razor1 is not installed.";
}


%patterns = (

q{ Listed in Razor v1 }, 'spam',

);

sarun ("-t < data/spam/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);

%patterns = ();
%anti_patterns = (

q{ Listed in Razor v1 }, 'nonspam',

);

sarun ("-t < data/nice/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);
