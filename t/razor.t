#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => -e 't/do_razor' ? 2 : 0 };

exit unless -e 't/do_razor';

# ---------------------------------------------------------------------------

my $razor_not_available = 0;

eval {
	require Razor::Client;
};

if ($@) {
	$razor_not_available = "Razor1 is not installed.";
}



%patterns = (

q{ Listed in Razor1 }, 'spam',

);

sarun ("-t < data/spam/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);

%patterns = ();
%anti_patterns = (

q{ Listed in Razor1 }, 'nonspam',

);

sarun ("-t < data/nice/001", \&patterns_run_cb);
skip_all_patterns($razor_not_available);
