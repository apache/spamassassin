#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("zz_cleanup");
use Test; BEGIN { plan tests => 1 };

use File::Path;

# jm: off! we want to keep the logs around in case something failed,
# so we can see what it was. esp. important in case of intermittent
# failures.
# rmtree ("log");

ok (1);
