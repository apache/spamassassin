#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("zz_cleanup");
use Test; BEGIN { plan tests => 1 };

use File::Path;

rmtree ("log");
ok (1);
