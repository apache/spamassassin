#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init('podchecker');

use Test::More;

eval "use Test::Pod 1.00";

plan skip_all => "This test requires Test::Pod"  if $@;

all_pod_files_ok("../blib");

