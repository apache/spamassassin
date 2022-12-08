#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init('podchecker');

use strict;
use warnings;
use Test::More;

plan skip_all => "This test requires Test::Pod" unless (eval { use Test::Pod 1.00; 1} );

all_pod_files_ok("../blib");

