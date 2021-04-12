#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("basic_meta2");

use Test::More;
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (

  q{ TEST_FOO_1 }     => '',
  q{ TEST_FOO_2 }     => '',
  q{ TEST_FOO_3 }     => '',
  q{ TEST_META_1 }     => '',

);

%anti_patterns = (

  q{ TEST_NEG_1 }     => '',

);

tstlocalrules (qq{

   body __FOO_1 /a/
   body __FOO_2 /b/
   body __FOO_33 /c/
   body __FOO_4 /xyzzynotfound/

   meta TEST_FOO_1 __FOO_1 + __FOO_2 + __FOO_33 + __FOO_4 == 3
   meta TEST_FOO_2 rules_matching(__FOO_*) == 3
   meta TEST_FOO_3 __FOO_4 + rules_matching(__FOO_?) == 2

   meta TEST_NEG_1 __FOO_1 + __FOO_2 == 1

   meta TEST_META_1 (TEST_FOO_1 + TEST_FOO_2 + TEST_NEG_1) == 2

});

sarun ("-L -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

