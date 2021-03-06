#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("basic_meta2");

use Test::More;
plan tests => 15;

# ---------------------------------------------------------------------------

%patterns = (
  q{ TEST_FOO_1 }     => '',
  q{ TEST_FOO_2 }     => '',
  q{ TEST_FOO_3 }     => '',
  q{ TEST_META_1 }    => '',
  q{ TEST_META_3 }    => '',
  q{ TEST_META_5 }    => '',
  q{ TEST_META_7 }    => '',
  q{ TEST_META_A }    => '',
  q{ TEST_META_B }    => '',
);

%anti_patterns = (
  q{ TEST_NEG_1 }     => '',
  q{ TEST_META_2 }    => '',
  q{ TEST_META_4 }    => '',
  q{ TEST_META_6 }    => '',
  q{ TEST_META_8 }    => '',
  q{ TEST_META_9 }    => '',
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

   ##
   ## Unrun rule dependencies (Bug 7735)
   ##

   # Non-existing rule
   # Should not hit, meta is evaled twice: (!0) && (!1)
   meta TEST_META_2 !NONEXISTINGRULE
   # Should hit, meta is evaled twice: (!0 || 0) && (!1 || 1)
   meta TEST_META_3 !NONEXISTINGRULE || NONEXISTINGRULE

   # Disabled rule, same as above
   body TEST_DISABLED /a/
   score TEST_DISABLED 0
   # Should not hit
   meta TEST_META_4 !TEST_DISABLED
   # Should hit
   meta TEST_META_5 !TEST_DISABLED || TEST_DISABLED

   # Unrun rule (due to local tests only), same as above
   askdns TEST_DISABLED2 spamassassin.org TXT /./
   # Should not hit
   meta TEST_META_6 !TEST_DISABLED2
   # Should hit
   meta TEST_META_7 !TEST_DISABLED2 || TEST_DISABLED2

   # Should not hit
   meta TEST_META_8 __FOO_1 + NONEXISTINGRULE == 2
   # Should not hit
   meta TEST_META_9 __FOO_1 + NONEXISTINGRULE + __FOO_2 == 2
   # Should hit (both eval checks are true thanks to >1)
   meta TEST_META_A __FOO_1 + NONEXISTINGRULE + __FOO_2 > 1

   # local_tests_only
   meta TEST_META_B NONEXISTINGRULE || local_tests_only

});

sarun ("-L -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

