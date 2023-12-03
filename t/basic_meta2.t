#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("basic_meta2");

use Test::More;

# run many times to catch some random natured failures
my $iterations = 5;
plan tests => 24 * $iterations;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 TEST_FOO_1 }     => '',
  q{ 1.0 TEST_FOO_2 }     => '',
  q{ 1.0 TEST_FOO_3 }     => '',
  q{ 1.0 TEST_META_1 }    => '',
  q{ 1.0 TEST_META_2 }    => '',
  q{ 1.0 TEST_META_3 }    => '',
  q{ 1.0 TEST_META_4 }    => '',
  q{ 1.0 TEST_META_5 }    => '',
  q{ 1.0 TEST_META_6 }    => '',
  q{ 1.0 TEST_META_7 }    => '',
  q{ 1.0 TEST_META_9 }    => '',
  q{ 1.0 TEST_META_A }    => '',
  q{ 1.0 TEST_META_B }    => '',
  q{ 1.0 TEST_META_C }    => '',
  q{ 1.0 TEST_META_D }    => '',
  q{ 1.0 TEST_META_E }    => '',
  q{ 1.0 TEST_META_F }    => '',
  q{ 1.0 TEST_META_G }    => '',
  q{ 1.0 TEST_META_H }    => '',
  q{ 1.0 TEST_META_I }    => '',
  q{ 1.0 TEST_META_J }    => '',
  q{ 1.0 TEST_META_K }    => '',
);

%anti_patterns = (
  q{ TEST_NEG_1 }     => '',
  q{ TEST_META_8 }    => '',
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

   # Non-existing rule, should hit as !0
   meta TEST_META_2 !NONEXISTINGRULE
   # Should hit as !0 || 0
   meta TEST_META_3 !NONEXISTINGRULE || NONEXISTINGRULE

   # Disabled rule, same as above
   body TEST_DISABLED /a/
   score TEST_DISABLED 0
   # Should hit as !0
   meta TEST_META_4 !TEST_DISABLED
   # Should hit as !0 || 0
   meta TEST_META_5 !TEST_DISABLED || TEST_DISABLED

   # Unrun rule (due to local tests only), same as above
   askdns TEST_DISABLED2 spamassassin.org TXT /./
   # Should hit as !0
   meta TEST_META_6 !TEST_DISABLED2
   # Should hit as !0 || 0
   meta TEST_META_7 !TEST_DISABLED2 || TEST_DISABLED2

   # Other way of "disabling" a rule, with meta 0.
   meta TEST_DISABLED3 0
   # Should hit
   meta TEST_META_I !TEST_DISABLED3
   # Should hit
   meta TEST_META_J !TEST_DISABLED3 && __FOO_1

   # Should not hit
   meta TEST_META_8 __FOO_1 + NONEXISTINGRULE == 2
   # Should hit as 1 + 0 + 1 == 2
   meta TEST_META_9 __FOO_1 + NONEXISTINGRULE + __FOO_2 == 2
   # Should hit as above
   meta TEST_META_A __FOO_1 + NONEXISTINGRULE + __FOO_2 > 1

   # local_tests_only
   meta TEST_META_B NONEXISTINGRULE || local_tests_only

   # complex metas with different priorities
   body __BAR_5 /a/
   priority __BAR_5 -1000
   body __BAR_6 /b/
   priority __BAR_6 0
   body __BAR_7 /c/
   priority __BAR_7 1000
   meta TEST_META_C __BAR_5 && __BAR_6 && __BAR_7
   meta TEST_META_D __BAR_5 && __BAR_6 && TEST_META_C
   priority TEST_META_D -2000
   meta TEST_META_E __BAR_6 && __BAR_7 && TEST_META_D
   meta TEST_META_F __BAR_5 && __BAR_7 && TEST_META_E
   priority TEST_META_F 2000
   meta TEST_META_G TEST_META_C && TEST_META_D && TEST_META_E && TEST_META_F

   # metas without dependencies
   meta __TEST_META_H1  6
   meta __TEST_META_H2  2
   meta __TEST_META_H3  1
   meta TEST_META_H   (__TEST_META_H1 > 2) && (__TEST_META_H2 > 1) && __TEST_META_H3

   # bug 7735, comment 87
   meta __TEST_META_K  (1 || TEST_DISABLED || TEST_DISABLED2 || TEST_DISABLED3)
   meta TEST_META_K  __TEST_META_K
});

for (1 .. $iterations) {
  sarun ("-L -t < data/nice/001 2>&1", \&patterns_run_cb);
  ok_all_patterns();
}

