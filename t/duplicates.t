#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("duplicates");
use Test; BEGIN { plan tests => 21 };

$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (

  q{ FOO1 }     => '',  # use default names
  q{ FOO2 }     => '',
  q{ HDR1 }     => '',
  q{ HDR2 }     => '',
  q{ META1 }     => '',
  q{ META2 }     => '',
  q{ META3 }     => '',
  q{ HDREVAL1 }     => '',
  q{ HDREVAL2 }     => '',
  q{ ran body rule FOO1 ======> got hit } => '',
  q{ ran header rule HDR1 ======> got hit } => '',
  q{ rules: FOO1 merged duplicates: FOO2 } => '',
  q{ rules: HDR1 merged duplicates: HDR2 } => '',
  q{ rules: META3 merged duplicates: META1 } => '',
  q{ ran eval rule HDREVAL1 ======> got hit } => '',
  q{ ran eval rule HDREVAL2 ======> got hit } => '',
);

%anti_patterns = (

  q{ FOO3 }     => '',
  q{ RAWFOO }   => '',
  q{ ran body rule FOO2 ======> got hit } => '',
  q{ ran header rule HDR2 ======> got hit } => '',

);

tstprefs (qq{

   $default_cf_lines

   loadplugin Mail::SpamAssassin::Plugin::Test

   body FOO1 /click here and e= nter your/i
   describe FOO1 Test rule
   body FOO2 /click here and e= nter your/i
   describe FOO2 Test rule

   # should not be found, not a dup (/i)
   body FOO3 /click here and e= nter your/
   describe FOO3 Test rule

   # should not be found, not dup since different type
   rawbody RAWFOO /click here and e= nter your/i
   describe RAWFOO Test rule

   header HDR1 Subject =~ /stained/
   describe HDR1 Test rule
   header HDR2 Subject =~ /stained/
   describe HDR2 Test rule

   # should not be merged -- eval rules (bug 5959)
   header HDREVAL1 eval:check_test_plugin() 
   describe HDREVAL1 Test rule
   header HDREVAL2 eval:check_test_plugin()
   describe HDREVAL2 Test rule

   meta META1 (1)
   describe META1 Test rule
   meta META2 (META1 && META3)
   describe META2 Test rule
   meta META3 (1)
   priority META3 -500
   describe META3 Test rule

});

sarun ("-L -t -D < data/spam/006 2>&1", \&patterns_run_cb);
ok ok_all_patterns();
