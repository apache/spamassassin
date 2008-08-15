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
   body FOO2 /click here and e= nter your/i

   # should not be found, not a dup (/i)
   body FOO3 /click here and e= nter your/

   # should not be found, not dup since different type
   rawbody RAWFOO /click here and e= nter your/i

   header HDR1 Subject =~ /stained/
   header HDR2 Subject =~ /stained/

   # should not be merged -- eval rules (bug 5959)
   header HDREVAL1 eval:check_test_plugin()
   header HDREVAL2 eval:check_test_plugin()

   meta META1 (1)
   meta META2 (META1 && META3)
   meta META3 (1)
   priority META3 -500

});

sarun ("-L -t -D < data/spam/006 2>&1", \&patterns_run_cb);
ok ok_all_patterns();
