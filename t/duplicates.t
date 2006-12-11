#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("duplicates");
use Test; BEGIN { plan tests => 16 };

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
  q{ ran body rule FOO1 ======> got hit } => '',
  q{ ran header rule HDR1 ======> got hit } => '',
  q{ rules: FOO1 merged duplicates: FOO2 } => '',
  q{ rules: HDR1 merged duplicates: HDR2 } => '',

);

%anti_patterns = (

  q{ FOO3 }     => '',
  q{ RAWFOO }   => '',
  q{ ran body rule FOO2 ======> got hit } => '',
  q{ ran header rule HDR2 ======> got hit } => '',

);

tstprefs (qq{

   $default_cf_lines

   body FOO1 /click here and e= nter your/i
   body FOO2 /click here and e= nter your/i

   # should not be found, not a dup (/i)
   body FOO3 /click here and e= nter your/

   # should not be found, not dup since different type
   rawbody RAWFOO /click here and e= nter your/i

   header HDR1 Subject =~ /stained/
   header HDR2 Subject =~ /stained/

   meta META1 (1)
   meta META2 (META1 && META3)
   meta META3 (1)
   priority META3 -500

});

sarun ("-L -t -D < data/spam/006 2>&1", \&patterns_run_cb);
ok ok_all_patterns();
