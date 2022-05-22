#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("regexp_named_capture");

use Test::More;
plan tests => 12;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 TEST_CAPTURE_1 } => '',
  q{ 1.0 TEST_CAPTURE_2 } => '',
  q{ 1.0 TEST_CAPTURE_3 } => '',
  q{ 1.0 TEST_CAPTURE_4 } => '',
  q{ 1.0 TEST_CAPTURE_5 } => '',
  q{ 1.0 TEST_CAPTURE_6 } => '',
  q{ 1.0 TEST_CAPTURE_7 } => '',
  q{/tag TESTCAP1 is now ready, value: Ximian\n/} => '',
  q{/tag TESTCAP2 is now ready, value: Ximian\n/} => '',
  q{/tag TESTCAP3 is now ready, value: gnome.org\n/} => '',
  q{/tag TESTCAP4 is now ready, value: milkplus\n/} => '',
  q{/tag TESTCAP5 is now ready, value: release\n/} => '',
);
%anti_patterns = ();

tstlocalrules (q{
   body TEST_CAPTURE_1 /release of (?<TESTCAP1>\w+)/
   rawbody TEST_CAPTURE_2 /release of (?<TESTCAP2>\w+)/
   uri TEST_CAPTURE_3 /ftp\.(?<TESTCAP3>[\w.]+)/
   header TEST_CAPTURE_4 Message-ID =~ /@(?<TESTCAP4>\w+)/
   full TEST_CAPTURE_5 /X-Spam-Status.* preview (?<TESTCAP5>\w+)/s

   # Use some captured tag
   body TEST_CAPTURE_6 m,www\.%{TESTCAP1}\.,i

   # We can also use common tags like HEADER()
   body TEST_CAPTURE_7 m{www\.%{HEADER(From:addr:domain)}/}
});

sarun ("-D check -L -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

