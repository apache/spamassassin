#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("regexp_named_capture");

use Test::More;
plan tests => 14;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 TEST_CAPTURE_1 } => '',
  q{ 1.0 TEST_CAPTURE_2 } => '',
  q{ 1.0 TEST_CAPTURE_3 } => '',
  q{ 1.0 TEST_CAPTURE_4 } => '',
  q{ 1.0 TEST_CAPTURE_5 } => '',
  q{ 1.0 TEST_CAPTURE_6 } => '',
  q{ 1.0 TEST_CAPTURE_7 } => '',
  qr/tag TESTCAP1 is now ready, value: Ximian\n/ => '',
  qr/tag TESTCAP2 is now ready, value: Ximian\n/ => '',
  qr/tag TESTCAP3 is now ready, value: gnome\.org\n/ => '',
  qr/tag TESTCAP4 is now ready, value: milkplus\n/ => '',
  qr/tag TESTCAP5 is now ready, value: release\n/ => '',
);
%anti_patterns = (
  q{ warn: } => '',
  q{ 1.0 TEST_CAPTURE_8 } => '',
);

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

   # Should not hit
   body TEST_CAPTURE_8 m,www\.\%{TESTCAP1}\.,i
});

sarun ("-D check,config -L -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

