#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("regexp_named_capture");

use Test::More;
plan tests => 10;

# ---------------------------------------------------------------------------

%patterns = (
  q{ TEST_CAPTURE_1 } => '',
  q{ TEST_CAPTURE_2 } => '',
  q{ TEST_CAPTURE_3 } => '',
  q{ TEST_CAPTURE_4 } => '',
  q{ TEST_CAPTURE_5 } => '',
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
});

sarun ("-D check -L -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

