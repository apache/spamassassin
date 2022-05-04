#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("razor2");

use constant HAS_RAZOR2 => eval { require Razor2::Client::Agent; };
use constant HAS_RAZOR2_IDENT => eval { -r $ENV{'HOME'}.'/.razor/identity'; };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Needs Razor2" unless HAS_RAZOR2;
plan skip_all => "Needs Razor2 Identity File Needed. razor-register / razor-admin -register has not been run, or identity file ($ENV{'HOME'}/.razor/identity) is unreadable." unless HAS_RAZOR2_IDENT;
plan tests => 8;

diag('Note: Failures may not be an SpamAssassin bug, as Razor tests can fail due to problems with the Razor servers.');

# ---------------------------------------------------------------------------

tstprefs ("
  full RAZOR2_CHECK	eval:check_razor2()
  tflags RAZOR2_CHECK	net autolearn_body
  dns_available no
  use_razor2 1
  score RAZOR2_CHECK 3.3
");

#RAZOR2 file contains a test string supplied by Razor tech support

#TESTING FOR SPAM
%patterns = (
  q{ 3.3 RAZOR2_CHECK }, 'spam',
);

sarun ("-t < data/spam/razor2", \&patterns_run_cb);
ok_all_patterns();
# Same with fork
sarun ("--cf='razor_fork 1' -t < data/spam/razor2", \&patterns_run_cb);
ok_all_patterns();

#TESTING FOR HAM
%patterns = (
  'Connection established', 'connection',
  'razor2: part=0 engine=8 contested=0 confidence=0', 'result',
);
%anti_patterns = (
  q{ 3.3 RAZOR2_CHECK }, 'nonspam',
);

sarun ("-D razor2 -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
# same with fork
sarun ("-D razor2 --cf='razor_fork 1' -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

