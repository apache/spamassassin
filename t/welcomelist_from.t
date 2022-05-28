#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("welcomelist_from");

use Test::More;
plan skip_all => 'Long running tests disabled' unless conf_bool('run_long_tests');
plan tests => 32;

# ---------------------------------------------------------------------------

tstprefs ("
  header USER_IN_WELCOMELIST		eval:check_from_in_welcomelist()
  tflags USER_IN_WELCOMELIST		userconf nice noautolearn
  score USER_IN_WELCOMELIST		-100
  header USER_IN_DEF_WELCOMELIST	eval:check_from_in_default_welcomelist()
  tflags USER_IN_DEF_WELCOMELIST	userconf nice noautolearn
  score USER_IN_DEF_WELCOMELIST		-15
  def_welcomelist_from_rcvd *\@paypal.com paypal.com
  def_welcomelist_from_rcvd *\@paypal.com ebay.com
  def_welcomelist_from_rcvd mumble\@example.com example.com
  welcomelist_from_rcvd foo\@example.com spamassassin.org
  welcomelist_from_rcvd foo\@example.com example.com
  welcomelist_from_rcvd bar\@example.com example.com
  welcomelist_allows_relays bar\@example.com
  welcomelist_from baz\@example.com
  welcomelist_from bam\@example.com
  unwelcomelist_from bam\@example.com
  unwelcomelist_from_rcvd mumble\@example.com
");

# tests 1 - 4 does welcomelist_from work?
%patterns = (
  q{ -100 USER_IN_WELCOMELIST }, '',
);

%anti_patterns = (
  q{ FORGED_IN_WELCOMELIST }, '',
  q{ USER_IN_DEF_WELCOMELIST }, '',
  q{ FORGED_IN_DEF_WELCOMELIST }, '',
);
sarun ("-L -t < data/nice/008", \&patterns_run_cb);
ok_all_patterns();

# tests 5 - 8 does welcomelist_from_rcvd work?
sarun ("-L -t < data/nice/009", \&patterns_run_cb);
ok_all_patterns();

# tests 9 - 12 second relay specified for same addr in welcomelist_from_rcvd
sarun ("-L -t < data/nice/010", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ -15 USER_IN_DEF_WELCOMELIST }, '',
);

%anti_patterns = (
  q{ USER_IN_WELCOMELIST }, '',
  q{ FORGED_IN_WELCOMELIST }, '',
  q{ FORGED_IN_DEF_WELCOMELIST }, '',
);

# tests 13 - 16 does def_welcomelist_from_rcvd work?
sarun ("-L -t < data/nice/011", \&patterns_run_cb);
ok_all_patterns();

# tests 17 - 20 second relay specified for same addr in def_welcomelist_from_rcvd
sarun ("-L -t < data/nice/012", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();

%anti_patterns = (
  q{ USER_IN_WELCOMELIST }, '',
  q{ FORGED_IN_WELCOMELIST }, '',
  q{ USER_IN_DEF_WELCOMELIST }, '',
  q{ FORGED_IN_DEF_WELCOMELIST }, '',
);
# tests 21 - 24 does welcomelist_allows_relays suppress the forged rule without
#  putting the address on the welcomelist?
sarun ("-L -t < data/nice/013", \&patterns_run_cb);
ok_all_patterns();

# tests 25 - 28 does unwelcomelist_from work?
sarun ("-L -t < data/nice/014", \&patterns_run_cb);
ok_all_patterns();

# tests 29 - 32 does unwelcomelist_from_rcvd work?
sarun ("-L -t < data/nice/015", \&patterns_run_cb);
ok_all_patterns();

