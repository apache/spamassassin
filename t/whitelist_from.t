#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_from");

use Test::More;
plan skip_all => 'Long running tests disabled' unless conf_bool('run_long_tests');
plan tests => 32;

# ---------------------------------------------------------------------------

disable_compat "welcomelist_blocklist";

tstprefs ("
  header USER_IN_WELCOMELIST		eval:check_from_in_welcomelist()
  tflags USER_IN_WELCOMELIST		userconf nice noautolearn
  header USER_IN_DEF_WELCOMELIST	eval:check_from_in_default_welcomelist()
  tflags USER_IN_DEF_WELCOMELIST	userconf nice noautolearn
  meta USER_IN_WHITELIST		(USER_IN_WELCOMELIST)
  tflags USER_IN_WHITELIST		userconf nice noautolearn
  score USER_IN_WHITELIST		-100
  score USER_IN_WELCOMELIST		-0.01
  meta USER_IN_DEF_WHITELIST		(USER_IN_DEF_WELCOMELIST)
  tflags USER_IN_DEF_WHITELIST	userconf nice noautolearn
  score USER_IN_DEF_WHITELIST		-15
  score USER_IN_DEF_WELCOMELIST	-0.01
  def_whitelist_from_rcvd *\@paypal.com paypal.com
  def_whitelist_from_rcvd *\@paypal.com ebay.com
  def_whitelist_from_rcvd mumble\@example.com example.com
  whitelist_from_rcvd foo\@example.com spamassassin.org
  whitelist_from_rcvd foo\@example.com example.com
  whitelist_from_rcvd bar\@example.com example.com
  whitelist_allows_relays bar\@example.com
  whitelist_from baz\@example.com
  whitelist_from bam\@example.com
  unwhitelist_from bam\@example.com
  unwhitelist_from_rcvd mumble\@example.com
");

# tests 1 - 4 does whitelist_from work?
%patterns = (
  q{ -100 USER_IN_WHITELIST }, '',
);

%anti_patterns = (
  q{ FORGED_IN_WHITELIST }, '',
  q{ USER_IN_DEF_WHITELIST }, '',
  q{ FORGED_IN_DEF_WHITELIST }, '',
);
sarun ("-L -t < data/nice/008", \&patterns_run_cb);
ok_all_patterns();

# tests 5 - 8 does whitelist_from_rcvd work?
sarun ("-L -t < data/nice/009", \&patterns_run_cb);
ok_all_patterns();

# tests 9 - 12 second relay specified for same addr in whitelist_from_rcvd
sarun ("-L -t < data/nice/010", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ -15 USER_IN_DEF_WHITELIST }, '',
);

%anti_patterns = (
  q{ USER_IN_WHITELIST }, '',
  q{ FORGED_IN_WHITELIST }, '',
  q{ FORGED_IN_DEF_WHITELIST }, '',
);

# tests 13 - 16 does def_whitelist_from_rcvd work?
sarun ("-L -t < data/nice/011", \&patterns_run_cb);
ok_all_patterns();

# tests 17 - 20 second relay specified for same addr in def_whitelist_from_rcvd
sarun ("-L -t < data/nice/012", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();

%anti_patterns = (
  q{ USER_IN_WHITELIST }, '',
  q{ FORGED_IN_WHITELIST }, '',
  q{ USER_IN_DEF_WHITELIST }, '',
  q{ FORGED_IN_DEF_WHITELIST }, '',
);
# tests 21 - 24 does whitelist_allows_relays suppress the forged rule without
#  putting the address on the whitelist?
sarun ("-L -t < data/nice/013", \&patterns_run_cb);
ok_all_patterns();

# tests 25 - 28 does unwhitelist_from work?
sarun ("-L -t < data/nice/014", \&patterns_run_cb);
ok_all_patterns();

# tests 29 - 32 does unwhitelist_from_rcvd work?
sarun ("-L -t < data/nice/015", \&patterns_run_cb);
ok_all_patterns();

