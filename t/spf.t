#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spf");
use Test::More;

use constant HAS_MAILSPF => eval { require Mail::SPF; };

plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Need Mail::SPF" unless HAS_MAILSPF;
plan skip_all => "Can't use Net::DNS Safely" unless can_use_net_dns_safely();

plan tests => 72;

# ---------------------------------------------------------------------------

disable_compat "welcomelist_blocklist";

# ensure all rules will fire
tstlocalrules ("
  header SPF_PASS		eval:check_for_spf_pass()
  header SPF_NEUTRAL		eval:check_for_spf_neutral()
  header SPF_FAIL		eval:check_for_spf_fail()
  header SPF_SOFTFAIL		eval:check_for_spf_softfail()
  header SPF_HELO_PASS		eval:check_for_spf_helo_pass()
  header SPF_HELO_NEUTRAL	eval:check_for_spf_helo_neutral()
  header SPF_HELO_FAIL		eval:check_for_spf_helo_fail()
  header SPF_HELO_SOFTFAIL	eval:check_for_spf_helo_softfail()
  tflags SPF_PASS		nice userconf net
  tflags SPF_HELO_PASS		nice userconf net
  tflags SPF_NEUTRAL		net
  tflags SPF_FAIL	        net
  tflags SPF_SOFTFAIL		net
  tflags SPF_HELO_NEUTRAL       net
  tflags SPF_HELO_FAIL		net
  tflags SPF_HELO_SOFTFAIL	net
  header USER_IN_SPF_WELCOMELIST eval:check_for_spf_welcomelist_from()
  tflags USER_IN_SPF_WELCOMELIST userconf nice noautolearn net
  header USER_IN_DEF_SPF_WL	eval:check_for_def_spf_welcomelist_from()
  tflags USER_IN_DEF_SPF_WL	userconf nice noautolearn net
  meta USER_IN_SPF_WHITELIST	(USER_IN_SPF_WELCOMELIST)
  tflags USER_IN_SPF_WHITELIST	userconf nice noautolearn net
  score SPF_FAIL 0.001
  score SPF_HELO_FAIL 0.001
  score SPF_HELO_NEUTRAL 0.001
  score SPF_HELO_SOFTFAIL 0.001
  score SPF_NEUTRAL 0.001
  score SPF_SOFTFAIL 0.001
  score SPF_PASS -0.001
  score SPF_HELO_PASS -0.001
  score USER_IN_DEF_SPF_WL -0.001
  score USER_IN_SPF_WELCOMELIST -0.001
  score USER_IN_SPF_WHITELIST -0.001
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ 0.0 SPF_NEUTRAL }, 'neutral',
  q{ 0.0 SPF_HELO_NEUTRAL }, 'helo_neutral',
);

sarun ("-t < data/spam/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ 0.0 SPF_SOFTFAIL }, 'softfail',
  q{ 0.0 SPF_HELO_SOFTFAIL }, 'helo_softfail',
);

sarun ("-t < data/spam/spf2", \&patterns_run_cb);
ok_all_patterns();
%patterns = (
  q{ 0.0 SPF_FAIL }, 'fail',
  q{ 0.0 SPF_HELO_FAIL }, 'helo_fail',
);

sarun ("-t < data/spam/spf3", \&patterns_run_cb);
ok_all_patterns();


# Test using an assortment of trusted and internal network definitions

# 9-10: Trusted networks contain first header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.157
  always_trust_envelope_sender 1
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 11-12: Internal networks contain first header.
#	   Trusted networks not defined.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  internal_networks 65.214.43.157
  always_trust_envelope_sender 1
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 13-14: Internal networks contain first header.
#	   Trusted networks contain some other IP.
#        jm: commented; this is now an error condition.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 1.2.3.4
  internal_networks 65.214.43.157
  always_trust_envelope_sender 1
");

%patterns = (
  q{ 0.0 SPF_HELO_NEUTRAL }, 'helo_neutral',
  q{ 0.0 SPF_NEUTRAL }, 'neutral',
);

if (0) {
  sarun ("-t < data/nice/spf2", \&patterns_run_cb);
  ok_all_patterns();
} else {
  ok(1);        # skip the tests
  ok(1);
}


# 15-16: Trusted+Internal networks contain first header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.157
  internal_networks 65.214.43.157
  always_trust_envelope_sender 1
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 17-18: Trusted networks contain first and second header.
#	   Internal networks contain first header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.157 64.142.3.173
  internal_networks 65.214.43.157
  always_trust_envelope_sender 1
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 19-26: Trusted networks contain first and second header.
#	   Internal networks contain first and second header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.157 64.142.3.173
  internal_networks 65.214.43.157 64.142.3.173
  always_trust_envelope_sender 1
");

%anti_patterns = (
  q{ SPF_HELO_PASS }, 'helo_pass',
  q{ SPF_HELO_FAIL }, 'helo_fail',
  q{ SPF_HELO_SOFTFAIL }, 'helo_softfail',
  q{ SPF_HELO_NEUTRAL }, 'helo_neutral',
  q{ SPF_PASS }, 'pass',
  q{ SPF_FAIL }, 'fail',
  q{ SPF_SOFTFAIL }, 'softfail',
  q{ SPF_NEUTRAL }, 'neutral',
);
%patterns = ();

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 27-28: Trusted networks contain first header.
#	   Internal networks contain first and second header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.157
  internal_networks 65.214.43.157 64.142.3.173
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf2", \&patterns_run_cb);
ok_all_patterns();


# 29-30: Trusted networks contain top 5 headers.
#	   Internal networks contain first header.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173 65.214.43.155 65.214.43.156 65.214.43.157
  internal_networks 65.214.43.158
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf3", \&patterns_run_cb);
ok_all_patterns();


# 31-32: Trusted networks contain top 5 headers.
#	   Internal networks contain top 2 headers.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173 65.214.43.155 65.214.43.156 65.214.43.157
  internal_networks 65.214.43.158 64.142.3.173
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_FAIL }, 'helo_fail',
  q{ 0.0 SPF_FAIL }, 'fail',
);

sarun ("-t < data/nice/spf3", \&patterns_run_cb);
ok_all_patterns();


# 33-34: Trusted networks contain top 5 headers.
#	   Internal networks contain top 3 headers.

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173 65.214.43.155 65.214.43.156 65.214.43.157
  internal_networks 65.214.43.158 64.142.3.173 65.214.43.155
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_SOFTFAIL }, 'helo_softfail',
  q{ 0.0 SPF_SOFTFAIL }, 'softfail',
);

sarun ("-t < data/nice/spf3", \&patterns_run_cb);
ok_all_patterns();


# 35-36: Trusted networks contain top 5 headers.
#	   Internal networks contain top 4 headers.	

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173 65.214.43.155 65.214.43.156 65.214.43.157
  internal_networks 65.214.43.158 64.142.3.173 65.214.43.155 65.214.43.156
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_NEUTRAL }, 'helo_neutral',
  q{ 0.0 SPF_NEUTRAL }, 'neutral',
);

sarun ("-t < data/nice/spf3", \&patterns_run_cb);
ok_all_patterns();


# 37-40: same as test 1-2 with some spf whitelisting added

tstprefs("
  whitelist_from_spf newsalerts-noreply\@dnsbltest.spamassassin.org
  def_whitelist_from_spf *\@dnsbltest.spamassassin.org
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
  q{ -0.0 USER_IN_SPF_WHITELIST }, 'spf_whitelist',
  q{ -0.0 USER_IN_DEF_SPF_WL }, 'default_spf_whitelist',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();


# 41-44: same as test 1-2 with some spf whitelist entries that don't match

tstprefs("
  whitelist_from_spf *\@example.com
  def_whitelist_from_spf nothere\@dnsbltest.spamassassin.org
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

%anti_patterns = (
  q{ USER_IN_SPF_WHITELIST }, 'spf_whitelist',
  q{ USER_IN_DEF_SPF_WL }, 'default_spf_whitelist',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

# clear these out before we loop
%anti_patterns = ();
%patterns = ();


# 45-48: same as test 37-40 with whitelist_auth added

tstprefs("
  whitelist_auth newsalerts-noreply\@dnsbltest.spamassassin.org
  def_whitelist_auth *\@dnsbltest.spamassassin.org
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
  q{ -0.0 USER_IN_SPF_WHITELIST }, 'spf_whitelist',
  q{ -0.0 USER_IN_DEF_SPF_WL }, 'default_spf_whitelist',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();


# test usage of Received-SPF headers added by internal relays
# the Received-SPF headers shouldn't be used in this test

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158
  internal_networks 65.214.43.158
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf3-received-spf", \&patterns_run_cb);
ok_all_patterns();
# Test same with nonfolded headers
sarun ("-t < data/nice/spf4-received-spf-nofold", \&patterns_run_cb);
ok_all_patterns();
# Test same with crlf line endings
sarun ("-t < data/nice/spf5-received-spf-crlf", \&patterns_run_cb);
ok_all_patterns();
# Test same with crlf line endings (bug 7785)
sarun ("-t < data/nice/spf6-received-spf-crlf2", \&patterns_run_cb);
ok_all_patterns();


# test usage of Received-SPF headers added by internal relays
# the Received-SPF headers shouldn't be used in this test

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173
  internal_networks 65.214.43.158 64.142.3.173
  always_trust_envelope_sender 1
  ignore_received_spf_header 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_FAIL }, 'helo_fail_ignore_header',
  q{ 0.0 SPF_FAIL }, 'fail_ignore_header',
);

sarun ("-t < data/nice/spf3-received-spf", \&patterns_run_cb);
ok_all_patterns();
# Test same with nonfolded headers
sarun ("-t < data/nice/spf4-received-spf-nofold", \&patterns_run_cb);
ok_all_patterns();


# test usage of Received-SPF headers added by internal relays
# the bottom 2 Received-SPF headers should be used in this test

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173
  internal_networks 65.214.43.158 64.142.3.173
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_SOFTFAIL }, 'helo_softfail_from_header',
  q{ 0.0 SPF_NEUTRAL }, 'neutral_from_header',
);

sarun ("-t < data/nice/spf3-received-spf", \&patterns_run_cb);
ok_all_patterns();
# Test same with nonfolded headers
sarun ("-t < data/nice/spf4-received-spf-nofold", \&patterns_run_cb);
ok_all_patterns();


# test usage of Received-SPF headers added by internal relays
# the top 2 Received-SPF headers should be used in this test

tstprefs("
  clear_trusted_networks
  clear_internal_networks
  trusted_networks 65.214.43.158 64.142.3.173
  internal_networks 65.214.43.158 64.142.3.173
  use_newest_received_spf_header 1
  always_trust_envelope_sender 1
");

%anti_patterns = ();
%patterns = (
  q{ 0.0 SPF_HELO_SOFTFAIL }, 'helo_softfail_from_header',
  q{ 0.0 SPF_FAIL }, 'fail_from_header',
);

sarun ("-t < data/nice/spf3-received-spf", \&patterns_run_cb);
ok_all_patterns();
# Test same with nonfolded headers
sarun ("-t < data/nice/spf4-received-spf-nofold", \&patterns_run_cb);
ok_all_patterns();


# test unwhitelist_auth and unwhitelist_from_spf

tstprefs("
  whitelist_auth newsalerts-noreply\@dnsbltest.spamassassin.org
  def_whitelist_auth newsalerts-noreply\@dnsbltest.spamassassin.org
  unwhitelist_auth newsalerts-noreply\@dnsbltest.spamassassin.org

  whitelist_from_spf *\@dnsbltest.spamassassin.org
  def_whitelist_from_spf *\@dnsbltest.spamassassin.org
  unwhitelist_from_spf *\@dnsbltest.spamassassin.org
");

%patterns = (
  q{ -0.0 SPF_HELO_PASS }, 'helo_pass',
  q{ -0.0 SPF_PASS }, 'pass',
);

%anti_patterns = (
  q{ USER_IN_SPF_WHITELIST }, 'spf_whitelist',
  q{ USER_IN_DEF_SPF_WL }, 'default_spf_whitelist',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

