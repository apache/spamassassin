#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("shortcircuit_before_dns");

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely" unless can_use_net_dns_safely();
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (
 q{ 1.0 SC_TEST_NO_DNS } => '',
);

%anti_patterns = (
 q{ DNSBL_TEST_TOP } => '',
 'dns: bgsend' => '',
);


my $conf = "

  loadplugin Mail::SpamAssassin::Plugin::Shortcircuit

  rbl_timeout 60

  clear_trusted_networks
  trusted_networks 127.
  trusted_networks 10.
  trusted_networks 150.51.53.1

  header DNSBL_TEST_TOP eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
  tflags DNSBL_TEST_TOP net

  # No DNS lookups are supposed to start before priority -100,
  # so our shortcircuit is at -101 ..

  body SC_TEST_NO_DNS /./
  priority SC_TEST_NO_DNS -101
  shortcircuit SC_TEST_NO_DNS on

";

tstprefs($conf);

# we need -D output for patterns
sarun ("-D dns,async -t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

#
# Try again, this time we want to see DNS
#

# Should see DNS at -100
$conf =~ s/SC_TEST_NO_DNS -101/SC_TEST_NO_DNS -100/;

%patterns = (
 q{ 1.0 SC_TEST_NO_DNS } => '',
 'dns: bgsend' => '',
);
%anti_patterns = ();

tstprefs($conf);
sarun ("-D dns -t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

