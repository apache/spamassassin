#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dnsbl_sc_meta");

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely" unless can_use_net_dns_safely();
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (
 q{ DNSBL_TEST_TOP } => 'DNSBL_TEST_TOP',
 q{ SC_DNSBL } => 'SC_DNSBL',
);

%anti_patterns = (
);

tstprefs("

  loadplugin Mail::SpamAssassin::Plugin::Shortcircuit

  rbl_timeout 60

  clear_trusted_networks
  trusted_networks 127.
  trusted_networks 10.
  trusted_networks 150.51.53.1

  header DNSBL_TEST_TOP	eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
  tflags DNSBL_TEST_TOP	net
  meta SC_DNSBL (DNSBL_TEST_TOP)
  priority SC_DNSBL -700
  shortcircuit SC_DNSBL on

");

sarun ("-t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

