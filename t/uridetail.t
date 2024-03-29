#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("uridetail");

use Test::More;

$tests = 2;
plan tests => $tests;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::URIDetail
");

my $rules = "
  uri_detail X_URIDETAIL cleaned =~ /8\.8\.8\.8/ text =~ /Dns/
  describe X_URIDETAIL Google Dns server
";

%patterns = (
  q{ X_URIDETAIL } => 'Google Dns',
);

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
clear_pattern_counters();

%anti_patterns = %patterns;
ok sarun ("-L -t < data/spam/006", \&patterns_run_cb);
