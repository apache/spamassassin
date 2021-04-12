#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("urilocalbl");

$tests = 0;
eval { require MaxMind::DB::Reader;   $tests += 8; $has{GEOIP2}  = 1 };
eval { require Geo::IP;               $tests += 8; $has{GEOIP}   = 1 };
eval { require IP::Country::DB_File;  $tests += 8; $has{DB_FILE} = 1 };
eval { require IP::Country::Fast;     $tests += 8; $has{FAST}    = 1 };

use Test::More;

plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "No supported GeoDB module installed" unless $tests;

$net = conf_bool('run_net_tests');
$ipv6 = $net && conf_bool('run_ipv6_dns_tests');

$tests *= 2 if $net;
$tests += 1 if $ipv6 && defined $has{GEOIP2};
$tests += 1 if $ipv6 && defined $has{DB_FILE};

plan tests => $tests;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::URILocalBL
");

%patterns_ipv4 = (
  q{ X_URIBL_USA } => 'USA',
  q{ X_URIBL_FINEG } => 'except Finland',
  q{ X_URIBL_NA } => 'north America',
  q{ X_URIBL_EUNEG } => 'except Europe',
  q{ X_URIBL_CIDR1 } => 'our TestIP1',
  q{ X_URIBL_CIDR2 } => 'our TestIP2',
  q{ X_URIBL_CIDR3 } => 'our TestIP3',
);

%patterns_ipv6 = (
  q{ X_URIBL_CIDR4 } => 'our TestIP4',
);

my $rules = "

  dns_query_restriction allow google.com

  uri_block_cc X_URIBL_USA us
  describe X_URIBL_USA uri located in USA
  
  uri_block_cc X_URIBL_FINEG !fi
  describe X_URIBL_FINEG uri located anywhere except Finland

  uri_block_cont X_URIBL_NA na
  describe X_URIBL_NA uri located in north America

  uri_block_cont X_URIBL_EUNEG !eu !af
  describe X_URIBL_EUNEG uri located anywhere except Europe/Africa

  uri_block_cidr X_URIBL_CIDR1 8.0.0.0/8 1.2.3.4
  describe X_URIBL_CIDR1 uri is our TestIP1

  uri_block_cidr X_URIBL_CIDR2 8.8.8.8
  describe X_URIBL_CIDR2 uri is our TestIP2

  uri_block_cidr X_URIBL_CIDR3 8.8.8.0/24
  describe X_URIBL_CIDR3 uri is our TestIP3
";

my $rules_ipv6 = "

  uri_block_cidr X_URIBL_CIDR4 2001:4860:4860::8888
  describe X_URIBL_CIDR4 uri is our TestIP4
";

if (defined $has{GEOIP2}) {
  my $lrules = "
    geodb_module GeoIP2
    geodb_search_path data/geodb
    $rules
  ";
  tstlocalrules ($lrules);
  %patterns = %patterns_ipv4;
  ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  if ($net) {
    $lrules .= $rules_ipv6 if $ipv6;
    tstlocalrules ($lrules);
    if ($ipv6) {
      %patterns = (%patterns_ipv4, %patterns_ipv6);
    } else {
      %patterns = %patterns_ipv4;
      warn "skipping IPv6 DNS lookup tests (run_ipv6_dns_tests=n)\n";
    }
    ok sarun ("-t < data/spam/urilocalbl_net.eml", \&patterns_run_cb);
    ok_all_patterns();
    clear_pattern_counters();
  } else {
    warn "skipping DNS lookup tests (run_net_tests=n)\n";
  }
} else {
  warn "skipping MaxMind::DB::Reader (GeoIP2) tests (not installed)\n";
}


if (defined $has{GEOIP}) {
  tstlocalrules ("
    geodb_module Geo::IP
    geodb_search_path data/geodb
    $rules
  ");
  %patterns = %patterns_ipv4;
  ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  if ($net) {
    ok sarun ("-t < data/spam/urilocalbl_net.eml", \&patterns_run_cb);
    ok_all_patterns();
    clear_pattern_counters();
  } else {
    warn "skipping DNS lookup tests (run_net_tests=n)\n";
  }
} else {
  warn "skipping Geo::IP tests (not installed)\n";
}


if (defined $has{DB_FILE}) {
  my $lrules = "
    geodb_module DB_File
    geodb_options country:data/geodb/ipcc.db
    $rules
  ";
  tstlocalrules ($lrules);
  %patterns = %patterns_ipv4;
  ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  if ($net) {
    $lrules .= $rules_ipv6 if $ipv6;
    tstlocalrules ($lrules);
    if ($ipv6) {
      %patterns = (%patterns_ipv4, %patterns_ipv6);
    } else {
      %patterns = %patterns_ipv4;
      warn "skipping IPv6 DNS lookup tests (run_ipv6_dns_tests=n)\n";
    }
    ok sarun ("-t < data/spam/urilocalbl_net.eml", \&patterns_run_cb);
    ok_all_patterns();
    clear_pattern_counters();
  } else {
    warn "skipping DNS lookup tests (run_net_tests=n)\n";
  }
} else {
  warn "skipping IP::Country::DB_File tests (not installed)\n";
}


if (defined $has{FAST}) {
  tstlocalrules ("
    geodb_module Fast
    $rules
  ");
  %patterns = %patterns_ipv4;
  ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();

  if ($net) {
    ok sarun ("-t < data/spam/urilocalbl_net.eml", \&patterns_run_cb);
    ok_all_patterns();
    clear_pattern_counters();
  } else {
    warn "skipping DNS lookup tests (run_net_tests=n)\n";
  }
} else {
  warn "skipping IP::Country::Fast tests (not installed)\n";
}


