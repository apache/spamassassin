#!/usr/bin/perl -T

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

use lib '.'; use lib 't';
use SATest; sa_t_init("relaycountry");

my $tests = 0;
my %has;
eval { require MaxMind::DB::Reader;   $tests += 2; $has{GEOIP2}  = 1 };
eval { require Geo::IP;               $tests += 2; $has{GEOIP}   = 1 };
eval { require IP::Country::DB_File;  $tests += 2; $has{DB_FILE} = 1 };
eval { require IP::Country::Fast;     $tests += 2; $has{FAST}    = 1 };

use Test::More;

plan skip_all => "No supported GeoDB module installed" unless $tests;
plan tests => $tests;

# ---------------------------------------------------------------------------

if (defined $has{GEOIP2}) {

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        geodb_module GeoIP2
        geodb_search_path data/geodb

        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US }, '',
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

} else {
  warn "skipping MaxMind::DB::Reader (GeoIP2) tests (not installed)\n";
}


if (defined $has{GEOIP}) {

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        geodb_module Geo::IP
        geodb_search_path data/geodb

        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US }, '',
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

} else {
  warn "skipping Geo::IP tests (not installed)\n";
}


if (defined $has{DB_FILE}) {

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        geodb_module DB_File
        geodb_options country:data/geodb/ipcc.db

        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US }, '',
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

} else {
  warn "skipping IP::Country::DB_File tests (not installed)\n";
}


if (defined $has{FAST}) {

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        geodb_module Fast

        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US }, '',
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

} else {
  warn "skipping IP::Country::Fast tests (not installed)\n";
}

