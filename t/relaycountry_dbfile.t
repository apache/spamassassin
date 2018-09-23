#!/usr/bin/perl

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

use constant HAS_COUNTRY_DB_FILE => eval { require IP::Country::DB_File; };

use Test::More;

plan skip_all => "IP::Country::DB_File not installed" unless HAS_COUNTRY_DB_FILE;
plan tests => 2;

# ---------------------------------------------------------------------------

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
        q{ X-Spam-Relay-Country: US },
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
