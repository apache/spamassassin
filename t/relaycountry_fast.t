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

use constant HAS_COUNTRY_FAST => eval { require IP::Country::Fast; };

use Test::More;

plan skip_all => "IP::Country::Fast not installed" unless HAS_COUNTRY_FAST;
plan tests => 2;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        $default_cf_lines
        country_db_type Fast
        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US },
            );

ok sarun ("-t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
