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

use constant HAS_GEOIP => eval { require Geo::IP; };
use constant HAS_GEOIP_CONF => eval { Geo::IP->new(GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE); };

use Test::More;

plan skip_all => "Geo::IP not installed" unless HAS_GEOIP;
plan skip_all => "Geo::IP not configured" unless HAS_GEOIP_CONF;

plan tests => 2;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        $default_cf_lines
        country_db_type GeoIP
        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US },
            );

ok sarun ("-t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
