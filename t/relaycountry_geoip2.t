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

use constant HAS_GEOIP2 => eval { require GeoIP2::Database::Reader; };

# TODO: get the list from RelayCountry.pm / geoip2_default_db_path
use constant HAS_GEOIP2_DB => eval {
  -f "/usr/local/share/GeoIP/GeoIP2-Country.mmdb" or
  -f "/usr/share/GeoIP/GeoIP2-Country.mmdb" or
  -f "/var/lib/GeoIP/GeoIP2-Country.mmdb" or
  -f "/usr/local/share/GeoIP/GeoLite2-Country.mmdb" or
  -f "/usr/share/GeoIP/GeoLite2-Country.mmdb" or
  -f "/var/lib/GeoIP/GeoLite2-Country.mmdb"
};

use Test::More;

plan skip_all => "GeoIP2::Database::Reader not installed" unless HAS_GEOIP2;
plan skip_all => "GeoIP2 database not found from default locations" unless HAS_GEOIP2_DB;

plan tests => 2;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::RelayCountry
");

tstprefs ("
        dns_available no
        country_db_type GeoIP2
        add_header all Relay-Country _RELAYCOUNTRY_
        ");

# Check for country of gmail.com mail server
%patterns = (
        q{ X-Spam-Relay-Country: US }, '',
            );

ok sarun ("-L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
