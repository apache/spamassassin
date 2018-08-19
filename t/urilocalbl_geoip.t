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
use SATest; sa_t_init("urilocalbl");

use constant HAS_GEOIP => eval { require Geo::IP; };
use constant HAS_GEOIP_CONF => eval { Geo::IP->new(GEOIP_MEMORY_CACHE | GEOIP_CHECK_CACHE); };

use Test::More;

plan skip_all => "Geo::IP not installed" unless HAS_GEOIP;
plan skip_all => "Geo::IP not configured" unless HAS_GEOIP_CONF;
plan tests => 3;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::URILocalBL
");

%patterns = (
  q{ X_URIBL_USA } => 'USA',
  q{ X_URIBL_NA } => 'north America',
);

tstlocalrules (q{
  uri_block_cc X_URIBL_USA us
  describe X_URIBL_USA uri located in USA
  
  uri_block_cont X_URIBL_NA na
  describe X_URIBL_NA uri located in north America
});

ok sarun ("-t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
