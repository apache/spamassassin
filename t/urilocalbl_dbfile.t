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

use constant HAS_COUNTRY_DB_FILE => eval { require IP::Country::DB_File; };

use Test::More;

plan skip_all => "IP::Country::DB_File not installed" unless HAS_COUNTRY_DB_FILE;
#plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan tests => 3;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::URILocalBL
");

%patterns = (
  q{ X_URIBL_USA } => 'USA',
  q{ X_URIBL_NA } => 'north America',
);

tstlocalrules ("
  geodb_module DB_File
  geodb_options country:data/geodb/ipcc.db

  uri_block_cc X_URIBL_USA us
  describe X_URIBL_USA uri located in USA
  
  uri_block_cont X_URIBL_NA na
  describe X_URIBL_NA uri located in north America
");

ok sarun ("-D -L -t < data/spam/relayUS.eml", \&patterns_run_cb);
ok_all_patterns();
