#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("phishing");

use Test::More;
plan tests => 4;

my $conf = <<'END';
  loadplugin Mail::SpamAssassin::Plugin::Phishing

  phishing_openphish_feed data/phishing/openphish-feed.txt
  phishing_phishtank_feed data/phishing/phishtank-feed.csv

  body     URI_PHISHING   eval:check_phishing()
  describe URI_PHISHING   Url match phishing in feed
END

tstprefs("
	$conf
");

%patterns_openphish = (
  q{ URI_PHISHING } => 'OpenPhish',
);

%patterns_phishtank = (
  q{ URI_PHISHING } => 'PhishTank',
);

%patterns = %patterns_openphish;
sarun ("-L -t < data/spam/phishing_openphish.eml", \&patterns_run_cb);
ok_all_patterns();

%patterns = %patterns_phishtank;
sarun ("-L -t < data/spam/phishing_phishtank.eml", \&patterns_run_cb);
ok_all_patterns();

tstprefs(
	$conf . "phishing_uri_noparam 1"
);

%patterns = %patterns_openphish;
sarun ("-L -t < data/spam/phishing_openphish.eml", \&patterns_run_cb);
ok_all_patterns();

%patterns = %patterns_phishtank;
sarun ("-L -t < data/spam/phishing_phishtank.eml", \&patterns_run_cb);
ok_all_patterns();
