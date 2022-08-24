#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("askdns");
use version 0.77;

use constant HAS_DKIM_VERIFIER => eval {
  require Mail::DKIM::Verifier;
  version->parse(Mail::DKIM::Verifier->VERSION) >= version->parse(0.31);
};

use Test::More;
plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();

my $tests = 4;
$tests += 3 if (HAS_DKIM_VERIFIER);

plan tests => $tests;

# ---------------------------------------------------------------------------

#
# some DKIM stuff
#

if (HAS_DKIM_VERIFIER) {
  tstlocalrules(q{
    full   DKIM_SIGNED           eval:check_dkim_signed()
    askdns  ASKDNS_DKIM_AUTHORDOMAIN  _AUTHORDOMAIN_.askdnstest.spamassassin.org. A /^127\.0\.0\.8$/
    askdns  ASKDNS_DKIM_DKIMDOMAIN  _DKIMDOMAIN_.askdnstest.spamassassin.org. A /^127\.0\.0\.8$/
    # Bug 7897 - test that meta rules depending on net rules hit
    meta ASKDNS_META_AUTHORDOMAIN ASKDNS_DKIM_AUTHORDOMAIN
  });
  %patterns = (
    q{ ASKDNS_DKIM_AUTHORDOMAIN } => 'ASKDNS_DKIM_AUTHORDOMAIN',
    q{ ASKDNS_DKIM_DKIMDOMAIN } => 'ASKDNS_DKIM_DKIMDOMAIN',
    q{ ASKDNS_META_AUTHORDOMAIN } => 'ASKDNS_META_AUTHORDOMAIN',
  );
  ok sarun ("-t < data/dkim/test-pass-01.msg 2>&1", \&patterns_run_cb);
  ok_all_patterns();
  clear_pattern_counters();
}

#
# TXT
#

tstlocalrules(q{
  askdns  ASKDNS_TXT_SPF spamassassin.org TXT /^v=spf1 -all$/
});
%patterns = (
  q{ ASKDNS_TXT_SPF } => 'ASKDNS_TXT_SPF',
  '[spamassassin.org TXT:v=spf1 -all]' => 'ASKDNS_TXT_SPF_LOG',
);
ok sarun ("-t -D < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

