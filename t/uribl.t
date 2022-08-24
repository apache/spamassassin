#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("uribl");

use Test::More;
plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();

# run many times to catch some random natured failures
my $iterations = 5;
plan tests => 10 * $iterations;

# ---------------------------------------------------------------------------

%patterns = (
 q{ 1.0 X_URIBL_A } => '',
 q{ 1.0 X_URIBL_B } => '',
 q{ 1.0 X_URIBL_NS } => '',
 q{ 1.0 X_URIBL_DOMSONLY } => '',
 q{ 1.0 META_URIBL_A } => '',
 q{ 1.0 META_URIBL_B } => '',
 q{ 1.0 META_URIBL_NS } => '',
 q{ 1.0 X_URIBL_NOTRIM } => '',
);

%anti_patterns = (
 q{ X_URIBL_FULL_NS } => '',
);

tstlocalrules(q{

  rbl_timeout 30

  urirhssub  X_URIBL_A  dnsbltest.spamassassin.org.    A 2
  body       X_URIBL_A  eval:check_uridnsbl('X_URIBL_A')
  tflags     X_URIBL_A  net

  urirhssub  X_URIBL_B  dnsbltest.spamassassin.org.    A 4
  body       X_URIBL_B  eval:check_uridnsbl('X_URIBL_B')
  tflags     X_URIBL_B  net

  urinsrhssub X_URIBL_NS  dnsbltest.spamassassin.org.  A 8
  body       X_URIBL_NS  eval:check_uridnsbl('X_URIBL_NS')
  tflags     X_URIBL_NS  net

  urifullnsrhssub X_URIBL_FULL_NS  dnsbltest.spamassassin.org.  A 8
  body       X_URIBL_FULL_NS  eval:check_uridnsbl('X_URIBL_FULL_NS')
  tflags     X_URIBL_FULL_NS  net

  urirhssub  X_URIBL_DOMSONLY  dnsbltest.spamassassin.org.    A 2
  body       X_URIBL_DOMSONLY  eval:check_uridnsbl('X_URIBL_DOMSONLY')
  tflags     X_URIBL_DOMSONLY  net domains_only

  add_header all RBL _RBL_

  # Bug 7897 - test that meta rules depending on net rules hit
  meta META_URIBL_A X_URIBL_A
  # It also needs to hit even if priority is lower than dnsbl (-100)
  meta META_URIBL_B X_URIBL_B
  priority META_URIBL_B -500
  # Or super high
  meta META_URIBL_NS X_URIBL_NS
  priority META_URIBL_NS 2000
  priority X_URIBL_NS 2000

  # Bug 7835 - tflags notrim
  urirhssub  X_URIBL_NOTRIM  dnsbltest.spamassassin.org.    A 16
  body       X_URIBL_NOTRIM  eval:check_uridnsbl('X_URIBL_NOTRIM')
  tflags     X_URIBL_NOTRIM  net domains_only notrim

});

for (1 .. $iterations) {
  clear_localrules() if $_ == 3; # do some tests without any other rules to check meta bugs
  ok sarun ("-t < data/spam/dnsbl.eml", \&patterns_run_cb);
  ok_all_patterns();
}

