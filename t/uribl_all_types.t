#!/usr/bin/perl
#
# bug 6335: ensure that both domains_only and ips_only URIDNSBL rules can coexist

use lib '.'; use lib 't';
use SATest; sa_t_init("uribl_all_types");

use Test::More;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Net tests disabled"                unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();
plan tests => 3;

# ---------------------------------------------------------------------------

%patterns = (

   q{ X_URIBL_IPSONLY [URIs: 144.137.3.98] } => 'X_URIBL_IPSONLY',

   # can be either uribl-example-b.com or uribl-example-c.com
   q{ X_URIBL_DOMSONLY [URIs: uribl-example} => 'X_URIBL_DOMSONLY',

);

tstlocalrules(q{

  rbl_timeout 30

  urirhssub  X_URIBL_IPSONLY  dnsbltest.spamassassin.org.    A 2
  body       X_URIBL_IPSONLY  eval:check_uridnsbl('X_URIBL_IPSONLY')
  describe   X_URIBL_IPSONLY  X_URIBL_IPSONLY
  tflags     X_URIBL_IPSONLY  net ips_only

  urirhssub  X_URIBL_DOMSONLY  dnsbltest.spamassassin.org.    A 4
  body       X_URIBL_DOMSONLY  eval:check_uridnsbl('X_URIBL_DOMSONLY')
  describe   X_URIBL_DOMSONLY  X_URIBL_DOMSONLY
  tflags     X_URIBL_DOMSONLY  net domains_only

  add_header all RBL _RBL_

});

# note: don't leave -D here, it causes spurious passes
ok sarun ("-t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

