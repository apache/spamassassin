#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("basic_meta_net");
use Test::More;

plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();

plan tests => 32;

# ---------------------------------------------------------------------------


%patterns = (
  q{ 1.0 X_LOCAL_TESTS } => '',
);
%anti_patterns = (
  q{ 1.0 X_URIBL_A }    => '',
  q{ 1.0 X_ASKDNS }     => '',
  q{ 1.0 X_DNSBL_TEST }     => '',
  q{ 1.0 X_DNSBL_SUB }     => '',
  q{ 1.0 X_META_POS1 }  => '',
  q{ 1.0 X_META_POS2 }  => '',
  q{ 1.0 X_META_POS3 }  => '',
  q{ 1.0 X_META_POS4 }  => '',
  q{ 1.0 X_META_POS5 }  => '',
  q{ 1.0 X_META_NEG1 }  => '',
  q{ 1.0 X_META_NEG2 }  => '',
  q{ 1.0 X_META_NEG3 }  => '',
  q{ 1.0 X_META_NEG4 } => '',
  q{ 1.0 X_META_NEG5 } => '',
  q{ 1.0 X_LOCAL_NEG } => '',
);

my $common_rules = q{
   urirhssub  X_URIBL_A  dnsbltest.spamassassin.org. A 2
   body       X_URIBL_A  eval:check_uridnsbl('X_URIBL_A')
   tflags     X_URIBL_A  net

   askdns     X_ASKDNS spamassassin.org TXT /./

   header X_DNSBL_TEST   eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
   tflags X_DNSBL_TEST   net

   header X_DNSBL_SUB    eval:check_rbl_sub('test', '2')
   tflags X_DNSBL_SUB    net

   meta X_META_POS1 X_URIBL_A
   meta X_META_POS2 X_ASKDNS
   meta X_META_POS3 X_DNSBL_TEST
   meta X_META_POS4 X_DNSBL_SUB
   meta X_META_POS5 X_URIBL_A || X_ASKDNS || X_DNSBL_TEST || X_DNSBL_SUB

   meta X_META_NEG1 !X_URIBL_A
   meta X_META_NEG2 !X_ASKDNS
   meta X_META_NEG3 !X_DNSBL_TEST
   meta X_META_NEG4 !X_DNSBL_SUB
   meta X_META_NEG5 !X_URIBL_A || !X_ASKDNS || !X_DNSBL_TEST || !X_DNSBL_SUB
};

#
# Nothing should hit with a timed out lookup
#

tstlocalrules (qq{
   # Force DNS queries to fail/timeout
   rbl_timeout 2 1
   dns_server 240.0.0.240

   $common_rules

   # local_tests_only
   meta X_LOCAL_TESTS !local_tests_only
   meta X_LOCAL_NEG local_tests_only
});

sarun ("-t < data/spam/dnsbl.eml", \&patterns_run_cb);
ok_all_patterns();

#
# Local tests only, nothing should hit as nothing is queried
#

tstlocalrules (qq{
   $common_rules

   # local_tests_only
   meta X_LOCAL_TESTS local_tests_only
   meta X_LOCAL_NEG !local_tests_only
});

sarun ("-t -L < data/spam/dnsbl.eml", \&patterns_run_cb);
ok_all_patterns();

