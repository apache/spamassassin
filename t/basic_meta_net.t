#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; sa_t_init("basic_meta_net");
use Test::More;

plan skip_all => "Net tests disabled"          unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely"   unless can_use_net_dns_safely();

plan tests => 20;

# ---------------------------------------------------------------------------


%patterns = (
  q{ X_META_POS4 } => '',
);
%anti_patterns = (
  q{ X_URIBL_A }    => '',
  q{ X_ASKDNS }     => '',
  q{ X_META_POS1 }  => '',
  q{ X_META_POS2 }  => '',
  q{ X_META_POS3 }  => '',
  q{ X_META_NEG1 }  => '',
  q{ X_META_NEG2 }  => '',
  q{ X_META_NEG3 }  => '',
  q{ X_META_NEG4 } => '',
);

#
# Nothing should hit with a failed lookup
#

tstlocalrules (qq{
   # Force DNS queries to fail/timeout
   rbl_timeout 2 1
   dns_server 240.0.0.240

   urirhssub  X_URIBL_A  dnsbltest.spamassassin.org. A 2
   body       X_URIBL_A  eval:check_uridnsbl('X_URIBL_A')
   tflags     X_URIBL_A  net

   askdns     X_ASKDNS spamassassin.org TXT /./

   meta X_META_POS1 X_URIBL_A
   meta X_META_POS2 X_ASKDNS
   meta X_META_POS3 X_URIBL_A || X_ASKDNS

   meta X_META_NEG1 !X_URIBL_A
   meta X_META_NEG2 !X_ASKDNS
   meta X_META_NEG3 !X_URIBL_A || !X_ASKDNS

   # local_tests_only
   meta X_META_NEG4 local_tests_only
   meta X_META_POS4 !local_tests_only
});

sarun ("-t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

#
# Local only, nothing should hit as nothing is queried
#

tstlocalrules (qq{
   urirhssub  X_URIBL_A  dnsbltest.spamassassin.org. A 2
   body       X_URIBL_A  eval:check_uridnsbl('X_URIBL_A')
   tflags     X_URIBL_A  net

   askdns     X_ASKDNS spamassassin.org TXT /./

   meta X_META_POS1 X_URIBL_A
   meta X_META_POS2 X_ASKDNS
   meta X_META_POS3 X_URIBL_A || X_ASKDNS

   meta X_META_NEG1 !X_URIBL_A
   meta X_META_NEG2 !X_ASKDNS
   meta X_META_NEG3 !X_URIBL_A || !X_ASKDNS

   # local_tests_only
   meta X_META_POS4 local_tests_only
   meta X_META_NEG4 !local_tests_only
});

sarun ("-t -L < data/spam/dnsbl.eml", \&patterns_run_cb);
ok_all_patterns();

