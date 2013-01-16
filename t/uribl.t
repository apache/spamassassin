#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("uribl");

use constant TEST_ENABLED => conf_bool('run_net_tests') && conf_bool('run_long_tests');
use constant DO_RUN => TEST_ENABLED && can_use_net_dns_safely();
use Test;

BEGIN {
  plan tests => (DO_RUN ? 6 : 0),
};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

%patterns = (
 q{ X_URIBL_A } => 'A',
 q{ X_URIBL_B } => 'B',
 q{ X_URIBL_NS } => 'NS',
 q{ X_URIBL_DOMSONLY } => 'X_URIBL_DOMSONLY',
);

%anti_patterns = (
 q{ X_URIBL_FULL_NS } => 'FULL_NS',
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

});

# note: don't leave -D here, it causes spurious passes
ok sarun ("-t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

