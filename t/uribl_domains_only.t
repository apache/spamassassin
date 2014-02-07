#!/usr/bin/perl
# bug 6335: domains_only URIDNSBL rules

use lib '.'; use lib 't';
use SATest; sa_t_init("uribl_domains_only");

use constant TEST_ENABLED => conf_bool('run_net_tests') && conf_bool('run_long_tests');
use constant DO_RUN => TEST_ENABLED && can_use_net_dns_safely();
use Test;

BEGIN {
  plan tests => (DO_RUN ? 4 : 0),
};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

%anti_patterns = ( q{ X_URIBL_DOMSONLY } => 'A' );

tstlocalrules(q{

  rbl_timeout 30

  urirhssub  X_URIBL_DOMSONLY  dnsbltest.spamassassin.org.    A 2
  body       X_URIBL_DOMSONLY  eval:check_uridnsbl('X_URIBL_DOMSONLY')
  tflags     X_URIBL_DOMSONLY  net domains_only

  add_header all RBL _RBL_

});

# note: don't leave -D here, it causes spurious passes
ok sarun ("-t < data/spam/dnsbl_domsonly.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = ( q{ X_URIBL_DOMSONLY } => 'A' );
%anti_patterns = ();

clear_pattern_counters();
ok sarun ("-t < data/spam/dnsbl_ipsonly.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

