#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("uribl");

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_NET_DNS => eval { require Net::DNS; };
# bug 3806:
# Do not run this test on non-Linux unices as root, due to a bug
# in Sys::Hostname::Long (which Net::DNS uses.)
use constant IS_LINUX   => $^O eq 'linux';
use constant IS_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);
use constant AM_ROOT    => $< == 0;

use constant DO_RUN     => TEST_ENABLED && HAS_NET_DNS &&
                                        !(AM_ROOT &&
                                          !(IS_LINUX || IS_WINDOWS));

use Test;

BEGIN {
  plan tests => (DO_RUN ? 3 : 0),
};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

%patterns = (
 q{ X_URIBL_A } => 'A',
 q{ X_URIBL_B } => 'B',
);

tstlocalrules(q{

  rbl_timeout 30

  urirhssub  X_URIBL_A  dnsbltest.spamassassin.org.    A 2
  body       X_URIBL_A  eval:check_uridnsbl('X_URIBL_A')
  tflags     X_URIBL_A  net
  urirhssub  X_URIBL_B  dnsbltest.spamassassin.org.    A 4
  body       X_URIBL_B  eval:check_uridnsbl('X_URIBL_B')
  tflags     X_URIBL_B  net

  add_header all RBL _RBL_

});

ok sarun ("-D -t < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
ok_all_patterns();

