#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dns");

use constant TEST_ENABLED => (-e 't/do_net');
use constant HAS_NET_DNS => eval { require Net::DNS; };

use Test;

BEGIN {
  plan tests => ((TEST_ENABLED && HAS_NET_DNS) ? 6 : 0),
};

# ---------------------------------------------------------------------------

%patterns = (
	q{ <dns:226.149.120.193.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_2',
	q{ <dns:18.13.119.61.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_3',
	q{ <dns:134.88.73.210.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_4',
	q{ <dns:98.3.137.144.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_5',
	q{ RCVD_IN_TEST } => 'P_6',
	     );

%anti_patterns = (
	q{ <dns:127.0.0.1.dnsbltest.spamassassin.org> [127.0.0.2] } => 'A_1',
		  );

tstprefs ("
	header RCVD_IN_TEST eval:check_rbl('satest', 'dnsbltest.spamassassin.org.')
	describe RCVD_IN_TEST TEST: sender is any address
	tflags RCVD_IN_TEST net
	add_header all RBL _RBL_
	");

sarun ("-t < data/spam/004", \&patterns_run_cb);
ok_all_patterns();
