#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("dns");

use constant TEST_ENABLED => (-e 't/do_net' || -e 'do_net');
use constant HAS_NET_DNS => eval { require Net::DNS; };

use Test;

BEGIN {
  plan tests => ((TEST_ENABLED && HAS_NET_DNS) ? 16 : 0),
};

exit unless (TEST_ENABLED && HAS_NET_DNS);

# ---------------------------------------------------------------------------
# bind configuration currently used to support this test
# update when DNS changes for *.dnsbltest.spamassassin.org

my $bind = <<'EOF';

; records to support SA test t/dns.t
;
; 127.0.0.1 -> whitelisted sender
; 127.0.0.2 -> dynamic host
; 127.0.0.4 -> spam source
; 127.0.0.8 -> open proxy
;
; first hop
98.3.137.144.dnsbltest          A       127.0.0.2
98.3.137.144.dnsbltest          TXT     "dynamic host"
; second hop
134.88.73.210.dnsbltest         A       127.0.0.4
134.88.73.210.dnsbltest         TXT     "spam source"
; third hop
18.13.119.61.dnsbltest          A       127.0.0.12
18.13.119.61.dnsbltest          TXT     "spam source, open relay"
; fourth hop (trusted)
226.149.120.193.dnsbltest       A       127.0.0.1
226.149.120.193.dnsbltest       TXT     "whitelisted sender"
; last hop (trusted)
14.35.17.212.dnsbltest          A       127.0.0.1
14.35.17.212.dnsbltest          TXT     "whitelisted sender"
; RHS
example.com.dnsbltest           A       127.0.0.2

EOF

# ---------------------------------------------------------------------------
# hits we expect and some hits we don't expect

%patterns = (
 q{ <dns:98.3.137.144.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_1',
 q{ <dns:134.88.73.210.dnsbltest.spamassassin.org> [127.0.0.4] } => 'P_2',
 q{ <dns:18.13.119.61.dnsbltest.spamassassin.org> [127.0.0.12] } => 'P_3',
 q{ <dns:226.149.120.193.dnsbltest.spamassassin.org> [127.0.0.1] } => 'P_4',
 q{ <dns:example.com.dnsbltest.spamassassin.org> [127.0.0.2] } => 'P_5',
 q{ DNSBL_TEST_TOP } => 'P_6',
 q{ DNSBL_TEST_WHITELIST } => 'P_7',
 q{ DNSBL_TEST_DYNAMIC } => 'P_8',
 q{ DNSBL_TEST_SPAM } => 'P_9',
 q{ DNSBL_TEST_RELAY } => 'P_10',
 q{ DNSBL_TXT_TOP } => 'P_11',
 q{ DNSBL_TXT_RE } => 'P_12',
 q{ DNSBL_RHS } => 'P_13',
);

%anti_patterns = (
 q{ <dns:14.35.17.212.dnsbltest.spamassassin.org> [127.0.0.1] } => 'P_14',
 q{ DNSBL_TEST_MISS } => 'P_15',
 q{ DNSBL_TXT_MISS } => 'P_16',
);

tstprefs("
add_header all RBL _RBL_
add_header all Trusted _RELAYSTRUSTED_
add_header all Untrusted _RELAYSUNTRUSTED_

clear_trusted_networks
trusted_networks 127.

header DNSBL_TEST_TOP	eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
describe DNSBL_TEST_TOP	DNSBL A record match
tflags DNSBL_TEST_TOP	net

header DNSBL_TEST_WHITELIST	eval:check_rbl_sub('test', '127.0.0.1')
describe DNSBL_TEST_WHITELIST	DNSBL whitelist match
tflags DNSBL_TEST_WHITELIST	net nice

header DNSBL_TEST_DYNAMIC	eval:check_rbl_sub('test', '2')
describe DNSBL_TEST_DYNAMIC	DNSBL dynamic match
tflags DNSBL_TEST_DYNAMIC	net

header DNSBL_TEST_SPAM		eval:check_rbl_sub('test', '4')
describe DNSBL_TEST_SPAM	DNSBL spam source
tflags DNSBL_TEST_SPAM		net

header DNSBL_TEST_RELAY		eval:check_rbl_sub('test', '8')
describe DNSBL_TEST_RELAY	DNSBL open relay
tflags DNSBL_TEST_RELAY		net

header DNSBL_TEST_MISS		eval:check_rbl_sub('test', '16')
describe DNSBL_TEST_MISS	DNSBL open relay
tflags DNSBL_TEST_MISS		net

header DNSBL_TXT_TOP	eval:check_rbl_txt('t', 'dnsbltest.spamassassin.org.')
describe DNSBL_TXT_TOP	DNSBL TXT record match
tflags DNSBL_TXT_TOP	net

header DNSBL_TXT_RE	eval:check_rbl_sub('t', 'open relay')
describe DNSBL_TXT_RE	DNSBL TXT regular expression match
tflags DNSBL_TXT_RE	net

header DNSBL_TXT_MISS	eval:check_rbl_sub('t', 'foobar')
describe DNSBL_TXT_MISS	DNSBL TXT regular expression match (should miss)
tflags DNSBL_TXT_MISS	net

header DNSBL_RHS	eval:check_rbl_from_host('r', 'dnsbltest.spamassassin.org.')
describe DNSBL_RHS	DNSBL RHS match
tflags DNSBL_RHS	net
");

sarun ("-t < data/spam/dnsbl.eml", \&patterns_run_cb);
ok_all_patterns();
