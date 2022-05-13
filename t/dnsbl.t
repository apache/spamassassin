#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dnsbl");

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Can't use Net::DNS Safely" unless can_use_net_dns_safely();

# run many times to catch some random natured failures
my $iterations = 5;
plan tests => 22 * $iterations;

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
; fourth hop
226.149.120.193.dnsbltest       A       127.0.0.1
226.149.120.193.dnsbltest       TXT     "whitelisted sender"
; fifth hop
14.35.17.212.dnsbltest          A       127.0.0.1
14.35.17.212.dnsbltest          TXT     "whitelisted sender"
; RHS
example.com.dnsbltest           A       127.0.0.2
; SenderBase
134.88.73.210.sb.dnsbltest	TXT	"0-0=1|1=Spammer Networks|2=7.2|3=7.1|4=1537186|6=1060085863|7=80|8=12288|9=129|20=yh6.|21=example.com|23=6.5|24=6.1|25=1080071572|40=6.3|41=6.1|45=N|49=1.00"

EOF

# ---------------------------------------------------------------------------
# hits we expect and some hits we don't expect

%patterns = (
 q{'<dns:98.3.137.144.dnsbltest.spamassassin.org> [127.0.0.2]'} => '',
 q{'<dns:134.88.73.210.dnsbltest.spamassassin.org> [127.0.0.4]'} => '',
 q{'<dns:18.13.119.61.dnsbltest.spamassassin.org> [127.0.0.12]'} => '',
 q{'<dns:14.35.17.212.dnsbltest.spamassassin.org> [127.0.0.1]'} => '',
 q{'<dns:226.149.120.193.dnsbltest.spamassassin.org> [127.0.0.1]'} => '',
 q{'<dns:example.com.dnsbltest.spamassassin.org> [127.0.0.2]'} => '',
 q{'1.0 DNSBL_TEST_TOP'} => '',
 q{'1.0 DNSBL_TEST_WHITELIST'} => '',
 q{'1.0 DNSBL_TEST_DYNAMIC'} => '',
 q{'1.0 DNSBL_TEST_SPAM'} => '',
 q{'1.0 DNSBL_TEST_RELAY'} => '',
 q{'1.0 DNSBL_TXT_TOP'} => '',
 q{'1.0 DNSBL_TXT_RE'} => '',
 q{'1.0 DNSBL_RHS'} => '',
 q{'1.0 META_DNSBL_A'} => '',
 q{'1.0 META_DNSBL_B'} => '',
 q{'1.0 META_DNSBL_C'} => '',
);

%anti_patterns = (
 q{'1.0 DNSBL_TEST_MISS'} => '',
 q{'1.0 DNSBL_TXT_MISS'} => '',
 q{'1.0 DNSBL_TEST_WHITELIST_MISS'} => '',
 q{'14.35.17.212.untrusted.dnsbltest.spamassassin.org'} => '',
 q{/rules-all: unrun dependencies [^\n]+ (?:__|META_)?DNSBL_/} => '',
);

tstprefs("

# we really do not want to timeout here. use a large value, as the
# scaling code otherwise results in timing out after 7 seconds due
# to the volume of lookups performed
rbl_timeout 60

add_header all RBL _RBL_
add_header all Trusted _RELAYSTRUSTED_
add_header all Untrusted _RELAYSUNTRUSTED_

clear_trusted_networks
trusted_networks 10.
trusted_networks 150.51.53.1

header DNSBL_TEST_TOP	eval:check_rbl('test', 'dnsbltest.spamassassin.org.')
describe DNSBL_TEST_TOP	DNSBL A record match
tflags DNSBL_TEST_TOP	net

header DNSBL_TEST_WHITELIST	eval:check_rbl('white-firsttrusted', 'dnsbltest.spamassassin.org.', '127.0.0.1')
describe DNSBL_TEST_WHITELIST	DNSBL whitelist match
tflags DNSBL_TEST_WHITELIST	net nice

header DNSBL_TEST_WHITELIST_MISS	eval:check_rbl('white-firsttrusted', 'dnsbltest.spamassassin.org.', '127.0.0.255')
describe DNSBL_TEST_WHITELIST_MISS	This rule should not match
tflags DNSBL_TEST_WHITELIST_MISS	net

header DNSBL_TEST_UNTRUSTED	eval:check_rbl('white-untrusted', 'untrusted.dnsbltest.spamassassin.org.', '127.0.0.1')
describe DNSBL_TEST_UNTRUSTED	DNSBL untrusted match
tflags DNSBL_TEST_UNTRUSTED	net nice

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

# Bug 7897 - test that meta rules depending on net rules hit
meta META_DNSBL_A DNSBL_TEST_DYNAMIC
# It also needs to hit even if priority is lower than dnsbl (-100)
meta META_DNSBL_B DNSBL_TEST_SPAM
priority META_DNSBL_B -500
# Or super high
meta META_DNSBL_C DNSBL_TEST_RELAY
priority META_DNSBL_C 2000
priority DNSBL_TEST_RELAY 2000

");

for (1 .. $iterations) {
  # rules-all debug needed for unrun check
  sarun ("-t -D rules-all < data/spam/dnsbl.eml 2>&1", \&patterns_run_cb);
  ok_all_patterns();
}

