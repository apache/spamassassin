#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("if_can");
use Test::More tests => 9;

# ---------------------------------------------------------------------------

tstlocalrules (q{
  clear_originating_ip_headers
  originating_ip_headers X-Yahoo-Post-IP X-Apparently-From
  originating_ip_headers X-Originating-IP X-SenderIP
  header TEST_ORIG_IP_H1 X-Spam-Relays-External =~ /\bip=198\.51\.100\.1\b/
  score  TEST_ORIG_IP_H1 0.1
  header TEST_ORIG_IP_H2 X-Spam-Relays-External =~ /\bip=198\.51\.100\.2\b/
  score  TEST_ORIG_IP_H2 0.1
});

%patterns      = ( q{ 0.1 TEST_ORIG_IP_H1 }, '' );
%anti_patterns = ( q{ TEST_ORIG_IP_H2 }, '' );

ok(sarun("-L -t < data/nice/orig_ip_hdr.eml", \&patterns_run_cb));
ok_all_patterns();

# ---------------------------------------------------------------------------

tstlocalrules (q{
  clear_originating_ip_headers
  originating_ip_headers X-Yahoo-Post-IP X-Apparently-From
  originating_ip_headers X-Originating-IP X-SenderIP
  originating_ip_headers X-Testing-Ip
  header TEST_ORIG_IP_H1 X-Spam-Relays-External =~ /\bip=198\.51\.100\.1\b/
  score  TEST_ORIG_IP_H1 0.1
  header TEST_ORIG_IP_H2 X-Spam-Relays-External =~ /\bip=198\.51\.100\.2\b/
  score  TEST_ORIG_IP_H2 0.1
});

%patterns      = ( q{ 0.1 TEST_ORIG_IP_H1 }, '',
                   q{ TEST_ORIG_IP_H2 }, '' );
%anti_patterns = ();

ok(sarun("-L -t < data/nice/orig_ip_hdr.eml", \&patterns_run_cb));
ok_all_patterns();

# ---------------------------------------------------------------------------

tstlocalrules (q{
  clear_originating_ip_headers
  header TEST_ORIG_IP_H1 X-Spam-Relays-External =~ /\bip=198\.51\.100\.1\b/
  score  TEST_ORIG_IP_H1 0.1
  header TEST_ORIG_IP_H2 X-Spam-Relays-External =~ /\bip=198\.51\.100\.2\b/
  score  TEST_ORIG_IP_H2 0.1
});

%patterns = ();
%anti_patterns = ( q{ 0.1 TEST_ORIG_IP_H1 }, '',
                   q{ TEST_ORIG_IP_H2 }, '' );

ok(sarun("-L -t < data/nice/orig_ip_hdr.eml", \&patterns_run_cb));
ok_all_patterns();

