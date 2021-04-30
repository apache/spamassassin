#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("get_all_headers");
use Test::More;

use constant HAS_EMAIL_ADDRESS_XS => eval { require Email::Address::XS; };

$tests = 19;
$tests += 19 if (HAS_EMAIL_ADDRESS_XS);
plan tests => $tests;

# ---------------------------------------------------------------------------

%patterns = (
  q{'MIME-Version: 1.0'} => 'no-extra-space',
  q{'scalar-text-all-raw: Received: from yahoo.com[\n]    (PPPa33-ResaleLosAngelesMetroB2-2R7452.dialinx.net [4.48.136.190]) by[\n]    www.goabroad.com.cn (8.9.3/8.9.3) with SMTP id TAA96146; Thu,[\n]    30 Aug 2001 19:06:45 +0800 (CST) (envelope-from[\n]    pertand@email.mondolink.com)[\n]From  :<tst1@example.com>[\n]X-Mailer: Mozilla 4.04 [en]C-bls40  (Win95; U)[\n]To: jenny33436@netscape.net[\n]Subject: via.gra[\n]From:[\t]  <tst2@example.com>[\n]DATE: Fri, 7 Dec 2001 07:01:03[\n]MIME-Version: 1.0[\n]Message-Id: <20011206235802.4FD6F1143D6@mail.netnoteinc.com>[\n]Sender: travelincentives@aol.com[\n]Content-Type: text/plain; charset="us-ascii"[\n][END]'} => 'scalar-text-all-raw',
  q{'scalar-text-all-noraw: Received: from yahoo.com (PPPa33-ResaleLosAngelesMetroB2-2R7452.dialinx.net [4.48.136.190]) by www.goabroad.com.cn (8.9.3/8.9.3) with SMTP id TAA96146; Thu, 30 Aug 2001 19:06:45 +0800 (CST) (envelope-from pertand@email.mondolink.com)[\n]From: <tst1@example.com>[\n]X-Mailer: Mozilla 4.04 [en]C-bls40  (Win95; U)[\n]To: jenny33436@netscape.net[\n]Subject: via.gra[\n]From: <tst2@example.com>[\n]DATE: Fri, 7 Dec 2001 07:01:03[\n]MIME-Version: 1.0[\n]Message-Id: <20011206235802.4FD6F1143D6@mail.netnoteinc.com>[\n]Sender: travelincentives@aol.com[\n]Content-Type: text/plain; charset="us-ascii"[\n][END]'} => 'scalar-text-all-noraw',
  q{'scalar-text-from-raw: <tst1@example.com>[\n][\t]  <tst2@example.com>[\n][END]'} => 'scalar-text-from-raw',
  q{'scalar-text-from-noraw: <tst1@example.com>[\n]<tst2@example.com>[\n][END]'} => 'scalar-text-from-noraw',
  q{'scalar-text-from-addr: tst1@example.com[END]'} => 'scalar-text-from-addr',
  q{'list-text-all-raw: Received: from yahoo.com[\n]    (PPPa33-ResaleLosAngelesMetroB2-2R7452.dialinx.net [4.48.136.190]) by[\n]    www.goabroad.com.cn (8.9.3/8.9.3) with SMTP id TAA96146; Thu,[\n]    30 Aug 2001 19:06:45 +0800 (CST) (envelope-from[\n]    pertand@email.mondolink.com)[\n][LIST]From  :<tst1@example.com>[\n][LIST]X-Mailer: Mozilla 4.04 [en]C-bls40  (Win95; U)[\n][LIST]To: jenny33436@netscape.net[\n][LIST]Subject: via.gra[\n][LIST]From:[\t]  <tst2@example.com>[\n][LIST]DATE: Fri, 7 Dec 2001 07:01:03[\n][LIST]MIME-Version: 1.0[\n][LIST]Message-Id: <20011206235802.4FD6F1143D6@mail.netnoteinc.com>[\n][LIST]Sender: travelincentives@aol.com[\n][LIST]Content-Type: text/plain; charset="us-ascii"[\n][END]'} => 'list-text-all-raw',
  q{'list-text-all-noraw: Received: from yahoo.com (PPPa33-ResaleLosAngelesMetroB2-2R7452.dialinx.net [4.48.136.190]) by www.goabroad.com.cn (8.9.3/8.9.3) with SMTP id TAA96146; Thu, 30 Aug 2001 19:06:45 +0800 (CST) (envelope-from pertand@email.mondolink.com)[\n][LIST]From: <tst1@example.com>[\n][LIST]X-Mailer: Mozilla 4.04 [en]C-bls40  (Win95; U)[\n][LIST]To: jenny33436@netscape.net[\n][LIST]Subject: via.gra[\n][LIST]From: <tst2@example.com>[\n][LIST]DATE: Fri, 7 Dec 2001 07:01:03[\n][LIST]MIME-Version: 1.0[\n][LIST]Message-Id: <20011206235802.4FD6F1143D6@mail.netnoteinc.com>[\n][LIST]Sender: travelincentives@aol.com[\n][LIST]Content-Type: text/plain; charset="us-ascii"[\n][END]'} => 'list-text-all-noraw',
  q{'list-text-from-raw: <tst1@example.com>[\n][LIST][\t]  <tst2@example.com>[\n][END]'} => 'list-text-from-raw',
  q{'list-text-from-noraw: <tst1@example.com>[\n][LIST]<tst2@example.com>[\n][END]'} => 'list-text-from-noraw',
  q{'list-text-from-addr: tst1@example.com[LIST]tst2@example.com[END]'} => 'list-text-from-addr',
  q{'list-text-from-first-addr: tst1@example.com[END]'} => 'list-text-from-first-addr',
  q{'list-text-from-last-addr: tst2@example.com[END]'} => 'list-text-from-last-addr',
  q{'list-text-msgid-host: mail.netnoteinc.com[END]'} => 'list-text-msgid-host',
  q{'list-text-msgid-domain: netnoteinc.com[END]'} => 'list-text-msgid-domain',
  q{'list-text-received-ip: 4.48.136.190[END]'} => 'list-text-received-ip',
  q{'list-text-received-revip: 190.136.48.4[END]'} => 'list-text-received-revip',
);

%anti_patterns = (
  q{/MIME-Version:  1\.0/} => 'extra-space'
);

tstprefs ("
  loadplugin Dumpheaders ../../../data/Dumpheaders.pm
");

# Internal parser
$ENV{'SA_HEADER_ADDRESS_PARSER'} = 1;
ok (sarun ("-L -t < data/spam/008", \&patterns_run_cb));
ok_all_patterns();

if (HAS_EMAIL_ADDRESS_XS) {
  # Email::Address::XS
  $ENV{'SA_HEADER_ADDRESS_PARSER'} = 2;
  ok (sarun ("-L -t < data/spam/008", \&patterns_run_cb));
  ok_all_patterns();
} else { warn "Not running Email::Address::XS tests, module missing\n"; }

