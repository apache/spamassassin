#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("rcvd_parser");
use Test; BEGIN { plan tests => 21 };


use strict;

my %data = (

# format is:
#     q{ ...received hdrs sample... } => q{ [ expected string, normalized ] },
#     ....
# (normalized == s/\s+/ /gs;)

    q{

Received: (qmail 10681 invoked by uid 404); 14 Nov 2003 08:05:52 -0000
Received: from postfix3-2.free.fr (foobar@213.228.0.129)
  by totor.example.net with SMTP; 14 Nov 2003 08:05:50 -0000
Received: from asterix.laurier.org (lns-p19-8-82-65-66-244.adsl.proxad.net [82.65.66.244])
	by postfix3-2.free.fr (Postfix) with ESMTP id 7BACDC372
	for <somelist@example.net>; Fri, 14 Nov 2003 09:05:49 +0100 (CET)

} => q{

[ ip=213.228.0.129 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= ] [ ip=82.65.66.244 rdns=lns-p19-8-82-65-66-244.adsl.proxad.net helo=asterix.laurier.org by=postfix3-2.free.fr ident= envfrom= ]

}, q{

Received: from postfix3-2.free.fr (foobar@213.228.0.139) 
  by totor.example.net with SMTP; 14 Nov 2003 08:05:50 -0000 
Received: from asterix.laurier.org (lns-p19-8-82-65-66-244.adsl.proxad.net [82.65.66.244]) 
	by postfix3-2.free.fr (Postfix) with ESMTP id 7BACDC372 
	for <michel@example.net>; Fri, 14 Nov 2003 09:05:49 +0100 (CET) 
} => q{

[ ip=213.228.0.139 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= ] [ ip=82.65.66.244 rdns=lns-p19-8-82-65-66-244.adsl.proxad.net helo=asterix.laurier.org by=postfix3-2.free.fr ident= envfrom= ]

}, q{

Received: from unknown (HELO feux01a-isp) (213.199.4.210) 
  by totor.example.net with SMTP; 1 Nov 2003 07:05:19 -0000 
 
} => q{

[ ip=213.199.4.210 rdns= helo=feux01a-isp by=totor.example.net ident= envfrom= ]

}, q{

Received: from x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk (benelli@80.167.158.170) 
  by totor.example.net with SMTP; 5 Nov 2003 23:18:42 -0000 
 
} => q{

[ ip=80.167.158.170 rdns=x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk helo=x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk by=totor.example.net ident=benelli envfrom= ]

}, q{
 
Received: from adsl-207-213-27-129.dsl.lsan03.pacbell.net (HELO merlin.net.au) (Owner50@207.213.27.129) 
  by totor.example.net with SMTP; 10 Nov 2003 06:30:34 -0000

} => q{

[ ip=207.213.27.129 rdns=adsl-207-213-27-129.dsl.lsan03.pacbell.net helo=merlin.net.au by=totor.example.net ident=Owner50 envfrom= ]

}, q{


Received: from postfix3-2.free.fr (HELO machine.domain.com) 
  (foobar@213.228.20.149) by totor.example.net with SMTP; 
  14 Nov 2003 08:31:29 -0000 

} => q{

[ ip=213.228.20.149 rdns=postfix3-2.free.fr helo=machine.domain.com by=totor.example.net ident=foobar envfrom= ]

}, q{
Received: from postfix3-2.free.fr (213.228.0.159) by totor.example.net 
  with SMTP; 14 Nov 2003 08:31:29 -0000 
 
} => q{

[ ip=213.228.0.159 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident= envfrom= ]

}, q{
Received: from postfix3-2.free.fr (foobar@213.228.0.169) by totor.example.net 
  with SMTP; 14 Nov 2003 08:31:29 -0000 
 
} => q{

[ ip=213.228.0.169 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= ]

}, q{
Received: from unknown (HELO machine.domain.com) (foobar@213.228.0.179) 
  by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000 
 
} => q{

[ ip=213.228.0.179 rdns= helo=machine.domain.com by=totor.example.net ident=foobar envfrom= ]

}, q{
Received: from unknown (HELO machine.domain.com) (213.228.0.189) 
  by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000 

} => q{

[ ip=213.228.0.189 rdns= helo=machine.domain.com by=totor.example.net ident= envfrom= ]

}, q{
 
Received: from loki.komtel.net (212.7.146.145) 
  by totor.example.net with SMTP; 16 Nov 2003 04:53:54 -0000 
 
} => q{

[ ip=212.7.146.145 rdns=loki.komtel.net helo=loki.komtel.net by=totor.example.net ident= envfrom= ]

}, q{
 
Received: from c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com 
  (66.169.197.134) by totor.example.net with SMTP; 
  16 Nov 2003 05:59:32 -0000 
} => q{

[ ip=66.169.197.134 rdns=c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com helo=c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com by=totor.example.net ident= envfrom= ]

}, q{

Received: from dyn-81-166-39-132.ppp.tiscali.fr (81.166.39.132) by cpmail.dk.tiscali.com (6.7.018)
        id 3FE6899B004FE7A4; Thu, 1 Jan 2004 05:28:49 +0100

} => q{

[ ip=81.166.39.132 rdns=dyn-81-166-39-132.ppp.tiscali.fr helo=dyn-81-166-39-132.ppp.tiscali.fr by=cpmail.dk.tiscali.com ident= envfrom= ]

}, q{

Received: from unknown (HELO [81.64.159.45]) ([81.64.159.45]) 
          (envelope-sender <xyz@example.org>) 
          by 212.198.2.120 (qmail-ldap-1.03) with SMTP 
          for <zyx@somewhere.net>; 28 Nov 2003 20:44:45 -0000 

} => q{

[ ip=81.64.159.45 rdns= helo=81.64.159.45 by=212.198.2.120 ident= envfrom=xyz@example.org ]

}, q{

Received: (qmail 8363 invoked by uid 526); 3 Mar 2004 20:34:41 -0000
Received: from advertisement@topofferz.net by blazing.fooooo.org by
	uid 501 with qmail-scanner-1.20
	(clamuko: 0.65. f-prot: 4.2.0/3.13.4.  Clear:RC:1(127.0.0.1):.
	Processed in 0.20859 secs); 03 Mar 2004 20:34:41 -0000
Received: (qmail 8351 invoked by uid 526); 3 Mar 2004 20:34:39 -0000
Received: from advertisement@topofferz.net by blazing.fooooo.org by
	uid 502 with qmail-scanner-1.20
	(clamuko: 0.65. f-prot: 4.2.0/3.13.4.  Clear:RC:0(69.6.60.10):.
	Processed in 0.212322 secs); 03 Mar 2004 20:34:39 -0000
Received: from mx10.topofferz.net (HELO ) (69.6.60.10)
	by blazing.fooooo.org with SMTP; 3 Mar 2004 20:34:38 -0000

} => q{

[ ip=69.6.60.10 rdns=mx10.topofferz.net helo= by=blazing.fooooo.org ident= envfrom= ]


}, q{

Received: from email.com (unknown [222.32.65.3])
	by eclectic.kluge.net (Postfix) with ESMTP id 33DC4416F20
	for <city@kluge.net>; Mon,  1 Mar 2004 01:09:44 -0500 (EST)

} => q{

[ ip=222.32.65.3 rdns= helo=email.com by=eclectic.kluge.net ident= envfrom= ]

}, q{

Received: from kluge.net (unknown [222.156.78.32])
	by eclectic.kluge.net (Postfix) with SMTP id CE1BA416F20
	for <jay@kluge.net>; Mon,  1 Mar 2004 13:11:31 -0500 (EST)

} => q{

[ ip=222.156.78.32 rdns= helo=kluge.net by=eclectic.kluge.net ident= envfrom= ]

}, q{

Received: from xjwrvjq (unknown [222.54.106.152])
	by eclectic.kluge.net (Postfix) with SMTP id ED474416F20
	for <cyoung@eclectic.kluge.net>; Tue,  2 Mar 2004 12:51:44 -0500

} => q{

[ ip=222.54.106.152 rdns= helo=xjwrvjq by=eclectic.kluge.net ident= envfrom= ]

}, q{

Received: from localhost (localhost [127.0.0.1])
	by radish.zzzz.org (Postfix) with ESMTP id 1398F5900D9
	for <zzzz@localhost>; Mon,  8 Mar 2004 16:02:50 -0800 (PST)
Received: from localhost [127.0.0.1]
	by localhost with IMAP (fetchmail-6.2.4)
	for zzzz@localhost (single-drop); Mon, 08 Mar 2004 16:02:50 -0800 (PST)
Received: from mail00.svc.cra.dublin.eircom.net (mail00.svc.cra.dublin.eircom.net [159.134.118.16])
	by amgod.boxhost.net (Postfix) with SMTP id 0ACFC31014D
	for <zzzz@zzzz.org>; Mon,  8 Mar 2004 23:59:19 +0000 (GMT)
Received: (qmail 87263 messnum 771997 invoked from network[83.70.48.2/83-70-48-2.bas2.dbn.dublin.eircom.net]); 8 Mar 2004 23:59:05 -0000
Received: from 83-70-48-2.bas2.dbn.dublin.eircom.net (HELO ?192.168.23.32?) (83.70.48.2)
  by mail00.svc.cra.dublin.eircom.net (qp 87263) with SMTP; 8 Mar 2004 23:59:05 -0000

} => q{

[ ip=159.134.118.16 rdns=mail00.svc.cra.dublin.eircom.net helo=mail00.svc.cra.dublin.eircom.net by=amgod.boxhost.net ident= envfrom= ] [ ip=83.70.48.2 rdns=83-70-48-2.bas2.dbn.dublin.eircom.net helo=?192.168.23.32? by=mail00.svc.cra.dublin.eircom.net ident= envfrom= ]

}, q{

Received: from localhost (localhost [127.0.0.1])
	by radish.jmason.org (Postfix) with ESMTP id 27B275900D9
	for <zzzzz@localhost>; Mon,  8 Mar 2004 16:13:23 -0800 (PST)
Received: from localhost [127.0.0.1]
	by localhost with IMAP (fetchmail-6.2.4)
	for zzzzz@localhost (single-drop); Mon, 08 Mar 2004 16:13:23 -0800 (PST)
Received: from smtp3.es.uci.edu (smtp3.es.uci.edu [128.200.80.6])
	by amgod.boxhost.net (Postfix) with ESMTP id 87D0A310091
	for <zzzzz@jmason.org>; Tue,  9 Mar 2004 00:07:59 +0000 (GMT)
Received: from rigel.oac.uci.edu (rigel.oac.uci.edu [128.200.80.22])
	by smtp3.es.uci.edu (8.12.8/8.12.8) with ESMTP id i2907ZaF008726
	for <zzzzz@jmason.org>; Mon, 8 Mar 2004 16:07:35 -0800
Received: from localhost (wwwwww@localhost)
	by rigel.oac.uci.edu (8.9.3p2/8.9.3) with ESMTP id QAA13555
	for <zzzzz@jmason.org>; Mon, 8 Mar 2004 16:07:35 -0800 (PST)

} => q{
  
[ ip=128.200.80.6 rdns=smtp3.es.uci.edu helo=smtp3.es.uci.edu by=amgod.boxhost.net ident= envfrom= ] [ ip=128.200.80.22 rdns=rigel.oac.uci.edu helo=rigel.oac.uci.edu by=smtp3.es.uci.edu ident= envfrom= ]
  
});

tstprefs ("add_header all Relays _RELAYSUNTRUSTED_ _RELAYSTRUSTED_\n");

my $sa = create_saobj({ userprefs_filename => "log/tst.cf" });
$sa->init();
ok($sa);

foreach my $hdrs (sort keys %data) {
  my $expected = $data{$hdrs};

  my $msg = $hdrs."\n\n[no body]\n";
  $msg =~ s/^\s+//gs;
  my $status = $sa->check_message_text ($msg);
  my $result = $status->rewrite_mail();

  #warn "JMD $result";
  $result =~ s/\n[ \t]+/ /gs;
  $result =~ /\nX-Spam-Relays: ([^\n]*)\n/s;
  my $relays = $1;
  
  $relays =~ s/\s+/ /gs;
  $expected =~ s/\s+/ /gs;
  $relays =~ s/^\s+//gs;
  $expected =~ s/^\s+//gs;
  $relays =~ s/\s+$//gs;
  $expected =~ s/\s+$//gs;

# strip "intl" from match.  We don't need to care about this when testing!
$relays =~ s/ intl=[01] / /gs;
$expected =~ s/ intl=[01] / /gs;

  ok ($relays eq $expected);
  if ($relays ne $expected) {
    print "expected: $expected\n";
    print "got     : $relays\n";
    print "hdr sample: ", ('-' x 67), $hdrs, ('-' x 78), "\n\n";
  }
}

