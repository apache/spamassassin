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
use Test; BEGIN { plan tests => 129 };
use strict;

# format is:
#     '...received hdr sample...'	# single line, trimmed to just the header data
#     '[ expected string ]',		# '' if message should be skipped

my %data = (

  ####  HEADERS THAT SHOULD BE IGNORED  ####

  '(qmail 10681 invoked by uid 404); 14 Nov 2003 08:05:52 -0000' =>
  '',

  '(qmail 87263 messnum 771997 invoked from network[83.70.48.2/83-70-48-2.bas2.dbn.dublin.eircom.net]); 8 Mar 2004 23:59:05 -0000' =>
  '',

  'from mail pickup service by hotmail.com with Microsoft SMTPSVC; Tue, 16 Mar 2004 18:12:31 -0800' =>
  '',

  'from Dwsf@aol.com by imo-m01.mx.aol.com (mail_out_v36_r4.12.) id m.b9.3bfe3305 (4116) for <Slowhand101967@aol.com>; Tue, 3 Feb 2004 11:14:06 -0500 (EST)' =>
  '',

  'from advertisement@topofferz.net by blazing.fooooo.org by uid 502 with qmail-scanner-1.20 (clamuko: 0.65. f-prot: 4.2.0/3.13.4.  Clear:RC:0(69.6.60.10):.  Processed in 0.212322 secs); 03 Mar 2004 20:34:39 -0000' =>
  '',

  'from localhost [127.0.0.1] by localhost with IMAP (fetchmail-6.2.4) for zzzzz@localhost (single-drop); Mon, 08 Mar 2004 16:13:23 -0800 (PST)' =>
  '',

  'from localhost (wwwwww@localhost) by rigel.oac.uci.edu (8.9.3p2/8.9.3) with ESMTP id QAA13555 for <zzzzz@jmason.org>; Mon, 8 Mar 2004 16:07:35 -0800 (PST)' =>
  '',
  
  'from pop.vip.sc5.yahoo.com [216.136.173.10] by localhost with POP3 (fetchmail-5.9.13) for pppppppppp@hhhhhhhhh.net (single-drop); Sun, 22 Feb 2004 20:46:25 -0600 (CST)' =>
  '',

  'from rc3.isc.org (rc3.isc.org [IPv6:2001:4f8:3:bb::25])       (using TLSv1 with cipher DHE-RSA-AES256-SHA (256/256 bits))        (No client certificate requested)  by sf1.isc.org (Postfix) with ESMTP id C986F284EE       for <jm@jmason.org>; Sat, 16 Oct 2004 21:30:02 +0000 (UTC) (envelope-from bind-users-bounce@isc.org)' =>
  '',

  'from ausisaps301-dmz.aus.amer.dell.com ([143.166.226.16]) (SquirrelMail authenticated user hoolis); by www.penguintowne.org with HTTP; Mon, 22 Mar 2004 12:54:13 -0600 (CST)' =>
  '',

  'from localhost [127.0.0.1] by localhost with IMAP (fetchmail-6.2.4) for zzzz@localhost (single-drop); Mon, 08 Mar 2004 16:02:50 -0800 (PST)' =>
  '',

  'from 153.90.199.141        (SquirrelMail authenticated user admin); by web1.cs.montana.edu with HTTP;        Thu, 23 Sep 2004 14:35:29 -0600 (MDT)' =>
  '',

  'from 156.56.111.196 by blazing.arsecandle.org (envelope-from <gentoo-announce-return-530-rod=arsecandle.org@lists.gentoo.org>, uid 502) with qmail-scanner-1.24 (clamdscan: 0.80/594. f-prot: 4.4.2/3.14.11.  Clear:RC:0(156.56.111.196):.  Processed in 0.288806 secs); 06 Feb 2005 21:11:38 -0000' =>
  '',

  'from <unavailable> by pps01.tyson.com (8.12.11/8.12.11) with ESMTP id k4MC0Jdu015089 for <<tysonrecipemail@listserv.tyson.com>>; Mon, 22 May 2006 07:00:20 -0500' =>
  '',

  'from CNNIMAIL12.CNN.COM by CNNIMAIL12.CNN.COM (LISTSERV-TCP/IP release 1.8d) with spool id 35469828 for TEXTBREAKINGNEWS@CNNIMAIL12.CNN.COM; Tue, 23 May 2006 11:01:27 -0400' =>
  '',

  'from DL1GSPMX02 (dl1gspmx02.gamestop.com) by email.ebgames.com (LSMTP for Windows NT v1.1b) with SMTP id <21.000575A0@email.ebgames.com>; Tue, 12 Sep 2006 21:06:43 -0500' =>
  '',

  'from LOCALHOST by LOCALHOST with ESMTP id EF01F5A6A515A04D89C9B0461D36E7A4 Mon, 11 Sep 2006 11:41:10 -0500' =>
  '',

  'from PRODWEB02LA by dns03.treehousei.com (Merak 8.0.3) with SMTP id ACM38534 for <example@vandinter.org>; Fri, 19 May 2006 14:50:48 -0700' =>
  '',

  'from Programmr.newtv.org by newtv.org (VisNetic.MailServer.v8.3.0.1) with ASMTP id AYT39007; Mon, 22 May 2006 15:49:07 -0400' =>
  '',

  'from Spooler by mail2.getcoactive.com (Mercury/32 v4.01a) ID MO0072A1; 5 Jun 2006 11:50:08 -0400' =>
  '',

  'from spooler by mail2.getcoactive.com (Mercury/32 v4.01a); 5 Jun 2006 11:44:13 -0400' =>
  '',

  'from [Masked] by mailrelay2.thestar.ca with ESMTP id lxalvkca for example@vandinter.org; Fri, 8 Sep 2006 17:21:46 -0400' =>
  '',

  'from amavis by forumakad.pl with scanned-ok (Exim 3.35 #1 (Debian)) id 1FiWc9-0007Du-00 for <proftp-user@lists.sourceforge.net>; Tue, 23 May 2006 15:07:57 +0200' =>
  '',

  'from autoreply-daemon.mail.wgbh.org by mail.wgbh.org (iPlanet Messaging Server 5.2 HotFix 2.07 (built Jun 24 2005)) id <0J0E00K02L0G76@mail.wgbh.org> for example@vandinter.org; Mon, 05 Jun 2006 16:02:40 -0400 (EDT)' =>
  '',

  'from chplds004 by ns2.stlouis.usf.ibm.com (8.11.6p3/8.10.1) with ESMTP id k7IHGfA114538 for <example@vandinter.org>; Fri, 18 Aug 2006 12:16:41 -0500' =>
  '',

  'from conversion-daemon.d1-sfbay-01.sun.com by d1-sfbay-01.sun.com (Sun Java System Messaging Server 6.2-4.02 (built Sep  9 2005)) id <0IZO00701ISSIU00@d1-sfbay-01.sun.com> (original mail from David.Vancouvering@Sun.COM) for code-awards@apache.org; Mon, 22 May 2006 11:23:41 -0700 (PDT)' =>
  '',

  'from gb02qws092els27 by www.elsevier.com (8.12.10/8.9.3/USFo1.0) with ESMTP id k7UDHtrV057626 for <example@vandinter.org>; Wed, 30 Aug 2006 13:17:58 GMT' =>
  '',

  'from lin6410.northern.com by CSKMAIL1; 29 Aug 2006 11:02:05 -0700' =>
  '',

  'from localhost by aopen.compata.com (Linux 2.6) with ESMTP (8.13.6/8.13.4) id k4JNjENG010334 for <discuss@lopsa.org>; Fri, 19 May 2006 16:45:14 -0700' =>
  '',

  'from localhost by spike.gizmag.com with SpamAssassin (version 3.0.2); Thu, 17 Aug 2006 08:21:10 +1000' =>
  '',

  'from mail by pascal.ctyme.com with ctyme-spam-scanned (Exim 4.51) id 1DnPTU-0006bL-UT for ToUser@menschel.net; Tue, 28 Jun 2005 16:26:44 -0700' =>
  '',

  'from mailer  by www.lesstroudonline.com with HTTP (Mail); Mon, 14 Aug 2006 14:20:13 -0700' =>
  '',

  'from pmxchannel-daemon.newman.NebrWesleyan.edu by newman.NebrWesleyan.edu (iPlanet Messaging Server 5.2 HotFix 2.05 (built Mar  3 2005)) id <0IZY00I01M1DCE@newman.NebrWesleyan.edu> for discuss@lopsa.org; Sun, 28 May 2006 00:03:13 -0500 (CDT)' =>
  '',

  'from senmail2.senate.gov with LMTP by senmail2 (3.0.2/sieved-3-0-build-942) for <example@vandinter.org>; Fri, 30 Jun 2006 10:58:41 -0400' =>
  '',

  'from smalldog.com by list.smalldog.com with SMTP; Fri, 1 Sep 2006 10:56:21 -0400' =>
  '',

  'from web01.bgca.dmz by list.bgca.org (MDaemon PRO v9.0.1) with ESMTP id md50000050056.msg for <example@vandinter.org>; Mon, 19 Jun 2006 11:50:20 -0400' =>
  '',

  'from zimbramail.artsit.org.uk (unverified) by MAILSWEEP.birminghamartsit.org.uk (Clearswift SMTPRS 5.1.7) with ESMTP id <T78926b35f2c0a80003da8@MAILSWEEP.birminghamartsit.org.uk> for <discuss@lists.surbl.org>; Tue, 30 May 2006 15:56:15 +0100' =>
  '',





  ####  HEADERS THAT SHOULD BE PARSED  ####

  'from jsoliday.acs.internap.com ([63.251.66.24.63559]) by mailhost.acs.internap.com with esmtp  (v3.35.1) id 1GNrLz-000295-00; Thu, 14 Sep 2006 09:34:07 -0400' =>
  '[ ip=63.251.66.24 rdns= helo=jsoliday.acs.internap.com by=mailhost.acs.internap.com ident= envfrom= id=1GNrLz-000295-00 auth= msa=0 ]',

  'from lists.gentoo.org (HELO parrot.gentoo.org) (156.56.111.196) by blazing.arsecandle.org with (DHE-RSA-AES256-SHA encrypted) SMTP; 6 Feb 2005 21:11:37 -0000' =>
  '[ ip=156.56.111.196 rdns=lists.gentoo.org helo=parrot.gentoo.org by=blazing.arsecandle.org ident= envfrom= id= auth= msa=0 ]',

  'from postfix3-2.free.fr (foobar@213.228.0.129) by totor.example.net with SMTP; 14 Nov 2003 08:05:50 -0000' =>
  '[ ip=213.228.0.129 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= id= auth= msa=0 ]',

  'from asterix.laurier.org (lns-p19-8-82-65-66-244.adsl.proxad.net [82.65.66.244]) by postfix3-2.free.fr (Postfix) with ESMTP id 7BACDC372 for <somelist@example.net>; Fri, 14 Nov 2003 09:05:49 +0100 (CET)' =>
  '[ ip=82.65.66.244 rdns=lns-p19-8-82-65-66-244.adsl.proxad.net helo=asterix.laurier.org by=postfix3-2.free.fr ident= envfrom= id=7BACDC372 auth= msa=0 ]',

  'from 0 ([61.31.135.91]) by bass.bass.com.eg with Microsoft SMTPSVC(5.0.2195.6713); Tue, 21 Sep 2004 08:59:06 +0300' =>
  '[ ip=61.31.135.91 rdns= helo=0 by=bass.bass.com.eg ident= envfrom= intl=0 id= auth= msa=0 ]',

  'from helene8.i.pinwand.net (helene.cats.ms) [10.0.8.6.13219] (mail) by lisbeth.i.pinwand.net with esmtp (Exim 3.35 #1 (Debian)) id 1CO5y7-0001vC-00; Sun, 31 Oct 2004 04:01:23 +0100' =>
  '[ ip=10.0.8.6 rdns=helene8.i.pinwand.net helo=helene.cats.ms by=lisbeth.i.pinwand.net ident= envfrom= intl=0 id=1CO5y7-0001vC-00 auth= msa=0 ]',

  'from inet-vrs-05.redmond.corp.microsoft.com ([157.54.6.157]) by INET-IMC-05.redmond.corp.microsoft.com with Microsoft SMTPSVC(5.0.2195.6624); Thu, 6 Mar 2003 12:02:35 -0800' =>
  '[ ip=157.54.6.157 rdns= helo=inet-vrs-05.redmond.corp.microsoft.com by=INET-IMC-05.redmond.corp.microsoft.com ident= envfrom= id= auth= msa=0 ]',

  'from tthompson ([217.35.105.172] unverified) by mail.neosinteractive.com with Microsoft SMTPSVC(5.0.2195.5329); Tue, 11 Mar 2003 13:23:01 +0000' =>
  '[ ip=217.35.105.172 rdns= helo=tthompson by=mail.neosinteractive.com ident= envfrom= id= auth= msa=0 ]',

  'from mx56.pirmateh.us (64.119.196.56.rev.iwaynetworks.com [64.119.196.56] (may be forged)) by mail.core.obfugenedata.com (8.13.1/8.13.1) with ESMTP id i8FJcSRZ007847 for <othmar.pfannes@obfugenedata.com>; Wed, 15 Sep 2004 21:38:31 +0200' =>
  '[ ip=64.119.196.56 rdns=64.119.196.56.rev.iwaynetworks.com helo=mx56.pirmateh.us by=mail.core.obfugenedata.com ident= envfrom= intl=0 id=i8FJcSRZ007847 auth= msa=0 ]',

  'from 0 ([61.31.138.57] RDNS failed) by nccdi.com with Microsoft SMTPSVC(6.0.3790.0); Thu, 23 Sep 2004 08:51:06 -0700' =>
  '[ ip=61.31.138.57 rdns= helo=0 by=nccdi.com ident= envfrom= id= auth= msa=0 ]',

  'from ([192.168.1.205:50387] helo=i6.prod.democracyinaction.com) by m12.prod.democracyinaction.com (ecelerity 2.1.1.3 r(11743)) with ESMTP id 80/0A-02454-4DCB6054 for <example@vandinter.org>; Tue, 12 Sep 2006 09:57:40 -0400' =>
  '[ ip=192.168.1.205 rdns= helo=i6.prod.democracyinaction.com by=m12.prod.democracyinaction.com ident= envfrom= id=80/0A-02454-4DCB6054 auth= msa=0 ]',

  'from [127.0.0.1] ([127.0.0.1:50024]) by bm1-13.ed10.com (ecelerity 2.1.1.8 r(12431)) with ECSTREAM id 10/BD-03444-F4DB6054 for <example@vandinter.org>; Tue, 12 Sep 2006 09:59:43 -0400' =>
  '[ ip=127.0.0.1 rdns= helo= by=bm1-13.ed10.com ident= envfrom= id=10/BD-03444-F4DB6054 auth= msa=0 ]',

  'from ([67.91.233.27:53798] helo=eclectic.kluge.net) by idunn.apache.osuosl.org (ecelerity 2.1 r(10620)) with ESMTP id 5A/F0-04030-76FF6054 for <dev@spamassassin.apache.org>; Tue, 12 Sep 2006 11:41:44 -0700' =>
  '[ ip=67.91.233.27 rdns= helo=eclectic.kluge.net by=idunn.apache.osuosl.org ident= envfrom= id=5A/F0-04030-76FF6054 auth= msa=0 ]',

  'from klqe.net (unknown [192.168.50.50]) by mail.dropinsolutions.com (Postfix) with ESMTP id 62F9114047; Sun, 15 Feb 2004 14:29:04 -0500 (EST)' =>
  '[ ip=192.168.50.50 rdns= helo=klqe.net by=mail.dropinsolutions.com ident= envfrom= id=62F9114047 auth= msa=0 ]',

  'from Minstrel ([82.0.67.38]) by mta07-svc.ntlworld.com (InterMail vM.4.01.03.37 201-229-121-137-20020806) with ESMTP id <20031220035023.GCFK2588.mta07-svc.ntlworld.com@Minstrel> for <postmaster@internetgremlin.com>; Sat, 20 Dec 2003 03:50:23 +0000' =>
  '[ ip=82.0.67.38 rdns= helo=Minstrel by=mta07-svc.ntlworld.com ident= envfrom= id=20031220035023.GCFK2588.mta07-svc.ntlworld.com@Minstrel auth= msa=0 ]',

  'from cs.helsinki.fi ([::ffff:218.11.152.141]) by mail.cs.helsinki.fi with esmtp; Mon, 18 Aug 2003 15:37:48 +0300' =>
  '[ ip=218.11.152.141 rdns= helo=cs.helsinki.fi by=mail.cs.helsinki.fi ident= envfrom= id= auth= msa=0 ]',

  'from m165.4superdeals.biz (softdnserr [::ffff:64.235.238.165]) by mail.cs.helsinki.fi with esmtp; Sun, 17 Aug 2003 19:30:42 +0300' =>
  '[ ip=64.235.238.165 rdns= helo=m165.4superdeals.biz by=mail.cs.helsinki.fi ident= envfrom= id= auth= msa=0 ]',

  'from hotmail.com (bay1-f95.bay1.hotmail.com [65.54.245.95]) by Daffy.timing.com;' =>
  '[ ip=65.54.245.95 rdns=bay1-f95.bay1.hotmail.com helo=hotmail.com by=Daffy.timing.com ident= envfrom= id= auth= msa=0 ]',

  'from 24.8.231.233 by by1fd.bay1.hotmail.msn.com with HTTP; Wed, 17 Mar 2004 02:12:31 GMT' =>
  '[ ip=24.8.231.233 rdns= helo= by=by1fd.bay1.hotmail.msn.com ident= envfrom= id= auth=HTTP msa=0 ]',

  'from hotmail.com (something.com [65.54.245.95]) at just after 10pm by Daffy.timing.com on a Friday (CrazyMTA) (envelope-from <foo@example.com>) with TFTP' =>
  '[ ip=65.54.245.95 rdns=something.com helo=hotmail.com by=Daffy.timing.com ident= envfrom=foo@example.com id= auth= msa=0 ]',

  'from postfix3-2.free.fr (foobar@213.228.0.139) by totor.example.net with SMTP; 14 Nov 2003 08:05:50 -0000' =>
  '[ ip=213.228.0.139 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= id= auth= msa=0 ]',

  'from asterix.laurier.org (lns-p19-8-82-65-66-244.adsl.proxad.net [82.65.66.244]) by postfix3-2.free.fr (Postfix) with ESMTP id 7BACDC372 for <michel@example.net>; Fri, 14 Nov 2003 09:05:49 +0100 (CET)' =>
  '[ ip=82.65.66.244 rdns=lns-p19-8-82-65-66-244.adsl.proxad.net helo=asterix.laurier.org by=postfix3-2.free.fr ident= envfrom= id=7BACDC372 auth= msa=0 ]',

  'from unknown (HELO feux01a-isp) (213.199.4.210) by totor.example.net with SMTP; 1 Nov 2003 07:05:19 -0000' =>
  '[ ip=213.199.4.210 rdns= helo=feux01a-isp by=totor.example.net ident= envfrom= id= auth= msa=0 ]',

  'from x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk (benelli@80.167.158.170) by totor.example.net with SMTP; 5 Nov 2003 23:18:42 -0000' =>
  '[ ip=80.167.158.170 rdns=x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk helo=x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk by=totor.example.net ident=benelli envfrom= id= auth= msa=0 ]',

  'from adsl-207-213-27-129.dsl.lsan03.pacbell.net (HELO merlin.net.au) (Owner50@207.213.27.129) by totor.example.net with SMTP; 10 Nov 2003 06:30:34 -0000' =>
  '[ ip=207.213.27.129 rdns=adsl-207-213-27-129.dsl.lsan03.pacbell.net helo=merlin.net.au by=totor.example.net ident=Owner50 envfrom= id= auth= msa=0 ]',

  'from imo-m01.mx.aol.com ([64.12.136.4] verified) by xxx.com (CommuniGate Pro SMTP 4.1.8) with ESMTP id 875522 for yyy@xxx.com; Tue, 03 Feb 2004 08:37:38 -0800' =>
  '[ ip=64.12.136.4 rdns= helo=imo-m01.mx.aol.com by=xxx.com ident= envfrom= id=875522 auth= msa=0 ]',

  'from [65.17.198.50] (HELO 123greetings.info) by mail.wcg.org (CommuniGate Pro SMTP 5.1.3) with SMTP id 19467966 for xxxx@wcg.org; Fri, 08 Dec 2006 08:40:46 -0800' =>
  '[ ip=65.17.198.50 rdns= helo=123greetings.info by=mail.wcg.org ident= envfrom= id=19467966 auth= msa=0 ]',

  'from [128.114.2.223] (account user@example.edu HELO [10.10.10.10]) by silver.ucsc.edu (CommuniGate Pro SMTP 4.3.7) with ESMTPSA id 88402416 for user@example.edu; Mon, 04 Dec 2006 13:15:07 -0800' =>
  '[ ip=128.114.2.223 rdns= helo=!10.10.10.10! by=silver.ucsc.edu ident= envfrom= id=88402416 auth=ESMTPSA msa=0 ]',

  'from [128.114.2.223] (account user@example.edu) by tin.ucsc.edu (CommuniGate Pro WebUser 4.3.7) with HTTP id 109780632 for user@example.edu; Tue, 05 Dec 2006 11:17:51 -0800' =>
  '[ ip=128.114.2.223 rdns= helo= by=tin.ucsc.edu ident= envfrom= id=109780632 auth=HTTP msa=0 ]',

  'from bigass1.example.com ([66.199.2.3]) by slim1.example.com with esmtp; Tue, 06 Jan 2004 23:56:09 +0000' =>
  '[ ip=66.199.2.3 rdns= helo=bigass1.example.com by=slim1.example.com ident= envfrom= id= auth= msa=0 ]',

  'from a1200 ([24.83.2.4]) (AUTH: LOGIN mitch@example.com) by bigass1.example.com with esmtp; Tue, 06 Jan 2004 23:56:09 +0000' =>
  '[ ip=24.83.2.4 rdns= helo=a1200 by=bigass1.example.com ident= envfrom= id= auth=LOGIN msa=0 ]',

  'from bigass1.example.com (ns1.example.com [66.199.2.5]) by fiat.example.edu (8.12.10/8.12.10) with ESMTP id i06MBJ6U020255 for <broot@example.edu>; Tue, 6 Jan 2004 16:11:19 -0600' =>
  '[ ip=66.199.2.5 rdns=ns1.example.com helo=bigass1.example.com by=fiat.example.edu ident= envfrom= id=i06MBJ6U020255 auth= msa=0 ]',

  'from a1200 ([24.83.2.6]) (AUTH: LOGIN mitch@example.com) by bigass1.example.com with esmtp; Tue, 06 Jan 2004 22:09:53 +0000' =>
  '[ ip=24.83.2.6 rdns= helo=a1200 by=bigass1.example.com ident= envfrom= id= auth=LOGIN msa=0 ]',

  'from a1200 ([24.83.2.7]) (AUTH: LOGIN mitch@example.com) by bigass1.example.com with esmtp; Tue, 06 Jan 2004 23:56:09 +0000' =>
  '[ ip=24.83.2.7 rdns= helo=a1200 by=bigass1.example.com ident= envfrom= id= auth=LOGIN msa=0 ]',

  'from postfix3-2.free.fr (HELO machine.domain.com) (foobar@213.228.20.149) by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000' =>
  '[ ip=213.228.20.149 rdns=postfix3-2.free.fr helo=machine.domain.com by=totor.example.net ident=foobar envfrom= id= auth= msa=0 ]',

  'from postfix3-2.free.fr (213.228.0.159) by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000' =>
  '[ ip=213.228.0.159 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident= envfrom= id= auth= msa=0 ]',

  'from postfix3-2.free.fr (foobar@213.228.0.169) by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000' =>
  '[ ip=213.228.0.169 rdns=postfix3-2.free.fr helo=postfix3-2.free.fr by=totor.example.net ident=foobar envfrom= id= auth= msa=0 ]',

  'from unknown (HELO machine.domain.com) (foobar@213.228.0.179) by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000' =>
  '[ ip=213.228.0.179 rdns= helo=machine.domain.com by=totor.example.net ident=foobar envfrom= id= auth= msa=0 ]',

  'from unknown (HELO machine.domain.com) (213.228.0.189) by totor.example.net with SMTP; 14 Nov 2003 08:31:29 -0000' =>
  '[ ip=213.228.0.189 rdns= helo=machine.domain.com by=totor.example.net ident= envfrom= id= auth= msa=0 ]',

  'from loki.komtel.net (212.7.146.145) by totor.example.net with SMTP; 16 Nov 2003 04:53:54 -0000' =>
  '[ ip=212.7.146.145 rdns=loki.komtel.net helo=loki.komtel.net by=totor.example.net ident= envfrom= id= auth= msa=0 ]',

  'from c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com (66.169.197.134) by totor.example.net with SMTP; 16 Nov 2003 05:59:32 -0000' =>
  '[ ip=66.169.197.134 rdns=c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com helo=c66.169.197.134.ts46v-19.pkcty.ftwrth.tx.charter.com by=totor.example.net ident= envfrom= id= auth= msa=0 ]',

  'from dyn-81-166-39-132.ppp.tiscali.fr (81.166.39.132) by cpmail.dk.tiscali.com (6.7.018) id 3FE6899B004FE7A4; Thu, 1 Jan 2004 05:28:49 +0100' =>
  '[ ip=81.166.39.132 rdns=dyn-81-166-39-132.ppp.tiscali.fr helo=dyn-81-166-39-132.ppp.tiscali.fr by=cpmail.dk.tiscali.com ident= envfrom= id=3FE6899B004FE7A4 auth= msa=0 ]',

  'from unknown (HELO [81.64.159.45]) ([81.64.159.45]) (envelope-sender <xyz@example.org>) by 212.198.2.120 (qmail-ldap-1.03) with SMTP for <zyx@somewhere.net>; 28 Nov 2003 20:44:45 -0000' =>
  '[ ip=81.64.159.45 rdns= helo=!81.64.159.45! by=212.198.2.120 ident= envfrom=xyz@example.org id= auth= msa=0 ]',

  'from mx10.topofferz.net (HELO ) (69.6.60.10) by blazing.fooooo.org with SMTP; 3 Mar 2004 20:34:38 -0000' =>
  '[ ip=69.6.60.10 rdns=mx10.topofferz.net helo= by=blazing.fooooo.org ident= envfrom= id= auth= msa=0 ]',

  'from email.com (unknown [222.32.65.3]) by eclectic.kluge.net (Postfix) with ESMTP id 33DC4416F20 for <unknown@kluge.net>; Mon,  1 Mar 2004 01:09:44 -0500 (EST)' =>
  '[ ip=222.32.65.3 rdns= helo=email.com by=eclectic.kluge.net ident= envfrom= id=33DC4416F20 auth= msa=0 ]',

  'from kluge.net (unknown [222.156.78.32]) by eclectic.kluge.net (Postfix) with SMTP id CE1BA416F20 for <unknown@kluge.net>; Mon,  1 Mar 2004 13:11:31 -0500 (EST)' =>
  '[ ip=222.156.78.32 rdns= helo=kluge.net by=eclectic.kluge.net ident= envfrom= id=CE1BA416F20 auth= msa=0 ]',

  'from xjwrvjq (unknown [222.54.106.152]) by eclectic.kluge.net (Postfix) with SMTP id ED474416F20 for <unknown@eclectic.kluge.net>; Tue,  2 Mar 2004 12:51:44 -0500' =>
  '[ ip=222.54.106.152 rdns= helo=xjwrvjq by=eclectic.kluge.net ident= envfrom= id=ED474416F20 auth= msa=0 ]',

  'from europa21.inetsiteworld.net (europa21.inetsiteworld.net [217.110.206.5]) by mx1.redhat.com (8.12.10/8.12.10) with SMTP id i28CUmST012272 for <fedora-list@redhat.com>; Mon, 8 Mar 2004 07:30:48 -0500' =>
  '[ ip=217.110.206.5 rdns=europa21.inetsiteworld.net helo=europa21.inetsiteworld.net by=mx1.redhat.com ident= envfrom= id=i28CUmST012272 auth= msa=0 ]',

  'from SpamControl_operated_by_INetSiteWorld (localhost [127.0.0.1]) by europa21.inetsiteworld.net (8.12.9/8.12.7-jokey) with ESMTP id i28CNuck014319 for <fedora-list@redhat.com>; Mon, 8 Mar 2004 13:23:57 +0100' =>
  '[ ip=127.0.0.1 rdns=localhost helo=SpamControl_operated_by_INetSiteWorld by=europa21.inetsiteworld.net ident= envfrom= id=i28CNuck014319 auth= msa=0 ]',

  'from 212.202.243.194 ([212.202.243.194] helo=blackstar) by SpamControl_operated_by_INetSiteWorld ;  8 Mar 04 12:23:56 -0000' =>
  '[ ip=212.202.243.194 rdns= helo=blackstar by=SpamControl_operated_by_INetSiteWorld ident= envfrom= id= auth= msa=0 ]',

  'from mail00.svc.cra.dublin.eircom.net (mail00.svc.cra.dublin.eircom.net [159.134.118.16]) by amgod.boxhost.net (Postfix) with SMTP id 0ACFC31014D for <zzzz@zzzz.org>; Mon,  8 Mar 2004 23:59:19 +0000 (GMT)' =>
  '[ ip=159.134.118.16 rdns=mail00.svc.cra.dublin.eircom.net helo=mail00.svc.cra.dublin.eircom.net by=amgod.boxhost.net ident= envfrom= id=0ACFC31014D auth= msa=0 ]',

  'from 83-70-48-2.bas2.dbn.dublin.eircom.net (HELO ?192.168.23.32?) (83.70.48.2) by mail00.svc.cra.dublin.eircom.net (qp 87263) with SMTP; 8 Mar 2004 23:59:05 -0000' =>
  '[ ip=83.70.48.2 rdns=83-70-48-2.bas2.dbn.dublin.eircom.net helo=?192.168.23.32? by=mail00.svc.cra.dublin.eircom.net ident= envfrom= id= auth= msa=0 ]',

  'from smtp3.es.uci.edu (smtp3.es.uci.edu [128.200.80.6]) by amgod.boxhost.net (Postfix) with ESMTP id 87D0A310091 for <zzzzz@jmason.org>; Tue,  9 Mar 2004 00:07:59 +0000 (GMT)' =>
  '[ ip=128.200.80.6 rdns=smtp3.es.uci.edu helo=smtp3.es.uci.edu by=amgod.boxhost.net ident= envfrom= id=87D0A310091 auth= msa=0 ]',

  'from rigel.oac.uci.edu (rigel.oac.uci.edu [128.200.80.22]) by smtp3.es.uci.edu (8.12.8/8.12.8) with ESMTP id i2907ZaF008726 for <zzzzz@jmason.org>; Mon, 8 Mar 2004 16:07:35 -0800' =>
  '[ ip=128.200.80.22 rdns=rigel.oac.uci.edu helo=rigel.oac.uci.edu by=smtp3.es.uci.edu ident= envfrom= id=i2907ZaF008726 auth= msa=0 ]',

  'from list.brainbuzz.com (63.146.189.86:23198) by mx1.yourtech.net with [XMail 1.20 ESMTP Server] id <S72E> for <jjjjjjjjjj@obfuscatedellingson.org> from <bounce-cscommunity-11965901@list.obfuscatedzzzzzzz.com>; Sat, 18 Sep 2004 23:17:54 -0500' =>
  '[ ip=63.146.189.86 rdns= helo=list.brainbuzz.com by=mx1.yourtech.net ident= envfrom=bounce-cscommunity-11965901@list.obfuscatedzzzzzzz.com id=S72E auth= msa=0 ]',

  'from list.brainbuzz.com ([63.146.189.86]:23198) by mx1.yourtech.net with [XMail 1.20 ESMTP Server] id <S72E> for <jjjjjjjjjj@obfuscatedellingson.org> from <bounce-cscommunity-11965901@list.obfuscatedzzzzzzz.com>; Sat, 18 Sep 2004 23:17:54 -0500' =>
  '[ ip=63.146.189.86 rdns= helo=list.brainbuzz.com by=mx1.yourtech.net ident= envfrom=bounce-cscommunity-11965901@list.obfuscatedzzzzzzz.com id=S72E auth= msa=0 ]',

  'from 211.245.85.228  (EHLO ) (211.245.85.228) by mta232.mail.scd.yahoo.com with SMTP; Sun, 25 Jan 2004 00:24:37 -0800' =>
  '[ ip=211.245.85.228 rdns=211.245.85.228 helo= by=mta232.mail.scd.yahoo.com ident= envfrom= id= auth= msa=0 ]',
  
  'from dsl092-076-133.bos1.dsl.speakeasy.net ([66.92.76.133] helo=pendaran.arborius.net) by sc8-sf-mx1.sourceforge.net with esmtp (TLSv1:AES256-SHA:256) (Exim 4.41) id 1CIlfc-0003Pa-8W for xvoice-user@lists.sourceforge.net; Sat, 16 Oct 2004 03:20:18 -0700' =>
  '[ ip=66.92.76.133 rdns=dsl092-076-133.bos1.dsl.speakeasy.net helo=pendaran.arborius.net by=sc8-sf-mx1.sourceforge.net ident= envfrom= id=1CIlfc-0003Pa-8W auth= msa=0 ]',

  'from gilmore.ael.be ([158.64.60.71]) by castlerea.stdlib.net with esmtp (TLSv1:DES-CBC3-SHA:168) (Exim 4.41) id 1CIusZ-00049K-45 for e-voting@lists.stdlib.net; Sat, 16 Oct 2004 21:10:16 +0100' =>
  '[ ip=158.64.60.71 rdns=gilmore.ael.be helo=gilmore.ael.be by=castlerea.stdlib.net ident= envfrom= id=1CIusZ-00049K-45 auth= msa=0 ]',

  'from rubel.csumb.edu (rubel.csumb.edu [198.189.237.214]) (using TLSv1 with cipher DHE-RSA-AES256-SHA (256/256 bits)) (No client certificate requested) by sf1.isc.org (Postfix) with ESMTP id 23587284EE for <bind-users@isc.org>; Sat, 16 Oct 2004 23:32:19 +0000 (UTC) (envelope-from snort@csumb.edu)' =>
  '[ ip=198.189.237.214 rdns=rubel.csumb.edu helo=rubel.csumb.edu by=sf1.isc.org ident= envfrom=snort@csumb.edu id=23587284EE auth= msa=0 ]',

  'from p50894de7.dip0.t-ipconnect.de ([80.137.77.231]:11218 helo=sandpiper) by mail1.isc.de with esmtp (TLSv1:RC4-SHA:128) (Exim 4.04) id 1CJaZW-0006rU-00 for linux-thinkpad@linux-thinkpad.org; Mon, 18 Oct 2004 18:41:23 +0200' =>
  '[ ip=80.137.77.231 rdns=p50894de7.dip0.t-ipconnect.de helo=sandpiper by=mail1.isc.de ident= envfrom= id=1CJaZW-0006rU-00 auth= msa=0 ]',
  
  'from [192.168.1.3] (80-28-223-208.adsl.nuria.telefonica-data.net [80.28.223.208]) (authenticated bits=0) by mac.com (Xserve/smtpin08/MantshX 4.0) with ESMTP id i8NIdH8G002812 for ...' =>
  '[ ip=80.28.223.208 rdns=80-28-223-208.adsl.nuria.telefonica-data.net helo=!192.168.1.3! by=mac.com ident= envfrom= id=i8NIdH8G002812 auth=Sendmail msa=0 ]',

  'from perceptions.couk.com (81.103.146.112) by n082.sc1.cp.net (7.0.030.2) (authenticated as r.dickenson) id 414B418B002D65F1 for forteana@yahoogroups.com; Thu, 23 Sep 2004 18:42:17 +0000' =>
  '[ ip=81.103.146.112 rdns=perceptions.couk.com helo=perceptions.couk.com by=n082.sc1.cp.net ident= envfrom= id=414B418B002D65F1 auth=CriticalPath msa=0 ]',

  'from 141.44.167.13 (p83.129.191.197.tisdip.tiscali.de [83.129.191.197]) (authenticated bits=0) by sunny.urz.uni-magdeburg.de (8.12.10/8.12.10) with ESMTP id i8ND9v0N017746 (version=TLSv1/SSLv3 cipher=RC4-MD5 bits=128 verify=NO) for <ilug@linux.ie>; Thu, 23 Sep 2004 15:09:59 +0200' =>
  '[ ip=83.129.191.197 rdns=p83.129.191.197.tisdip.tiscali.de helo=141.44.167.13 by=sunny.urz.uni-magdeburg.de ident= envfrom= id=i8ND9v0N017746 auth=Sendmail msa=0 ]',
  
  'from rousalka.dyndns.org (81.64.155.54) by mx.laposte.net (7.0.028) (authenticated as Nicolas.Mailhot) id 413489B100C9C1FD for fedora-devel-list@redhat.com; Tue, 28 Sep 2004 21:43:43 +0200' =>
  '[ ip=81.64.155.54 rdns=rousalka.dyndns.org helo=rousalka.dyndns.org by=mx.laposte.net ident= envfrom= id=413489B100C9C1FD auth=CriticalPath msa=0 ]',

  'from [10.0.0.253] (82-68-189-22.dsl.in-addr.zen.co.uk [82.68.189.22]) (authenticated (0 bits)) by ensim.rackshack.net (8.11.6/8.11.6) with ESMTP id i8TAFAI25021 for <discuss@lists.surbl.org>; Wed, 29 Sep 2004 10:15:10 GMT' =>
  '[ ip=82.68.189.22 rdns=82-68-189-22.dsl.in-addr.zen.co.uk helo=!10.0.0.253! by=ensim.rackshack.net ident= envfrom= id=i8TAFAI25021 auth=Sendmail msa=0 ]',

  'from [213.174.165.187] (213.174.165.187) by vsmtp1.tin.it (7.0.027) (authenticated as mgiammarco@virgilio.it) id 416A525B0000A53B for linux-thinkpad@linux-thinkpad.org; Mon, 11 Oct 2004 12:52:46 +0200' =>
  '[ ip=213.174.165.187 rdns=!213.174.165.187! helo=!213.174.165.187! by=vsmtp1.tin.it ident= envfrom= id=416A525B0000A53B auth=CriticalPath msa=0 ]',

  'from [10.10.10.215] (Collation_Software.demarc.cogentco.com [66.250.6.18]) (authenticated bits=0) by waste.org (8.12.3/8.12.3/Debian-6.6) with ESMTP id i46MehGO005108 for <fork@xent.com>; Thu, 6 May 2004 17:40:44-0500' =>
  '[ ip=66.250.6.18 rdns=Collation_Software.demarc.cogentco.com helo=!10.10.10.215! by=waste.org ident= envfrom= id=i46MehGO005108 auth=Sendmail msa=0 ]',

  'from dsl-082-082-143-115.arcor-ip.net (dsl-082-083-139-045.arcor-ip.net [82.83.139.45]) (authenticated bits=0) by postman.arcor.de (8.13.0.PreAlpha4/8.13.0.PreAlpha4) with ESMTP id i2U75jD1003350 for <linux-thinkpad@linux-thinkpad.org>; Tue, 30 Mar 2004 09:05:45 +0200 (MEST)' =>
  '[ ip=82.83.139.45 rdns=dsl-082-083-139-045.arcor-ip.net helo=dsl-082-082-143-115.arcor-ip.net by=postman.arcor.de ident= envfrom= id=i2U75jD1003350 auth=Sendmail msa=0 ]',

  'from MARISELA (dsl-189-149-70-163.prod-infinitum.com.mx [189.149.70.163] (may be forged)) (authenticated bits=0) by mail.legosoft.com.mx (8.13.8/8.13.8) with ESMTP id kB3G26P6019032 for <rberber@cactus-soft.dyndns.org>; Sun, 3 Dec 2006 10:02:16 -0600 (CST)' =>
  '[ ip=189.149.70.163 rdns=dsl-189-149-70-163.prod-infinitum.com.mx helo=MARISELA by=mail.legosoft.com.mx ident= envfrom= id=kB3G26P6019032 auth=Sendmail msa=0 ]',
  
  'from p5483b7c0.dip.t-dialin.net ([84.131.183.192] helo=192.168.1.23) by moonflower.de with asmtp (TLS-1.0:RSA_ARCFOUR_MD5:16) (Exim 4.34) id 1CIoQP-0006SN-GV for linux-thinkpad@linux-thinkpad.org; Sat, 16 Oct 2004 15:16:47 +0200' =>
  '[ ip=84.131.183.192 rdns=p5483b7c0.dip.t-dialin.net helo=192.168.1.23 by=moonflower.de ident= envfrom= id=1CIoQP-0006SN-GV auth=asmtp msa=0 ]',

  'from bgp01132961bgs.ypeast01.mi.comcast.net ([68.42.119.201] helo=moonweaver.home.awesomeplay.com) by outbound.mailhop.org with esmtpsa (TLSv1:RC4-SHA:128) (Exim 4.42) id 1CJic5-00067m-U7' =>
  '[ ip=68.42.119.201 rdns=bgp01132961bgs.ypeast01.mi.comcast.net helo=moonweaver.home.awesomeplay.com by=outbound.mailhop.org ident= envfrom= id=1CJic5-00067m-U7 auth=esmtpsa msa=0 ]',

  'from gorkcomputer (my.dns.com [1.2.3.4]) (AUTH: LOGIN gork@mydomain.com, SSL: TLSv1/SSLv3,128bits,RC4-MD5) by mydomain.com with esmtp; Thu, 10 Nov 2005 08:24:21 -0600 id 000000DB.43735815.00001E11' =>
  '[ ip=1.2.3.4 rdns=my.dns.com helo=gorkcomputer by=mydomain.com ident= envfrom= id=000000DB.43735815.00001E11 auth=LOGIN msa=0 ]',

  'FROM hackers.mr.itd.umich.edu (smtp.mail.umich.edu [141.211.14.81]) BY madman.mr.itd.umich.edu ID 434B508E.174A6.13932 ; 11 Oct 2005 01:41:34 -0400' =>
  '[ ip=141.211.14.81 rdns=smtp.mail.umich.edu helo=hackers.mr.itd.umich.edu by=madman.mr.itd.umich.edu ident= envfrom= id=434B508E.174A6.13932 auth= msa=0 ]',

  'FROM [192.168.1.24] (s233-64-90-216.try.wideopenwest.com [64.233.216.90]) BY hackers.mr.itd.umich.edu ID 434B5051.8CDE5.15436 ; 11 Oct 2005 01:40:33 -0400' =>
  '[ ip=64.233.216.90 rdns=s233-64-90-216.try.wideopenwest.com helo=!192.168.1.24! by=hackers.mr.itd.umich.edu ident= envfrom= id=434B5051.8CDE5.15436 auth= msa=0 ]',

  'from TCE-E-7-182-54.bta.net.cn(202.106.182.54) via SMTP by st.tahina.priv.at, id smtpdEDUB8h; Sun Nov 13 14:50:12 2005' =>
  '[ ip=202.106.182.54 rdns=TCE-E-7-182-54.bta.net.cn helo= by=st.tahina.priv.at ident= envfrom= id=smtpdEDUB8h auth= msa=0 ]',

  'from pl027.nas934.d-osaka.nttpc.ne.jp(61.197.82.27), claiming to be "foo.woas.net" via SMTP by st.tahina.priv.at, id smtpd1PBsZT; Sun Nov 13 15:38:52 2005' =>
  '[ ip=61.197.82.27 rdns=pl027.nas934.d-osaka.nttpc.ne.jp helo=foo.woas.net by=st.tahina.priv.at ident= envfrom= id=smtpd1PBsZT auth= msa=0 ]',

  'from [206.51.230.145] (helo=t-online.de) by mxeu2.kundenserver.de with ESMTP (Nemesis), id 0MKpdM-1CkRpr14PF-000608; Fri, 31 Dec 2004 19:49:15 +0100' =>
  '[ ip=206.51.230.145 rdns= helo=t-online.de by=mxeu2.kundenserver.de ident= envfrom= id=0MKpdM-1CkRpr14PF-000608 auth= msa=0 ]',

  'from Amazon.com ([66.0.37.1]) by bi-staff1.beckman.uiuc.edu (8.12.8/8.12.8) with SMTP id k1SCIR87017358; Tue, 28 Feb 2006 06:18:27 -0600' =>
  '[ ip=66.0.37.1 rdns= helo=Amazon.com by=bi-staff1.beckman.uiuc.edu ident= envfrom= intl=0 id=k1SCIR87017358 auth= msa=0 ]',

  '(from KRYPTIK [70.20.57.51]) by host.name (NAVGW 2.5.2.12) with SMTP id M2006040415284308595 for <user@domain.co.uk>; Tue, 04 Apr 2006 15:28:45 +0100' =>
  '[ ip=70.20.57.51 rdns= helo=KRYPTIK by=host.name ident= envfrom= id=M2006040415284308595 auth= msa=0 ]',

  'from bar.example.org (bar.example.org [127.0.0.1]) (using TLSv1 with cipher DHE-RSA-AES256-SHA (256/256 bits)) (Client did not present a certificate) (Authenticated sender: sender.example.net) by foo.example.net (Postfix) with ESMTP id 44A8959ED6B0 for <recip@example.com>; Fri, 30 Jun 2006 08:02:00 +0100 (BST)' =>
  '[ ip=127.0.0.1 rdns=bar.example.org helo=bar.example.org by=foo.example.net ident= envfrom= id=44A8959ED6B0 auth=Postfix msa=0 ]',

  'from  ([172.16.1.78]) by email2.codeworksonline.com with Microsoft SMTPSVC(5.0.2195.6713); Wed, 6 Sep 2006 21:14:29 -0400' =>
  '[ ip=172.16.1.78 rdns= helo= by=email2.codeworksonline.com ident= envfrom= id= auth= msa=0 ]',

  'from (130.215.36.186) by mcafee.wpi.edu via smtp id 021b_7e19a55a_ea7e_11da_83a9_00304811e63a; Tue, 23 May 2006 13:06:35 -0400' =>
  '[ ip=130.215.36.186 rdns= helo= by=mcafee.wpi.edu ident= envfrom= id=021b_7e19a55a_ea7e_11da_83a9_00304811e63a auth= msa=0 ]',

  'from ([172.21.2.10]) by out-relay4.mtahq.org with ESMTP  id 4420961.8281; Tue, 22 Aug 2006 17:53:08 -0400' =>
  '[ ip=172.21.2.10 rdns= helo= by=out-relay4.mtahq.org ident= envfrom= id=4420961.8281 auth= msa=0 ]',

  'from 10.165.130.62 by CNNIMAIL12.CNN.COM (SMTPL release 1.0d) with TCP; Fri, 1 Sep 2006 20:28:14 -0400' =>
  '[ ip=10.165.130.62 rdns= helo= by=CNNIMAIL12.CNN.COM ident= envfrom= id= auth= msa=0 ]',

  'from DPLAPTOP ( 72.242.176.162) by mail.puryear-it.com (Scalix SMTP Relay 10.0.1.3) via ESMTP; Fri, 23 Jun 2006 16:39:47 -0500 (CDT)' =>
  '[ ip=72.242.176.162 rdns= helo=DPLAPTOP by=mail.puryear-it.com ident= envfrom= id= auth= msa=0 ]',

  'from av0001.technodiva.com (localhost [127.0.0.1])by  localhost.technodiva.com (Postfix) with ESMTP id 846CF2117for  <proftp-user@lists.sourceforge.net>; Mon,  7 Aug 2006 17:48:07 +0200 (MEST)' =>
  '[ ip=127.0.0.1 rdns=localhost helo=av0001.technodiva.com by=localhost.technodiva.com ident= envfrom= id=846CF2117for auth= msa=0 ]',

  'from server040.webpack.hosteurope.de ([80.237.130.48]:52313) by vps832469583.serverpool.info with esmtps (TLS-1.0:DHE_RSA_3DES_EDE_CBC_SHA:24) (Exim 4.50) id 1GzVLs-0002Oz-7b for axel@axelcity.de; Wed, 27 Dec 2006 10:45:49 +0100' =>
  '[ ip=80.237.130.48 rdns=server040.webpack.hosteurope.de helo=server040.webpack.hosteurope.de by=vps832469583.serverpool.info ident= envfrom= intl=0 id=1GzVLs-0002Oz-7b auth= msa=0 ]',

  'from gate.jakob.de ([217.145.101.130]:60178 helo=gate2.jakob.de) by vps832469583.serverpool.info (envelope-from <support@verleihshop.de>) with esmtps (TLS-1.0:DHE_RSA_3DES_EDE_CBC_SHA:24) (Exim 4.50) id 1H3KFP-0005pI-08 for dvd@axelcity.de; Sat, 06 Jan 2007 23:42:55 +0100' =>
  '[ ip=217.145.101.130 rdns=gate.jakob.de helo=gate2.jakob.de by=vps832469583.serverpool.info ident= envfrom=support@verleihshop.de intl=0 id=1H3KFP-0005pI-08 auth= msa=0 ]',

  'from dslb-082-083-045-064.pools.arcor-ip.net (EHLO homepc) [82.83.45.64] by mail.gmx.net (mp010) with SMTP; 03 Feb 2007 13:13:47 +0100' =>
  '[ ip=82.83.45.64 rdns=dslb-082-083-045-064.pools.arcor-ip.net helo=homepc by=mail.gmx.net ident= envfrom= intl=0 id= auth= msa=0 ]'

);

my $sa = create_saobj();
ok($sa);

my $msg = $sa->parse("\n", 0);
$msg->{metadata}->{is_dns_available} = 0;
ok($msg);

foreach my $hdr (sort keys %data) {
  my $expected = $data{$hdr};

  my $relays;
  my $parsed = $msg->{metadata}->parse_received_line($hdr);

  if (!defined $parsed) {
    $relays = '[ unparseable ]';
  }
  elsif (!$parsed) {
    $relays = '';
  }
  else {
    $relays = $msg->{metadata}->make_relay_as_string($parsed);
  }

  # we don't care about this
  $expected =~ s/ intl=[01] / /gs;
  $relays =~ s/ intl=[01] / /gs;

  ok ($relays eq $expected);
  if ($relays ne $expected) {
    print "expected: $expected\n";
    print "got     : $relays\n";
    print "hdr sample: ", ('-' x 67), "\n$hdr\n", ('-' x 78), "\n\n";
  }
}
