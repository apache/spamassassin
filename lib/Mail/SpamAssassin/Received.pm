# $Id: Received.pm,v 1.1 2003/04/05 20:15:09 jmason Exp $

package Mail::SpamAssassin::Received;
1;

package Mail::SpamAssassin::PerMsgStatus;

use strict;
use bytes;

use vars qw{
};

# ---------------------------------------------------------------------------

sub parse_received_headers {
  my ($self) = @_;

  @{$self->{relays_untrusted}} = [ ];
  $self->{relays_untrusted_str} = '';

  my $hdrs = join ('', $self->get('Received'));
  $hdrs ||= '';

  $hdrs =~ s/\n[ \t]+/ /gs;

  # urgh, droppings. TODO: move into loop below?
  $hdrs =~ s/\n
	  Received:\ from\ \S*hotmail\.com\ \(\[${IP_ADDRESS}\]\)\ 
	      by\ \S+\.hotmail.com with\ Microsoft\ SMTPSVC\(5\.0\.\S+\);
	      \ \S+,\ \S+\ \S+\ \d{4}\ \d{2}:\d{2}:\d{2}\ \S+\n
	      /\n/gx;

  $hdrs =~ s/\n
	  Received:\ from\ mail\ pickup\ service\ by\ hotmail\.com
	      \ with\ Microsoft\ SMTPSVC;
	      \ \S+,\ \S+\ \S+\ \d{4}\ \d{2}:\d{2}:\d{2}\ \S+\n
	      /\n/gx;

  my @rcvd = ($hdrs =~ /^(\S.+\S)$/gm);
  foreach (@rcvd)
  {
    next if (/^$/);
    $self->parse_received_line ($_);
  }

  chop ($self->{relays_untrusted_str}); # remove trailing ws

  # add the stringified representation to the message object, so Bayes
  # and rules can use it
  $self->{msg}->delete_header ("X-SA-Relays-Untrusted");
  $self->{msg}->put_header ("X-SA-Relays-Untrusted",
				$self->{relays_untrusted_str});
}

# TODO: evaluate trust of headers and move trusted entries from
# "X-SA-Relays-Untrusted" into "X-SA-Relays-Trusted".

# ---------------------------------------------------------------------------

sub parse_received_line {
  my ($self) = shift;
  local ($_) = shift;

  s/\s+/ /gs;
  my $ip = '';
  my $helo = '';
  my $rdns = '';
  my $by = '';
  my $ident = '';

  # OK -- given knowledge of most Received header formats,
  # break them down.  We have to do something like this, because
  # some MTAs will swap position of rdns and helo -- so we can't
  # simply use simplistic regexps.

  if (/Exim/) {
    # one of the HUGE number of Exim formats :(
    # This must be scriptable.

    # Received: from [61.174.163.26] (helo=host) by sc8-sf-list1.sourceforge.net
    # with smtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t2z0-0001NX-00 for
    # <razor-users@lists.sourceforge.net>; Wed, 12 Mar 2003 01:57:10 -0800
    if (/^from \[(${IP_ADDRESS})\] \(helo=(\S+)\) by (\S+) /) {
      $ip = $1; $helo = $2; $by = $3;
    }

    # Received: from sc8-sf-list1-b.sourceforge.net ([10.3.1.13] helo=sc8-sf-list1.sourceforge.net) by sc8-sf-list2.sourceforge.net with esmtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t301-0007Bh-00; Wed, 12 Mar 2003 01:58:13 -0800
    # Received: from dsl092-072-213.bos1.dsl.speakeasy.net ([66.92.72.213] helo=blazing.arsecandle.org) by sc8-sf-list1.sourceforge.net with esmtp (Cipher TLSv1:DES-CBC3-SHA:168) (Exim 3.31-VA-mm2 #1 (Debian)) id 18lyuU-0007TI-00 for <SpamAssassin-talk@lists.sourceforge.net>; Thu, 20 Feb 2003 14:11:18 -0800
    # Received: from eclectic.kluge.net ([66.92.69.221] ident=[W9VcNxE2vKxgWHD05PJbLzIHSxcmZQ/O]) by sc8-sf-list1.sourceforge.net with esmtp (Cipher TLSv1:DES-CBC3-SHA:168) (Exim 3.31-VA-mm2 #1 (Debian)) id 18m0hT-00031I-00 for <spamassassin-talk@lists.sourceforge.net>; Thu, 20 Feb 2003 16:06:00 -0800
    elsif (/^from (\S+) \(\[(${IP_ADDRESS})\] helo=(\S+) ident=(\S+)\) by (\S+) /) {
      $rdns=$1; $ip = $2; $helo = $3; $ident = $4; $by = $5;
    }
    # (and without ident)
    elsif (/^from (\S+) \(\[(${IP_ADDRESS})\] helo=(\S+)\) by (\S+) /) {
      $rdns=$1; $ip = $2; $helo = $3; $by = $4;
    }

    # Received: from mail.ssccbelen.edu.pe ([216.244.149.154]) by yzordderrex
    # with esmtp (Exim 3.35 #1 (Debian)) id 18tqiz-000702-00 for
    # <jm@example.com>; Fri, 14 Mar 2003 15:03:57 +0000
    elsif (/^from (\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) /) {
      # speculation: Exim uses this format when rdns==helo. TODO: verify fully
      $rdns= $1; $ip = $2; $helo = $1; $by = $3;
    }
    elsif (/^from (\S+) \(\[(${IP_ADDRESS})\] ident=(\S+)\) by (\S+) /) {
      $rdns= $1; $ip = $2; $helo = $1; $ident = $3; $by = $4;
    }

    # Received: from boggle.ihug.co.nz [203.109.252.209] by grunt6.ihug.co.nz
    # with esmtp (Exim 3.35 #1 (Debian)) id 18SWRe-0006X6-00; Sun, 29 Dec 
    # 2002 18:57:06 +1300
    elsif (/^from (\S+) \[(${IP_ADDRESS})\] by (\S+) /) {
      $rdns= $1; $ip = $2; $helo = $1; $by = $3;
    }

    # else it's probably forged. fall through
  }

  # Received: from ns.elcanto.co.kr (66.161.246.58 [66.161.246.58]) by
  # mail.ssccbelen.edu.pe with SMTP (Microsoft Exchange Internet Mail Service
  # Version 5.5.1960.3) id G69TW478; Thu, 13 Mar 2003 14:01:10 -0500
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) with \S+ \(/) {
    $rdns= $2; $ip = $3; $helo = $1; $by = $4;
  }

  # from mail2.detr.gsi.gov.uk ([51.64.35.18] helo=ahvfw.dtlr.gsi.gov.uk) by mail4.gsi.gov.uk with smtp id 190K1R-0000me-00 for spamassassin-talk-admin@lists.sourceforge.net; Tue, 01 Apr 2003 12:33:46 +0100
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\](.*)\) by (\S+) with /) {
    $rdns = $1; $ip = $2; $by = $4;
    my $sub = ' '.$3.' ';
    if ($sub =~ / helo=(\S+) /) { $helo = $1; }
  }

  # Received: from mail1.insuranceiq.com (host66.insuranceiq.com [65.217.159.66] (may be forged)) by dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id h2F0c2x31856 for <jm@jmason.org>; Sat, 15 Mar 2003 00:38:03 GMT
  # from rev.net (natpool62.rev.net [63.148.93.62] (may be forged)) (authenticated) by mail.rev.net (8.11.4/8.11.4) with ESMTP id h0KKa7d32306 for <spamassassin-talk@lists.sourceforge.net>
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\].*\) by (\S+) \(/) {
    $rdns= $2; $ip = $3; $helo = $1; $by = $4;
  }

  # Received: from localhost (unknown [127.0.0.1])
  # by cabbage.jmason.org (Postfix) with ESMTP id A96E18BD97
  # for <jm@localhost>; Thu, 13 Mar 2003 15:23:15 -0500 (EST)
  elsif (/ \(Postfix\) with/) {
    /^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) /;
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
    if ($rdns eq 'unknown') { $rdns = ''; }
  }

  # Received: from 213.123.174.21 by lw11fd.law11.hotmail.msn.com with HTTP;
  # Wed, 24 Jul 2002 16:36:44 GMT
  elsif (/by (\S+\.hotmail\.msn\.com) /) {
    $by = $1;
    /^from (\S+) / and $ip = $1;
  }

  # Received: from unknown (HELO hotmail.com) (64.4.17.215) by
  # mta1.grp.scd.yahoo.com with SMTP; 24 Jul 2002 16:36:44 -0000
  elsif (/^from (\S+) \(HELO (\S+)\) \((${IP_ADDRESS})\) by (\S+) with /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # Received: from [193.220.176.134] by web40310.mail.yahoo.com via HTTP;
  # Wed, 12 Feb 2003 14:22:21 PST
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) via HTTP\;/) {
    $ip = $1; $by = $2;
  }

  # Received: from 192.168.5.158 ( [192.168.5.158]) as user jason@localhost by mail.reusch.net with HTTP; Mon, 8 Jul 2002 23:24:56 -0400
  elsif (/^from (\S+) \( \[(${IP_ADDRESS})\]\).*? by (\S+) /) {
    # TODO: is $1 helo?
    $ip = $2; $by = $3;
  }

  # Received: from (64.52.135.194 [64.52.135.194]) by mail.unearthed.com with ESMTP id BQB0hUH2 Thu, 20 Feb 2003 16:13:20 -0700 (PST)
  elsif (/^from \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from [65.167.180.251] by relent.cedata.com (MessageWall 1.1.0) with SMTP; 20 Feb 2003 23:57:15 -0000
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) /) {
    $ip = $1; $by = $2;
  }

  # Received: from acecomms [202.83.84.95] by mailscan.acenet.net.au [202.83.84.27] with SMTP (MDaemon.PRO.v5.0.6.R) for <spamassassin-talk@lists.sourceforge.net>; Fri, 21 Feb 2003 09:32:27 +1000
  elsif (/^from (\S+) \[(${IP_ADDRESS})\] by (\S+) \[(\S+)\] with /) {
    $helo = $1; $ip = $2;
    $by = $4; # use the IP addr for "by", more useful?
  }

  # Received: from BAY0-HMR08.adinternal.hotmail.com
  # (bay0-hmr08.bay0.hotmail.com [65.54.241.207]) by dogma.slashnull.org
  # (8.11.6/8.11.6) with ESMTP id h2DBpvs24047 for <webmaster@efi.ie>;
  # Thu, 13 Mar 2003 11:51:57 GMT
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) \(/) {
    # very similar to postfix, but actually sendmail.
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
    $rdns =~ s/([^\@]+)\@//g and $ident = $1;	# remove IDENT lookups
  }

  # Received: from mail.sxptt.zj.cn ([218.0.185.24]) by dogma.slashnull.org
  # (8.11.6/8.11.6) with ESMTP id h2FH0Zx11330 for <webmaster@efi.ie>;
  # Sat, 15 Mar 2003 17:00:41 GMT
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) \(/) { # sendmail
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from umr-mail7.umr.edu (umr-mail7.umr.edu [131.151.1.64]) via ESMTP by mrelay1.cc.umr.edu (8.12.1/) id h06GHYLZ022481; Mon, 6 Jan 2003 10:17:34 -0600
  # Received: from Agni (localhost [::ffff:127.0.0.1]) (TLS: TLSv1/SSLv3, 168bits,DES-CBC3-SHA) by agni.forevermore.net with esmtp; Mon, 28 Oct 2002 14:48:52 -0800
  # Received: from gandalf ([4.37.75.131]) (authenticated bits=0) by herald.cc.purdue.edu (8.12.5/8.12.5/herald) with ESMTP id g9JLefrm028228 for <spamassassin-talk@lists.sourceforge.net>; Sat, 19 Oct 2002 16:40:41 -0500 (EST)
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\).*? by (\S+) /) { # sendmail
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
  }
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\]\).*? by (\S+) /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from roissy (p573.as1.exs.dublin.eircom.net [159.134.226.61])
  # (authenticated bits=0) by slate.dublin.wbtsystems.com (8.12.6/8.12.6)
  # with ESMTP id g9MFWcvb068860 for <jm@jmason.org>;
  # Tue, 22 Oct 2002 16:32:39 +0100 (IST)
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\)(?: \(authenticated bits=\d+\)|) by (\S+) \(/) { # sendmail
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
  }

  # Received: from cabbage.jmason.org [127.0.0.1]
  # by localhost with IMAP (fetchmail-5.9.0)
  # for jm@localhost (single-drop); Thu, 13 Mar 2003 20:39:56 -0800 (PST)
  elsif (/^from (\S+) \[(${IP_ADDRESS})\] by (\S+) with IMAP \(fetchmail/) {
    $rdns = $1; $ip = $2; $by = $3;

  }

  # Received: from pl653.nas927.o-tokyo.nttpc.ne.jp (HELO kaik)
  # (61.197.108.141) by one.develooper.com (qpsmtpd/0.21-dev) with SMTP;
  # Thu, 13 Mar 2003 23:24:32 -0800
  elsif (/^from (\S+) \(HELO (\S+)\) \((${IP_ADDRESS})\) by (\S+) \(qpsmtpd/) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # Received: from [129.24.215.125] by ws1-7.us4.outblaze.com with http for
  # _bushisevil_@mail.com; Thu, 13 Feb 2003 15:59:28 -0500
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) with http for /) {
    $ip = $1; $by = $2;
  }

  # Received: from po11.mit.edu [18.7.21.73]
  # by stark.dyndns.tv with POP3 (fetchmail-5.9.7)
  # for stark@localhost (single-drop); Tue, 18 Feb 2003 10:43:09 -0500 (EST)
  # by po11.mit.edu (Cyrus v2.1.5) with LMTP; Tue, 18 Feb 2003 09:49:46 -0500
  elsif (/^from (\S+) \[(${IP_ADDRESS})\] by (\S+) with POP3 /) {
    $rdns = $1; $ip = $2; $by = $3;
  }

  # Received: from snake.corp.yahoo.com(216.145.52.229) by x.x.org via smap (V1.3)
  # id xma093673; Wed, 26 Mar 03 20:43:24 -0600
  elsif (/^from (\S+)\((${IP_ADDRESS})\) by (\S+) via smap /) {
    $rdns = $1; $ip = $2; $by = $3;
  }

  # Received: from p135-44.as1.wxd.wexford.eircom.net (HELO coolcotts)
  # (213.94.135.44) by relay06.indigo.ie (qp 33102) with SMTP;
  # 2 Mar 2003 21:54:54 -0000
  elsif (/^from (\S+) \(HELO (\S+)\) \((${IP_ADDRESS})\) by (\S+) \(qp \d+\) with SMTP; /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # Received: from [192.168.0.71] by web01-nyc.clicvu.com (Post.Office MTA
  # v3.5.3 release 223 ID# 0-64039U1000L100S0V35) with SMTP id com for
  # <x@x.org>; Tue, 25 Mar 2003 11:42:04 -0500
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) \(Post/) {
    $ip = $1; $by = $2;
  }

  # Received: from [127.0.0.1] by euphoria (ArGoSoft Mail Server 
  # Freeware, Version 1.8 (1.8.2.5)); Sat, 8 Feb 2003 09:45:32 +0200
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) \(ArGoSoft/) {
    $ip = $1; $by = $2;
  }

  # Received: from inet-vrs-05.redmond.corp.microsoft.com ([157.54.6.157]) by
  # INET-IMC-05.redmond.corp.microsoft.com with Microsoft SMTPSVC(5.0.2195.6624);
  # Thu, 6 Mar 2003 12:02:35 -0800
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) with /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from tthompson ([217.35.105.172] unverified) by
  # mail.neosinteractive.com with Microsoft SMTPSVC(5.0.2195.5329);
  # Tue, 11 Mar 2003 13:23:01 +0000
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\] unverified\) by (\S+) with Microsoft SMTPSVC/) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from 157.54.8.23 by inet-vrs-05.redmond.corp.microsoft.com
  # (InterScan E-Mail VirusWall NT); Thu, 06 Mar 2003 12:02:35 -0800
  elsif (/^from (${IP_ADDRESS}) by (\S+) \(InterScan/) {
    $ip = $1; $by = $2;
  }

  # Received: from faerber.muc.de by slarti.muc.de with BSMTP (rsmtp-qm-ot 0.4)
  # for asrg@ietf.org; 7 Mar 2003 21:10:38 -0000
  elsif (/^from (\S+) by (\S+) with BSMTP/) {
    return;	# BSMTP != a TCP/IP handover, ignore it
  }

  # Received: from spike (spike.ig.co.uk [193.32.60.32]) by mail.ig.co.uk with
  # SMTP id h27CrCD03362 for <asrg@ietf.org>; Fri, 7 Mar 2003 12:53:12 GMT
  elsif (/^from (\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) with /) {
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
  }

  # Received: from customer254-217.iplannetworks.net (HELO AGAMENON) 
  # (baldusi@200.69.254.217 with plain) by smtp.mail.vip.sc5.yahoo.com with
  # SMTP; 11 Mar 2003 21:03:28 -0000
  elsif (/^from (\S+) \(HELO (\S+)\) \((\S+) with \S+\) by (\S+) with /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
    $ip =~ s/([^\@]+)\@//g and $ident = $1;	# remove IDENT lookups
  }

  # Received: from raptor.research.att.com (bala@localhost) by
  # raptor.research.att.com (SGI-8.9.3/8.8.7) with ESMTP id KAA14788 
  # for <asrg@example.com>; Fri, 7 Mar 2003 10:37:56 -0500 (EST)
  elsif (/^from (\S+) \((\S+\@\S+)\) by (\S+) \(/) {
    return;
  }

  # Received: from mmail by argon.connect.org.uk with local (connectmail/exim) id 18tOsg-0008FX-00; Thu, 13 Mar 2003 09:20:06 +0000
  elsif (/^from (\S+) by (\S+) with local/) { return; }

  # Received: from [192.168.1.104] (account nazgul HELO [192.168.1.104])
  # by somewhere.com (CommuniGate Pro SMTP 3.5.7) with ESMTP-TLS id 2088434;
  # Fri, 07 Mar 2003 13:05:06 -0500
  elsif (/^from \[(${IP_ADDRESS})\] \(account \S+ HELO (\S+)\) by (\S+) \(/) {
    $ip = $1; $helo = $2; $by = $3;
  }

  # Received: from ([10.0.0.6]) by mail0.ciphertrust.com with ESMTP ; Thu,
  # 13 Mar 2003 06:26:21 -0500 (EST)
  elsif (/^from \(\[(${IP_ADDRESS})\]\) by (\S+) with /) {
    $ip = $1; $by = $2;
  }

  # Received: from scv3.apple.com (scv3.apple.com) by mailgate2.apple.com (Content Technologies SMTPRS 4.2.1) with ESMTP id <T61095998e1118164e13f8@mailgate2.apple.com>; Mon, 17 Mar 2003 17:04:54 -0800
  elsif (/^from (\S+) \((\S+)\) by (\S+) \(/) {
    $helo = $1; $rdns = $2; $by = $3;
  }

  # Received: from centipaid.com ([216.177.8.126]) by centipaid.com ; Tue,
  # 11 Mar 2003 13:45:12 -500
  elsif (/^from (\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) ;/) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from 01al10015010057.ad.bls.com ([90.152.5.141] [90.152.5.141])
  # by aismtp3g.bls.com with ESMTP; Mon, 10 Mar 2003 11:10:41 -0500
  elsif (/^from (\S+) \(\[(\S+)\] \[(\S+)\]\) by (\S+) with /) {
    # not sure what $3 is ;)
    $helo = $1; $ip = $2; $by = $4;
  }

  # Received: from 206.47.0.153 by dm3cn8.bell.ca with ESMTP (Tumbleweed MMS
  # SMTP Relay (MMS v5.0)); Mon, 24 Mar 2003 19:49:48 -0500
  elsif (/^from (${IP_ADDRESS}) by (\S+) with /) {
    $ip = $1; $by = $2;
  }

  # Received: from pobox.com (h005018086b3b.ne.client2.attbi.com[66.31.45.164])
  # by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <2003031302165605300suph7e>;
  # Thu, 13 Mar 2003 02:16:56 +0000
  elsif (/^from (\S+) \((\S+)\[(${IP_ADDRESS})\]\) by (\S+) /) {
    $helo = $1; $rdns = $2; $ip = $3; $by = $4;
  }

  # Received: from virscan1.asianet.co.th (HELO mx.asianet.co.th) ([203.144.222.197]) (envelope-sender <jrace@attglobal.net>) by mail1.asianet.co.th (qmail-ldap-1.03) with SMTP for <asrg@ietf.org>; 23 Mar 2003 15:24:35 +0700
  elsif (/^from (\S+) \(HELO (\S+)\) \(\[(${IP_ADDRESS})\]\) \([^)]+\) by (\S+) /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # from pc-00101 (HELO leiinc.com) (192.168.0.101) by server.leiinc.com (192.168.0.1) with ESMTP
  elsif (/^from (\S+) \(HELO (\S+)\) \((${IP_ADDRESS})\) by (\S+) /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # Received: from unknown (HELO terpsichore.farfalle.com) (jdavid@[216.254.40.70]) (envelope-sender <jdavid@farfalle.com>) by mail13.speakeasy.net (qmail-ldap-1.03) with SMTP for <jm@jmason.org>; 12 Feb 2003 18:23:19 -0000
  elsif (/^from (\S+) \(HELO (\S+)\) \((\S+)\@\[(${IP_ADDRESS})\]\).*? by (\S+) /) {
    $rdns = $1; $helo = $2; $ident = $3; $ip = $4; $by = $5;
  }
  elsif (/^from (\S+) \(HELO (\S+)\) \(\[(${IP_ADDRESS})\]\).*? by (\S+) /) {
    $rdns = $1; $helo = $2; $ip = $3; $by = $4;
  }

  # Received: from [10.128.128.81]:50999 (HELO dfintra.f-secure.com) by fsav4im2 ([10.128.128.74]:25) (F-Secure Anti-Virus for Internet Mail 6.0.34 Release) with SMTP; Tue, 5 Mar 2002 14:11:53 -0000
  elsif (/^from \[(${IP_ADDRESS})\]\S+ \(HELO (\S+)\) by (\S+) /) {
    $ip = $1; $helo = $2; $by = $3;
  }

  # Received: from 62.180.7.250 (HELO daisy) by smtp.altavista.de (209.228.22.152) with SMTP; 19 Sep 2002 17:03:17 +0000
  elsif (/^from (${IP_ADDRESS}) \(HELO (\S+)\) by (\S+) /) {
    $ip = $1; $helo = $2; $by = $3;
  }

  # Received: from oemcomputer [63.232.189.195] by highstream.net (SMTPD32-7.07) id A4CE7F2A0028; Sat, 01 Feb 2003 21:39:10 -0500
  elsif (/^from (\S+) \[(${IP_ADDRESS})\] by (\S+) /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # from nodnsquery(192.100.64.12) by herbivore.monmouth.edu via csmap (V4.1) id srcAAAyHaywy
  elsif (/^from (\S+)\((${IP_ADDRESS})\) by (\S+) /) {
    $rdns = $1; $ip = $2; $by = $3;
  }

  # Received: from unknown (66.218.66.216) by m6.grp.scd.yahoo.com
  # with QMQP; 1 Apr 2003 11:51:03 -0000
  elsif (/^from \S+ \((${IP_ADDRESS})\) by (\S+\.yahoo\.com) with QMQP;/) {
    $ip = $1; $by = $2;
  }

  # Received: from [192.168.0.13] by <server> (MailGate 3.5.172) with SMTP;
  # Tue, 1 Apr 2003 15:04:55 +0100
  elsif (/^from \[(${IP_ADDRESS})\] by (\S+) \(MailGate /) {
    $ip = $1; $by = $2;
  }

  # Received: from ironport.com (10.1.1.5) by a50.ironport.com with ESMTP; 01 Apr 2003 12:00:51 -0800
  elsif (/^from (\S+) \((${IP_ADDRESS})\) by (\S+) with /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # Received: from jmason.org (unverified [195.218.107.131]) by ni-mail1.dna.utvinternet.net <B0014212518@ni-mail1.dna.utvinternet.net>; Tue, 11 Feb 2003 12:18:12 +0000
  elsif (/^from (\S+) \(unverified \[(${IP_ADDRESS})\]\) by (\S+) /) {
    $helo = $1; $ip = $2; $by = $3;
  }

  # from 165.228.131.11 (proxying for 139.130.20.189) (SquirrelMail authenticated user jmmail) by jmason.org with HTTP
  elsif (/^from (\S+) \(proxying for (${IP_ADDRESS})\) \([A-Za-z][^\)]+\) by (\S+) with /) {
    $ip = $2; $by = $3;
  }
  elsif (/^from (${IP_ADDRESS}) \([A-Za-z][^\)]+\) by (\S+) with /) {
    $ip = $1; $by = $2;
  }

  # Received: from [212.87.144.30] (account seiz [212.87.144.30] verified) by x.imd.net (CommuniGate Pro SMTP 4.0.3) with ESMTP-TLS id 5026665 for spamassassin-talk@lists.sourceforge.net; Wed, 15 Jan 2003 16:27:05 +0100
  elsif (/^from \[(${IP_ADDRESS})\] \([^\)]+\) by (\S+) /) {
    $ip = $1; $by = $2;
  }

  # IGNORED LINES: generally local-to-local or non-TCP/IP handovers

  # Received: (qmail 27981 invoked by uid 225); 14 Mar 2003 07:24:34 -0000
  # Received: (qmail 84907 invoked from network); 13 Feb 2003 20:59:28 -0000
  # Received: (ofmipd 208.31.42.38); 17 Mar 2003 04:09:01 -0000
  # we don't care about this kind of gateway noise
  elsif (/^\(/) { return; }

  # from qmail-scanner-general-admin@lists.sourceforge.net by alpha by uid 7791 with qmail-scanner-1.14 (spamassassin: 2.41. Clear:SA:0(-4.1/5.0):. Processed in 0.209512 secs)
  elsif (/^from \S+\@\S+ by \S+ by uid \S+ /) { return; }

  # Received: from mail pickup service by mail1.insuranceiq.com with
  # Microsoft SMTPSVC; Thu, 13 Feb 2003 19:05:39 -0500
  elsif (/^from mail pickup service by (\S+) with Microsoft SMTPSVC;/) {
    return;
  }

  # Received: by x.x.org (bulk_mailer v1.13); Wed, 26 Mar 2003 20:44:41 -0600
  elsif (/^by (\S+) \(bulk_mailer /) { return; }

  # Received: (from mailnull@localhost) by x.x.org (8.12.6/8.9.3) id
  # h2R2hmBb093695 for x-relay; Wed, 26 Mar 2003 20:43:48 -0600 (CST)
  # (envelope-from y@z.com)
  elsif (/^\(from \S+\@localhost\) /) { return; }

  # Received: from DSmith1204@aol.com by imo-m09.mx.aol.com (mail_out_v34.13.) id 7.53.208064a0 (4394); Sat, 11 Jan 2003 23:24:31 -0500 (EST)
  elsif (/^from \S+\@\S+ by \S+ /) { return; }

  # Received: from Unknown/Local ([?.?.?.?]) by mailcity.com; Fri, 17 Jan 2003 15:23:29 -0000
  elsif (/^from Unknown\/Local \(/) { return; }

  # Received: by SPIDERMAN with Internet Mail Service (5.5.2653.19) id <19AF8VY2>; Tue, 25 Mar 2003 11:58:27 -0500
  elsif (/^by \S+ with Internet Mail Service \(/) { return; }

  # Received: by oak.ein.cz (Postfix, from userid 1002) id DABBD1BED3;
  # Thu, 13 Feb 2003 14:02:21 +0100 (CET)
  elsif (/^by (\S+) \(Postfix, from userid /) { return; }

  # Received: from localhost (mailnull@localhost) by x.org (8.12.6/8.9.3) 
  # with SMTP id h2R2iivG093740; Wed, 26 Mar 2003 20:44:44 -0600 
  # (CST) (envelope-from x@x.org)
  # Received: from localhost (localhost [127.0.0.1]) (uid 500) by mail with local; Tue, 07 Jan 2003 11:40:47 -0600
  elsif (/^from localhost \((?:\S+\@|)localhost[\) ]/) { return; }

  # Received: from olgisoft.com (127.0.0.1) by 127.0.0.1 (EzMTS MTSSmtp
  # 1.55d5) ; Thu, 20 Mar 03 10:06:43 +0100 for <asrg@ietf.org>
  elsif (/^from \S+ \((?:\S+\@|)localhost\) /) { return; }

  # Received: from casper.ghostscript.com (raph@casper [127.0.0.1]) h148aux8016336verify=FAIL); Tue, 4 Feb 2003 00:36:56 -0800
  # TODO: could use IPv6 localhost
  elsif (/^from (\S+) \(\S+\@\S+ \[127\.0\.0\.1\]\) /) { return; }

  # Received: from (AUTH: e40a9cea) by vqx.net with esmtp (courier-0.40) for <asrg@ietf.org>; Mon, 03 Mar 2003 14:49:28 +0000
  elsif (/^from \(AUTH: (\S+)\) by (\S+) with /) { return; }

  # Received: by faerber.muc.de (OpenXP/32 v3.9.4 (Win32) alpha @
  # 2003-03-07-1751d); 07 Mar 2003 22:10:29 +0000
  # ignore any lines starting with "by", we want the "from"s!
  elsif (/^by \S+ /) { return; }

  # Received: FROM ca-ex-bridge1.nai.com BY scwsout1.nai.com ;
  # Fri Feb 07 10:18:12 2003 -0800
  elsif (/^FROM \S+ BY \S+ \; /) { return; }

  # Received: from andrew by trinity.supernews.net with local (Exim 4.12)
  # id 18xeL6-000Dn1-00; Tue, 25 Mar 2003 02:39:00 +0000
  # Received: from CATHY.IJS.SI by CATHY.IJS.SI (PMDF V4.3-10 #8779) id <01KTSSR50NSW001MXN@CATHY.IJS.SI>; Fri, 21 Mar 2003 20:50:56 +0100
  # Received: from MATT_LINUX by hippo.star.co.uk via smtpd (for mail.webnote.net [193.120.211.219]) with SMTP; 3 Jul 2002 15:43:50 UT
  # Received: from cp-its-ieg01.mail.saic.com by cpmx.mail.saic.com for me@jmason.org; Tue, 23 Jul 2002 14:09:10 -0700
  elsif (/^from \S+ by \S+ (?:with|via|for|\()/) { return; }

  # Received: from virtual-access.org by bolero.conactive.com ; Thu, 20 Feb 2003 23:32:58 +0100
  elsif (/^from (\S+) by (\S+) *\;/) {
    return;	# can't trust this
  }

  # Received: Message by Barricade wilhelm.eyp.ee with ESMTP id h1I7hGU06122 for <spamassassin-talk@lists.sourceforge.net>; Tue, 18 Feb 2003 09:43:16 +0200
  elsif (/^Message by /) {
    return;	# whatever
  }
 
  else {
    dbg ("received-header: unknown format: $_");
    # skip the line entirely!  We can't parse it...
    return;
  }

  # OK, line parsed; now deal with the contents

  if ($ip eq '127.0.0.1') {	# ignore localhost handovers
    return;
  }

  if ($rdns =~ /^unknown$/i) {
    $rdns = '';		# some MTAs seem to do this
  }

  # ensure invalid chars are stripped.  Replace with '!' to flag their
  # presence, though.
  $ip =~ s/[\s\0\#\[\]\(\)\<\>\|]/!/gs;
  $rdns =~ s/[\s\0\#\[\]\(\)\<\>\|]/!/gs;
  $helo =~ s/[\s\0\#\[\]\(\)\<\>\|]/!/gs;
  $by =~ s/[\s\0\#\[\]\(\)\<\>\|]/!/gs;
  $ident =~ s/[\s\0\#\[\]\(\)\<\>\|]/!/gs;

  # perform rDNS check if MTA has not done it for us.
  # TODO: do this for untrusted headers anyway; if it mismatches it
  # could be a spamsign.  Probably better done later after we've
  # moved the "trusted" ones out of the way.  In fact, this op
  # here may be movable too; no need to lookup trusted IPs all the time.
  if ($rdns eq '') {
    dbg ("received-header: lookup PTR: $ip");
    $rdns = $self->lookup_ptr ($ip);
  }

  # add spaces so things like Bayes can tokenize them easily
  my $asstr = "[ ip=$ip rdns=$rdns helo=$helo by=$by ident=$ident ] ";
  $self->{relays_untrusted_str} .= $asstr;

  # add it to an internal array so Eval tests can use it
  push (@{$self->{relays_untrusted}}, {
	ip => $ip,
	rdns => $rdns,
	helo => $helo,
	by => $by,
	ident => $ident,
	asstr => $asstr
      });
}

# ---------------------------------------------------------------------------

1;
