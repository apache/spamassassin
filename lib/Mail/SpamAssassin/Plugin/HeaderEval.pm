# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::HeaderEval;

use strict;
use warnings;
# use bytes;
use re 'taint';
use Errno qw(EBADF);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::Util qw(get_my_locales parse_rfc822_date
                                is_valid_utf_8);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:sa :ip);

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $IP_ADDRESS = IP_ADDRESS;

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_for_fake_aol_relay_in_rcvd", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_faraway_charset_in_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_unique_subject_id", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_illegal_chars", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_hotmail_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_no_hotmail_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_msn_groups_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_eudoramail_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_yahoo_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_juno_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_gmail_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_matching_env_and_hdr_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("sorted_recipients", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("similar_recipients", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_missing_to_header", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_forged_gw05_received_headers", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_shifted_date", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("subject_is_all_caps", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_for_to_in_subject", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_outlook_message_id", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_messageid_not_usable", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_header_count_range", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_unresolved_template", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_ratware_name_id", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_ratware_envelope_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("gated_through_received_hdr_remover", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("received_within_months", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_equal_from_domains", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  return $self;
}

sub check_for_fake_aol_relay_in_rcvd {
  my ($self, $pms) = @_;
  local ($_);

  $_ = $pms->get('Received');
  s/\s+/ /gs;

  # this is the hostname format used by AOL for their relays. Spammers love 
  # forging it.  Don't make it more specific to match aol.com only, though --
  # there's another set of spammers who generate fake hostnames to go with
  # it!
  if (/ rly-[a-z][a-z]\d\d\./i) {
    return 0 if /\/AOL-\d+\.\d+\.\d+\)/;    # via AOL mail relay
    return 0 if /ESMTP id (?:RELAY|MAILRELAY|MAILIN)/; # AOLish
    return 1;
  }

# spam: Received: from unknown (HELO mta05bw.bigpond.com) (80.71.176.130) by
#    rly-xw01.mx.aol.com with QMQP; Sat, 15 Jun 2002 23:37:16 -0000

# non: Received: from  rly-xj02.mx.aol.com (rly-xj02.mail.aol.com [172.20.116.39]) by
#    omr-r05.mx.aol.com (v83.35) with ESMTP id RELAYIN7-0501132011; Wed, 01
#    May 2002 13:20:11 -0400

# non: Received: from logs-tr.proxy.aol.com (logs-tr.proxy.aol.com [152.163.201.132])
#    by rly-ip01.mx.aol.com (8.8.8/8.8.8/AOL-5.0.0)
#    with ESMTP id NAA08955 for <sapient-alumni@yahoogroups.com>;
#    Thu, 4 Apr 2002 13:11:20 -0500 (EST)

  return 0;
}

sub check_for_faraway_charset_in_headers {
  my ($self, $pms) = @_;
  my $hdr;

  my @locales = get_my_locales($self->{main}->{conf}->{ok_locales});

  return 0 if grep { $_ eq "all" } @locales;

  for my $h (qw(From Subject)) {
    my @hdrs = $pms->get("$h:raw");
    foreach my $hdr (@hdrs) {
      while ($hdr =~ /=\?(.+?)\?.\?.*?\?=/g) {
        Mail::SpamAssassin::Locales::is_charset_ok_for_locales($1, @locales)
          or return 1;
      }
    }     
  }
  0;
}

# Deprecated (Bug 8051)
sub check_for_unique_subject_id {
  return 0;
}

# look for 8-bit and other illegal characters that should be MIME
# encoded, these might want to exempt languages that do not use
# Latin-based alphabets, but only if the user wants it that way
sub check_illegal_chars {
  my ($self, $pms, $header, $ratio, $count) = @_;

  $header .= ":raw" unless $header =~ /:raw$/;
  my $str = $pms->get($header);
  return 0 if !defined $str || $str !~ /\S/;

  if ($str =~ tr/\x00-\x7F//c && is_valid_utf_8($str)) {
    # is non-ASCII and is valid UTF-8
    if ($str =~ tr/\x00-\x08\x0B\x0C\x0E-\x1F//) {
      dbg("eval: %s is valid UTF-8 but contains controls: %s", $header, $str);
    } else {
      # todo: only with a SMTPUTF8 mail
      dbg("eval: %s is valid UTF-8: %s", $header, $str);
      return 0;
    }
  }

  # count illegal substrings (RFC 2045)
  # (non-ASCII + C0 controls except TAB, NL, CR)
  my $illegal = $str =~ tr/\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff//;

  # minor exemptions for Subject
  if ($illegal > 0 && lc $header eq "subject:raw") {
    # only exempt a single cent sign, pound sign, or registered sign
    my $exempt = $str =~ tr/\xa2\xa3\xae//;
    $illegal-- if $exempt == 1;
  }

  return 0 if $str eq '';
  return (($illegal / length($str)) >= $ratio && $illegal >= $count);
}

# ezmlm has a very bad habit of removing Received: headers! bad ezmlm.
#
sub gated_through_received_hdr_remover {
  my ($self, $pms) = @_;

  my $txt = $pms->get("Mailing-List",undef);
  if (defined $txt && $txt =~ /^contact \S+\@\S+\; run by ezmlm$/m) {
    my $dlto = $pms->get("Delivered-To");
    my $rcvd = $pms->get("Received");

    # ensure we have other indicative headers too
    if ($dlto =~ /^mailing list \S+\@\S+/m &&
        $rcvd =~ /qmail \d+ invoked (?:from network|by .{3,20})\); \d+ ... \d+/)
    {
      return 1;
    }
  }

  my $rcvd = $pms->get("Received",undef);
  if (!defined $rcvd) {
    # we have no Received headers!  These tests cannot run in that case
    return 1;
  }

  # MSN groups removes Received lines. thanks MSN
  if ($rcvd =~ /from groups\.msn\.com \(\S+\.msn\.com /) {
    return 1;
  }

  return 0;
}

# FORGED_HOTMAIL_RCVD
sub _check_for_forged_hotmail_received_headers {
  my ($self, $pms) = @_;

  if (defined $pms->{hotmail_addr_but_no_hotmail_received}) { return; }

  $pms->{hotmail_addr_with_forged_hotmail_received} = 0;
  $pms->{hotmail_addr_but_no_hotmail_received} = 0;

  my $rcvd = $pms->get('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  return if ($rcvd =~
	/from mail pickup service by hotmail\.com with Microsoft SMTPSVC;/);

  # Microsoft passes Hotmail mail directly to MSN Group servers.
  return if $self->check_for_msn_groups_headers($pms);

  my $ip = $pms->get('X-Originating-Ip',undef);
  my $orig = $pms->get('X-OriginatorOrg',undef);
  my $ORIGINATOR = qr/hotmail\.com|msonline\-outlook/;

  if (defined $ip && $ip =~ /$IP_ADDRESS/) { $ip = 1; } else { $ip = 0; }
  if (defined $orig && $orig =~ /$ORIGINATOR/) { $orig = 1; } else { $orig = 0; }

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # or like
  # Received: from EUR01-VE1-obe.outbound.protection.outlook.com (mail-oln040092066056.outbound.protection.outlook.com [40.92.66.56])
  # or
  # Received: from VI1PR04MB3039.eurprd04.prod.outlook.com (2603:10a6:802:b::13)
  # spammers do not ;)

  if ($self->gated_through_received_hdr_remover($pms)) { return; }

  if ($rcvd =~ /from (?:\S*\.)?hotmail.com \(\S+\.hotmail(?:\.msn)?\.com[ \)]/ && $ip)
                { return; }
  if ($rcvd =~ /from \S*\.outbound\.protection\.outlook\.com \(\S+\.outbound\.protection\.outlook\.com[ \)]/ && $orig)
                { return; }
  if ($rcvd =~ /from \S*\.(?:eur|nam)prd\d+\.prod\.outlook\.com \($IP_ADDRESS\)/ && $orig)
                { return; }
  if ($rcvd =~ /from \S*\.hotmail.com \(\[$IP_ADDRESS\][ \):]/ && $ip)
                { return; }
  if ($rcvd =~ /from \S+ by \S+\.hotmail(?:\.msn)?\.com with HTTP\;/ && $ip)
                { return; }
  if ($rcvd =~ /from \[66\.218.\S+\] by \S+\.yahoo\.com/ && $ip)
                { return; }

  if ($rcvd =~ /(?:from |HELO |helo=)\S*hotmail\.com\b/) {
    # HELO'd as hotmail.com, despite not being hotmail
    $pms->{hotmail_addr_with_forged_hotmail_received} = 1;
  } else {
    # check to see if From claimed to be @hotmail.com
    my $from = $pms->get('From:addr');
    if ($from !~ /\bhotmail\.com$/i) { return; }
    $pms->{hotmail_addr_but_no_hotmail_received} = 1;
  }
}

# FORGED_HOTMAIL_RCVD
sub check_for_forged_hotmail_received_headers {
  my ($self, $pms) = @_;
  $self->_check_for_forged_hotmail_received_headers($pms);
  return $pms->{hotmail_addr_with_forged_hotmail_received};
}

# SEMIFORGED_HOTMAIL_RCVD
sub check_for_no_hotmail_received_headers {
  my ($self, $pms) = @_;
  $self->_check_for_forged_hotmail_received_headers($pms);
  return $pms->{hotmail_addr_but_no_hotmail_received};
}

# MSN_GROUPS
sub check_for_msn_groups_headers {
  my ($self, $pms) = @_;

  my $to = $pms->get('To');
  return 0 unless $to =~ /<(\S+)\@groups\.msn\.com>/i;
  my $listname = $1;

  # from Theo Van Dinter, see bug 591
  # Updated by DOS, based on messages from Bob Menschel, bug 4301

  return 0 unless $pms->get('Received') =~
                 /from mail pickup service by ((?:p\d\d\.)groups\.msn\.com)\b/;
  my $server = $1;

  if ($listname =~ /^notifications$/) {
    return 0 unless $pms->get('Message-Id') =~ /^<\S+\@$server>/;
  } else {
    return 0 unless $pms->get('Message-Id') =~ /^<$listname-\S+\@groups\.msn\.com>/;
    return 0 unless $pms->get('EnvelopeFrom:addr') =~ /$listname-bounce\@groups\.msn\.com/;
  }
  return 1;

# MSN Groups
# Return-path: <ListName-bounce@groups.msn.com>
# Received: from groups.msn.com (tk2dcpuba02.msn.com [65.54.195.210]) by
#    dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id g72K35v10457 for
#    <zzzzzzzzzzzz@jmason.org>; Fri, 2 Aug 2002 21:03:05 +0100
# Received: from mail pickup service by groups.msn.com with Microsoft
#    SMTPSVC; Fri, 2 Aug 2002 13:01:30 -0700
# Message-id: <ListName-1392@groups.msn.com>
# X-loop: notifications@groups.msn.com
# Reply-to: "List Full Name" <ListName@groups.msn.com>
# To: "List Full Name" <ListName@groups.msn.com>

# Return-path: <ListName-bounce@groups.msn.com>
# Received: from p04.groups.msn.com ([65.54.195.216]) etc...
# Received: from mail pickup service by p04.groups.msn.com with Microsoft SMTPSVC;
#          Thu, 5 May 2005 20:30:37 -0700
# X-Originating-Ip: 207.68.170.30
# From: =?iso-8859-1?B?IqSj4/D9pEbzeN9s9vLw6qQiIA==?=<zzzzzzzz@hotmail.com>
# To: "Managers of List Name" <notifications@groups.msn.com>
# Subject: =?iso-8859-1?Q?APPROVAL_NEEDED:_=A4=A3=E3=F0=FD=A4F=F3x=DFl?=
#         =?iso-8859-1?Q?=F6=F2=F0=EA=A4_applied_to_join_List_Name=2C?=
#         =?iso-8859-1?Q?_an_MSN_Group?=
# Date: Thu, 5 May 2005 20:30:37 -0700
# MIME-Version: 1.0
# Content-Type: multipart/alternative;
#         boundary="----=_NextPart_000_333944_01C551B1.4BBA02B0"
# X-MimeOLE: Produced By Microsoft MimeOLE V5.50.4927.1200
# Message-ID: <TK2DCPUBA042cv0aGlt00020aa3@p04.groups.msn.com>

# Return-path: <ListName-bounce@groups.msn.com>
# Received: from [65.54.208.83] (helo=p05.groups.msn.com) etc...
# Received: from mail pickup service by p05.groups.msn.com with Microsoft SMTPSVC;
#          Fri, 6 May 2005 14:59:25 -0700
# X-Originating-Ip: 207.68.170.30
# Message-Id: <ListName-101@groups.msn.com>
# Reply-To: "List Name" <ListName@groups.msn.com>
# From: "whoever" <zzzzzzzzzz@hotmail.com>
# To: "List Name" <ListName@groups.msn.com>
# Subject: whatever
# Date: Fri, 6 May 2005 14:59:25 -0700

}

###########################################################################

sub check_for_forged_eudoramail_received_headers {
  my ($self, $pms) = @_;

  my $from = $pms->get('From:addr');
  if ($from !~ /\beudoramail\.com$/i) { return 0; }

  my $rcvd = $pms->get('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  my $ip = $pms->get('X-Sender-Ip',undef);
  if (defined $ip && $ip =~ /$IP_ADDRESS/) { $ip = 1; } else { $ip = 0; }

  # Eudoramail formats its received headers like this:
  # Received: from Unknown/Local ([?.?.?.?]) by shared1-mail.whowhere.com;
  #      Thu Nov 29 13:44:25 2001
  # Message-Id: <JGDHDEHPPJECDAAA@shared1-mail.whowhere.com>
  # Organization: QUALCOMM Eudora Web-Mail  (http://www.eudoramail.com:80)
  # X-Sender-Ip: 192.175.21.146
  # X-Mailer: MailCity Service

  if ($self->gated_through_received_hdr_remover($pms)) { return 0; }

  if ($rcvd =~ /by \S*whowhere.com\;/ && $ip) { return 0; }
  
  return 1;
}

###########################################################################

sub check_for_forged_yahoo_received_headers {
  my ($self, $pms) = @_;

  my $from = $pms->get('From:addr');
  if ($from !~ /\byahoo\.com$/i) { return 0; }

  my $rcvd = $pms->get('Received');
  
  if ($pms->get("Resent-From") ne '' && $pms->get("Resent-To") ne '') {
    my $xrcvd = $pms->get("X-Received");
    $rcvd = $xrcvd  if $xrcvd ne '';
  }
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  # not sure about this
  #if ($rcvd !~ /from \S*yahoo\.com/) { return 0; }

  if ($self->gated_through_received_hdr_remover($pms)) { return 0; }

  # bug 3740: ignore bounces from Yahoo!.   only honoured if the
  # correct rDNS shows up in the trusted relay list, or first untrusted relay
  #
  # bug 4528: [ ip=68.142.202.54 rdns=mta122.mail.mud.yahoo.com 
  # helo=mta122.mail.mud.yahoo.com by=eclectic.kluge.net ident=
  # envfrom= intl=0 id=49F2EAF13B auth= ]
  #
  if ($pms->{relays_trusted_str} =~ / rdns=\S+\.yahoo\.com /
        || $pms->{relays_untrusted_str} =~ /^[^\]]+ rdns=\S+\.yahoo\.com /)
            { return 0; }

  if ($rcvd =~ /by web\S+\.mail\S*\.yahoo\.com via HTTP/) { return 0; }
  if ($rcvd =~ /by sonic\S+\.consmr\.mail\S*\.yahoo\.com with HTTP/) { return 0; }
  if ($rcvd =~ /by smtp\S+\.yahoo\.com with SMTP/) { return 0; }
  if ($rcvd =~
      /from \[$IP_ADDRESS\] by \S+\.(?:groups|scd|dcn)\.yahoo\.com with NNFMP/) {
    return 0;
  }

  # used in "forward this news item to a friend" links.  There's no better
  # received hdrs to match on, unfortunately.  I'm not sure if the next test is
  # still useful, as a result.
  #
  # search for msgid <20020929140301.451A92940A9@xent.com>, subject "Yahoo!
  # News Story - Top Stories", date Sep 29 2002 on
  # <http://xent.com/pipermail/fork/> for an example.
  #
  if ($rcvd =~ /\bmailer\d+\.bulk\.scd\.yahoo\.com\b/
                && $from =~ /\@reply\.yahoo\.com$/i) { return 0; }

  if ($rcvd =~ /by \w+\.\w+\.yahoo\.com \(\d+\.\d+\.\d+\/\d+\.\d+\.\d+\)(?: with ESMTP)? id \w+/) {
      # possibly sent from "mail this story to a friend"
      return 0;
  }

  return 1;
}

sub check_for_forged_juno_received_headers {
  my ($self, $pms) = @_;

  my $from = $pms->get('From:addr');
  if ($from !~ /\bjuno\.com$/i) { return 0; }

  if ($self->gated_through_received_hdr_remover($pms)) { return 0; }

  my $xorig = $pms->get('X-Originating-IP');
  my $xmailer = $pms->get('X-Mailer');
  my $rcvd = $pms->get('Received');

  if ($xorig ne '') {
    # New style Juno has no X-Originating-IP header, and other changes
    if($rcvd !~ /from.*\b(?:juno|untd)\.com.*[\[\(]$IP_ADDRESS[\]\)].*by/
        && $rcvd !~ / cookie\.(?:juno|untd)\.com /) { return 1; }
    if(index($xmailer, 'Juno ') == -1) { return 1; }
  } else {
    if($rcvd =~ /from.*\bmail\.com.*\[$IP_ADDRESS\].*by/) {
      if($xmailer !~ /\bmail\.com/) { return 1; }
    } elsif($rcvd =~ /from (webmail\S+\.untd\.com) \(\1 \[$IP_ADDRESS\]\) by/) {
      if($xmailer !~ /^Webmail Version \d/) { return 1; }
    } else {
      return 1;
    }
    if($xorig !~ /$IP_ADDRESS/) { return 1; }
  }

  return 0;   
}

sub check_for_forged_gmail_received_headers {
  my ($self, $pms) = @_;
  use constant GOOGLE_MESSAGE_STATE_LENGTH_MIN => 60;
  use constant GOOGLE_SMTP_SOURCE_LENGTH_MIN => 60;

  my $from = $pms->get('From:addr');
  if ($from !~ /\bgmail\.com$/i) { return 0; }

  my $xgms = $pms->get('X-Gm-Message-State');
  my $xss = $pms->get('X-Google-Smtp-Source');
  my $xreceived = $pms->get('X-Received');
  my $received = $pms->get('Received');

  if ($xreceived =~ /by 10\.\S+ with SMTP id \S+/) { return 0; }
  if ($xreceived =~ /by 2002\:a\d\d\:\w+\:\S+ with SMTP id \S+/) { return 0; }
  if ($received =~ /by smtp\.googlemail\.com with ESMTPSA id \S+/) {
    return 0;
  }

  if ( (length($xgms) >= GOOGLE_MESSAGE_STATE_LENGTH_MIN) && 
    (length($xss) >= GOOGLE_SMTP_SOURCE_LENGTH_MIN)) {
      return 0;
  }

  return 1;
}

sub check_for_matching_env_and_hdr_from {
  my ($self, $pms) =@_;
  # two blank headers match so don't bother checking
  return (lc $pms->get('EnvelopeFrom:addr') eq lc $pms->get('From:addr'));
}

sub sorted_recipients {
  my ($self, $pms) = @_;

  if (!exists $pms->{tocc_sorted}) {
    $self->_check_recipients($pms);
  }
  return $pms->{tocc_sorted};
}

sub similar_recipients {
  my ($self, $pms, $min, $max) = @_;

  if (!exists $pms->{tocc_similar}) {
    $self->_check_recipients($pms);
  }
  return (($min eq 'undef' || $pms->{tocc_similar} >= $min) &&
	  ($max eq 'undef' || $pms->{tocc_similar} < $max));
}

# best experimentally derived values
use constant TOCC_SORTED_COUNT => 7;
use constant TOCC_SIMILAR_COUNT => 5;
use constant TOCC_SIMILAR_LENGTH => 2;

sub _check_recipients {
  my ($self, $pms) = @_;

  my @inputs;

  # ToCc: pseudo-header works best, but sometimes Bcc: is better
  for ('ToCc:addr', 'Bcc:addr') {
    my @to = $pms->get($_);	# get recipients
    push @inputs, @to;
    last if scalar(@inputs) >= TOCC_SIMILAR_COUNT;
  }

  # remove duplicate addresses only when they appear next to each other
  my @address;
  my $previous = '';
  while (my $current = shift @inputs) {
    push(@address, ($previous = $current)) if lc($current) ne lc($previous);
    last if @address == 256;
  }

  # ideas that had both poor S/O ratios and poor hit rates:
  # - testing for reverse sorted recipient lists
  # - testing To: and Cc: headers separately
  $pms->{tocc_sorted} = (scalar(@address) >= TOCC_SORTED_COUNT &&
			  join(',', @address) eq (join(',', sort @address)));

  # a good S/O ratio and hit rate is achieved by comparing 2-byte
  # substrings and requiring 5 or more addresses
  $pms->{tocc_similar} = 0;
  if (scalar (@address) >= TOCC_SIMILAR_COUNT) {
    my @user = map { substr($_,0,TOCC_SIMILAR_LENGTH) } @address;
    my @fqhn = map { m/\@(.*)/ } @address;
    my @host = map { substr($_,0,TOCC_SIMILAR_LENGTH) } @fqhn;
    my $hits = 0;
    my $combinations = 0;
    for (my $i = 0; $i <= $#address; $i++) {
      for (my $j = $i+1; $j <= $#address; $j++) {
	$hits++ if $user[$i] eq $user[$j];
	$hits++ if $host[$i] eq $host[$j] && $fqhn[$i] ne $fqhn[$j];
	$combinations++;
      }
    }
    $pms->{tocc_similar} = $hits / $combinations;
  }
}

sub check_for_missing_to_header {
  my ($self, $pms) = @_;

  my $hdr = $pms->get('To');
  $hdr = $pms->get('Apparently-To')  if $hdr eq '';
  return 1  if $hdr eq '';

  return 0;
}

sub check_for_forged_gw05_received_headers {
  my ($self, $pms) = @_;
  local ($_);

  my $rcv = $pms->get('Received');

  # e.g.
  # Received: from mail3.icytundra.com by gw05 with ESMTP; Thu, 21 Jun 2001 02:28:32 -0400
  my ($h1, $h2) = ($rcv =~ 
  	m/\nfrom\s(\S+)\sby\s(\S+)\swith\sESMTP\;\s+\S\S\S,\s+\d+\s+\S\S\S\s+
			\d{4}\s+\d\d:\d\d:\d\d\s+[-+]*\d{4}\n$/xs);

  if (defined ($h1) && defined ($h2) && $h2 !~ /\./) {
    return 1;
  }

  0;
}

###########################################################################

sub check_for_shifted_date {
  my ($self, $pms, $min, $max) = @_;

  if (!exists $pms->{date_diff}) {
    $self->_check_date_diff($pms);
  }
  return (($min eq 'undef' || $pms->{date_diff} >= (3600 * $min)) &&
	  ($max eq 'undef' || $pms->{date_diff} < (3600 * $max)));
}

# filters out some false positives in old corpus mail - Allen
sub received_within_months {
  my ($self,$pms,$min,$max) = @_;

  if (!exists($pms->{date_received})) {
    $self->_check_date_received($pms);
  }
  my $diff = time() - $pms->{date_received};

  # 365.2425 * 24 * 60 * 60 = 31556952 = seconds in year (including leap)

  if (((! defined($min)) || ($min eq 'undef') ||
       ($diff >= (31556952 * ($min/12)))) &&
      ((! defined($max)) || ($max eq 'undef') ||
       ($diff < (31556952 * ($max/12))))) {
    return 1;
  } else {
    return 0;
  }
}

sub _get_date_header_time {
  my ($self, $pms) = @_;

  my $time;
  # a Resent-Date: header takes precedence over any Date: header
  DATE: for my $header ('Resent-Date', 'Date') {
    my @dates = $pms->{msg}->get_header($header);
    for my $date (@dates) {
      if (defined($date) && length($date)) {
        chomp($date);
        $time = parse_rfc822_date($date);
      }
      last DATE if defined($time);
    }
  }
  if (defined($time)) {
    $pms->{date_header_time} = $time;
  }
  else {
    $pms->{date_header_time} = undef;
  }
}

sub _get_received_header_times {
  my ($self, $pms) = @_;

  $pms->{received_header_times} = [ () ];
  $pms->{received_fetchmail_time} = undef;

  my (@received);
  my $received = $pms->get('Received');
  if ($received ne '') {
    @received = grep {$_ =~ m/\S/} (split(/\n/,$received));
  }
  # if we have no Received: headers, chances are we're archived mail
  # with a limited set of headers
  if (!scalar(@received)) {
    return;
  }

  # handle fetchmail headers
  my (@local);
  if (($received[0] =~
      m/\bfrom (?:localhost\s|(?:\S+ ){1,2}\S*\b127\.0\.0\.1\b)/) ||
      ($received[0] =~ m/qmail \d+ invoked by uid \d+/)) {
    push @local, (shift @received);
  }
  if (scalar(@received) &&
      ($received[0] =~ m/\bby localhost with \w+ \(fetchmail-[\d.]+/)) {
    push @local, (shift @received);
  }
  elsif (scalar(@local)) {
    unshift @received, (shift @local);
  }

  if (scalar(@local)) {
    my (@fetchmail_times);
    foreach my $rcvd (@local) {
      if ($rcvd =~ m/(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+)/) {
	my $date = $1;
        dbg2("eval: trying Received fetchmail header date for real time: $date");
	my $time = parse_rfc822_date($date);
	if (defined($time) && (time() >= $time)) {
          dbg2("eval: time_t from date=$time, rcvd=$date");
	  push @fetchmail_times, $time;
	}
      }
    }
    if (scalar(@fetchmail_times) > 1) {
      $pms->{received_fetchmail_time} =
       (sort {$b <=> $a} (@fetchmail_times))[0];
    } elsif (scalar(@fetchmail_times)) {
      $pms->{received_fetchmail_time} = $fetchmail_times[0];
    }
  }

  my (@header_times);
  foreach my $rcvd (@received) {
    if ($rcvd =~ m/(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+)/) {
      my $date = $1;
      dbg2("eval: trying Received header date for real time: $date");
      my $time = parse_rfc822_date($date);
      if (defined($time)) {
        dbg2("eval: time_t from date=$time, rcvd=$date");
	push @header_times, $time;
      }
    }
  }

  if (scalar(@header_times)) {
    $pms->{received_header_times} = [ @header_times ];
  } else {
    dbg("eval: no dates found in Received headers");
  }
}

sub _check_date_received {
  my ($self, $pms) = @_;

  my (@dates_poss);

  $pms->{date_received} = 0;

  if (!exists($pms->{date_header_time})) {
    $self->_get_date_header_time($pms);
  }

  if (defined($pms->{date_header_time})) {
    push @dates_poss, $pms->{date_header_time};
  }

  if (!exists($pms->{received_header_times})) {
    $self->_get_received_header_times($pms);
  }
  my (@received_header_times) = @{ $pms->{received_header_times} };
  if (scalar(@received_header_times)) {
    push @dates_poss, $received_header_times[0];
  }
  if (defined($pms->{received_fetchmail_time})) {
    push @dates_poss, $pms->{received_fetchmail_time};
  }

  if (defined($pms->{date_header_time}) && scalar(@received_header_times)) {
    if (!exists($pms->{date_diff})) {
      $self->_check_date_diff($pms);
    }
    push @dates_poss, $pms->{date_header_time} - $pms->{date_diff};
  }

  if (scalar(@dates_poss)) {	# use median
    $pms->{date_received} = (sort {$b <=> $a}
			      (@dates_poss))[int($#dates_poss/2)];
    dbg("eval: date chosen from message: " .
	scalar(localtime($pms->{date_received})));
  } else {
    dbg("eval: no dates found in message");
  }
}

sub _check_date_diff {
  my ($self, $pms) = @_;

  $pms->{date_diff} = 0;

  if (!exists($pms->{date_header_time})) {
    $self->_get_date_header_time($pms);
  }

  if (!defined($pms->{date_header_time})) {
    return;			# already have tests for this
  }

  if (!exists($pms->{received_header_times})) {
    $self->_get_received_header_times($pms);
  }
  my (@header_times) = @{ $pms->{received_header_times} };

  if (!scalar(@header_times)) {
    return;			# archived mail?
  }

  my (@diffs) = map {$pms->{date_header_time} - $_} (@header_times);

  # if the last Received: header has no difference, then we choose to
  # exclude it
  if ($#diffs > 0 && $diffs[$#diffs] == 0) {
    pop(@diffs);
  }

  # use the date with the smallest absolute difference
  # (experimentally, this results in the fewest false positives)
  @diffs = sort { abs($a) <=> abs($b) } @diffs;
  $pms->{date_diff} = $diffs[0];
}


sub subject_is_all_caps {
   my ($self, $pms) = @_;
   my $subject = $pms->get('Subject');

   $subject =~ s/^\s+//;
   $subject =~ s/\s+$//;
   $subject =~ s/^(?:(?:Re|Fwd|Fw|Aw|Antwort|WG|SV|VB|VS|VL):\s*)+//i;  # Bug 6805
   return 0 if $subject !~ /\s/;	# don't match one word subjects
   return 0 if (length $subject < 10);  # don't match short subjects
   $subject =~ s/[^a-zA-Z]//g;		# only look at letters

   # now, check to see if the subject is encoded using a non-ASCII charset.
   # If so, punt on this test to avoid FPs.  We just list the known charsets
   # this test will FP on, here.
   my $subjraw = $pms->get('Subject:raw');
   my $CLTFAC = Mail::SpamAssassin::Constants::CHARSETS_LIKELY_TO_FP_AS_CAPS;
   if ($subjraw =~ /=\?${CLTFAC}\?/i) {
     return 0;
   }

   return length($subject) && ($subject eq uc($subject));
}

sub check_for_to_in_subject {
  my ($self, $pms, $test) = @_;

  my $full_to = $pms->get('To:addr');
  return 0 unless $full_to ne '';

  my $subject = $pms->get('Subject');

  if ($test eq "address") {
    return $subject =~ /\b\Q$full_to\E\b/i;	# "user@domain.com"
  }
  elsif ($test eq "user") {
    my $to = $full_to;
    $to =~ s/\@.*//;
    my $subj = $subject;
    $subj =~ s/^\s+//;
    $subj =~ s/\s+$//;
    
    return $subject =~ /^(?:
    	(?:re|fw):\s*(?:\w+\s+)?\Q$to\E$
    	|(?-i:\Q$to\E)\s*[,:;!?-](?:$|\s)
    	|\Q$to\E$
    	|,\s*\Q$to\E[,:;!?-]$
    )/ix;
  }
  return 0;
}

sub check_outlook_message_id {
  my ($self, $pms) = @_;
  local ($_);

  my $id = $pms->get('MESSAGEID');
  return 0 if $id !~ /^<[0-9a-f]{4}([0-9a-f]{8})\$[0-9a-f]{8}\$[0-9a-f]{8}\@/;

  my $timetoken = hex($1);
  my $x = 0.0023283064365387;
  my $y = 27111902.8329849;

  my $fudge = 250;

  $_ = $pms->get('Date');
  $_ = parse_rfc822_date($_) || 0;
  my $expected = int (($_ * $x) + $y);
  my $diff = $timetoken - $expected;
  return 0 if (abs($diff) < $fudge);

  $_ = $pms->get('Received');
  /(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+).*?$/;
  $_ = parse_rfc822_date($_) || 0;
  $expected = int(($_ * $x) + $y);
  $diff = $timetoken - $expected;

  return (abs($diff) >= $fudge);
}

sub check_messageid_not_usable {
  my ($self, $pms) = @_;
  local ($_);

  # Lyris eats message-ids.  also some ezmlm, I think :(
  $_ = $pms->get("List-Unsubscribe");
  return 1 if (/<mailto:(?:leave-\S+|\S+-unsubscribe)\@\S+>$/i);

  # ezmlm again
  if($self->gated_through_received_hdr_remover($pms)) { return 1; }

  # Allen notes this as 'Wacky sendmail version?'
  $_ = $pms->get("Received");
  return 1 if /\/CWT\/DCE\)/;

  # Apr  2 2003 jm: iPlanet rewrites lots of stuff, including Message-IDs
  return 1 if /iPlanet Messaging Server/;

  return 0;
}

# Return true if the count of $hdr headers are within the given range
sub check_header_count_range {
  my ($self, $pms, $hdr, $min, $max) = @_;
  my %uniq;
  my @hdrs = grep(!$uniq{$_}++, $pms->{msg}->get_header ($hdr));
  return (scalar @hdrs >= $min && scalar @hdrs <= $max);
}

sub check_unresolved_template {
  my ($self, $pms) = @_;

  my $all = $pms->get('ALL');	# cached access
  
  for my $header (split(/\n/, $all)) {
    # slightly faster to test in this order
    if ($header =~ /%[A-Z][A-Z_-]/ &&
	$header !~ /^(?:X-VMS-To|X-UIDL|X-Face|To|Cc|From|Subject|References|In-Reply-To|(?:X-|Resent-|X-Original-)?Message-Id):/i)
    {
      return 1;
    }
  }
  return 0;
}

sub check_ratware_name_id {
  my ($self, $pms) = @_;

  my $mid = $pms->get('MESSAGEID');
  my $from = $pms->get('From');
  if ($mid =~ m/<[A-Z]{28}\.([^>]+?)>/) {
     if ($from =~ m/\"[^\"]+\"\s*<\Q$1\E>/) {
       return 1;
     }
  }
  return 0;
}

sub check_ratware_envelope_from {
  my ($self, $pms) = @_;

  my $to = $pms->get('To:addr');
  my $from = $pms->get('EnvelopeFrom:addr');

  return 0 if $from eq '' || $to eq '';
  return 0 if $from =~ /^SRS\d[=+-]/i;

  if ($to =~ /^([^@]+)\@(.+)$/) {
    my($user,$dom) = ($1,$2);
    $dom = $self->{main}->{registryboundaries}->trim_domain($dom);
    return unless
        ($self->{main}->{registryboundaries}->is_domain_valid($dom));

    return 1 if ($from =~ /\b\Q$dom\E.\Q$user\E@/i);
  }

  return 0;
}

# ADDED FROM BUG 6487
sub check_equal_from_domains {
  my ($self, $pms) = @_;

  my $from = $pms->get('From:addr');
  my $envfrom = $pms->get('EnvelopeFrom:addr');

  local $1;
  my $fromdomain = '';
  #Revised regexp from 6487 comment 3
  $fromdomain = $1  if $from =~ /\@([^@]*)\z/;
  $fromdomain =~ s/^.+\.([^\.]+\.[^\.]+)$/$1/;
  return 0 if $fromdomain eq '';

  my $envfromdomain = '';
  $envfromdomain = $1  if $envfrom =~ /\@([^@]*)\z/;
  $envfromdomain =~ s/^.+\.([^\.]+\.[^\.]+)$/$1/;
  return 0 if $envfromdomain eq '';

  dbg("eval: From 2nd level domain: $fromdomain, EnvelopeFrom 2nd level domain: $envfromdomain");
  
  return 1 if lc($fromdomain) ne lc($envfromdomain);

  return 0;
}


###########################################################################

# support eval-test verbose debugs using "-Deval"
sub dbg2 {
  if (would_log('dbg', 'eval') == 2) {
    dbg(@_);
  }
}

1;
