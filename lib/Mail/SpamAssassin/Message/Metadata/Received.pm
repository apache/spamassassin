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

# ---------------------------------------------------------------------------

# So, what's the difference between a trusted and untrusted Received header?
# Basically, relays we *know* are trustworthy are 'trusted', all others after
# the last one of those are 'untrusted'.
#
# We determine trust by detecting if they are inside the network ranges
# specified in 'trusted_networks'.  There is also an inference algorithm
# which determines other trusted relays without user configuration.
#
# There's another type of Received header: the semi-trusted one.  This is the
# header added by *our* MX, at the boundary of trust; we can trust the IP
# address (and possibly rDNS) in this header, but that's about it; HELO name is
# untrustworthy.  We just use this internally for now.
#
# Finally, there's also 'internal_networks'.  These are the networks that you
# control; your MXes should be included.  This way, if you specify a wide range
# of trusted hosts, a mail that is relayed from a dynamic IP address via a
# 'trusted' host will not hit RCVD_IN_DYNABLOCK.

# ---------------------------------------------------------------------------

use strict;  # make Test::Perl::Critic happy
package Mail::SpamAssassin::Message::Metadata::Received; 1;

package Mail::SpamAssassin::Message::Metadata;
use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Dns;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Constants qw(:ip);

# ---------------------------------------------------------------------------

sub parse_received_headers {
  my ($self, $permsgstatus, $msg) = @_;

  my $suppl_attrib = $msg->{suppl_attrib};  # out-of-band info from a caller

  # a caller may assert that a message is coming from inside or from an
  # authenticated roaming users; this info may not be available in mail
  # header section, e.g. in case of nonstandard authentication mechanisms
  my $originating;  # boolean
  $originating = $suppl_attrib->{originating}  if ref $suppl_attrib;

  $self->{relays_trusted} = [ ];
  $self->{num_relays_trusted} = 0;
  $self->{relays_trusted_str} = '';

  $self->{relays_untrusted} = [ ];
  $self->{num_relays_untrusted} = 0;
  $self->{relays_untrusted_str} = '';

  $self->{relays_internal} = [ ];
  $self->{num_relays_internal} = 0;
  $self->{relays_internal_str} = '';

  $self->{relays_external} = [ ];
  $self->{num_relays_external} = 0;
  $self->{relays_external_str} = '';

  $self->{num_relays_unparseable} = 0;

  $self->{last_trusted_relay_index} = -1;	# last counting from the top,
  $self->{last_internal_relay_index} = -1;	# first in time

  # now figure out what relays are trusted...
  my $trusted = $permsgstatus->{main}->{conf}->{trusted_networks};
  my $internal = $permsgstatus->{main}->{conf}->{internal_networks};
  my $msa = $permsgstatus->{main}->{conf}->{msa_networks};
  my $did_user_specify_trust = $permsgstatus->{main}->{conf}->{trusted_networks_configured};
  my $did_user_specify_internal = $permsgstatus->{main}->{conf}->{internal_networks_configured};
  my $in_trusted = 1;
  my $in_internal = 1;
  my $found_msa = 0;

  unless ($did_user_specify_trust && $did_user_specify_internal) {
    if (!$did_user_specify_trust && !$did_user_specify_internal) {
      dbg('config: trusted_networks are not configured; it is recommended '.
	  'that you configure trusted_networks manually');
    } elsif (!$did_user_specify_internal) {
      # use 'trusted' for 'internal'; compatibility with SpamAssassin 2.60
      $internal = $trusted;
      dbg('config: internal_networks not configured, using trusted_networks '.
	  'configuration for internal_networks; if you really want '.
	  'internal_networks to only contain the required 127/8 add '.
	  "'internal_networks !0/0' to your configuration");
    } else {
      # use 'internal' for 'trusted'; I don't know why we let people define
      # internal without trusted, but we do... and we rely on trusted being set
      $trusted = $internal;
      dbg('config: trusted_networks not configured, using internal_networks '.
	  'configuration for trusted_networks');
    }
  }

  my $IP_ADDRESS = IP_ADDRESS;
  my $IP_PRIVATE = IP_PRIVATE;
  my $LOCALHOST = LOCALHOST;

  my @hdrs = $msg->get_header('Received');

  # Now add the single line headers like X-Originating-IP. (bug 5680)
  # we convert them into synthetic "Received" headers so we can share
  # code below.
  for my $header (@{$permsgstatus->{main}->{conf}->{originating_ip_headers}})
  {
    my $str = $msg->get_header($header);
    next unless ($str && $str =~ m/($IP_ADDRESS)/);
    push @hdrs, "from X-Originating-IP: $1\n";
  }

  foreach my $line ( @hdrs ) {

    # qmail-scanner support hack: we may have had one of these set from the
    # previous (read: more recent) Received header.   if so, add it on to this
    # header's set, since that's the handover it was describing.

    my $qms_env_from;
    if ($self->{qmail_scanner_env_from}) {
      $qms_env_from = $self->{qmail_scanner_env_from};
      delete $self->{qmail_scanner_env_from};
    }

    $line =~ s/\n[ \t]+/ /gs;

    my $relay = $self->parse_received_line ($line);
    if (!defined $relay) {
      dbg("received-header: unparseable: $line");
      $self->{num_relays_unparseable}++;
    }

    # undefined or 0 means there's no result, so goto the next header
    unless ($relay) {
      $self->{last_trusted_relay_index}++ if $in_trusted;
      $self->{last_internal_relay_index}++ if $in_internal;
      next;
    }

    # hack for qmail-scanner, as described above; add in the saved
    # metadata
    if ($qms_env_from) {
      $relay->{envfrom} = $qms_env_from;
      $self->make_relay_as_string($relay);
    }

    # relay status only changes when we're still in the trusted portion of the
    # relays and we haven't yet found an MSA
    if ($in_trusted && !$found_msa) {
      unless ($did_user_specify_trust || $did_user_specify_internal) {
        # OK, infer the trusted/untrusted handover, we don't have real info
	my $inferred_as_trusted = 0;

	# if the 'from' IP addr is in a reserved net range, it's not on
	# the public internet.
	if ($relay->{ip_private}) {
	  dbg("received-header: 'from' ".$relay->{ip}." has private IP");
	  $inferred_as_trusted = 1;
	}

	# if we find authentication tokens in the received header we can extend
	# the trust boundary to that host
	if ($relay->{auth}) {
	  dbg("received-header: authentication method ".$relay->{auth});
	  $inferred_as_trusted = 1;
	}

	# if the user didn't specify any trusted/internal config, everything
	# we assume as trusted is also internal, just like we'd do if they
	# specified trusted but not any internal networks or vice versa
	if (!$inferred_as_trusted) {
	  dbg("received-header: do not trust any hosts from here on");
	  $in_trusted = 0;
	  $in_internal = 0;
	}

      } else {
	# trusted_networks matches?
	if (!$relay->{auth} && !$trusted->contains_ip($relay->{ip})) {
	  if (!$originating) {
	    $in_trusted = 0;	# break the trust chain
	  } else {  # caller asserts a msg was submitted from inside or auth'd
	    $found_msa = 1;	# let's assume the previous hop was actually
				# an MSA, and propagate trust from here on
	    dbg('received-header: originating, '.
	        '%s and remaining relays will be considered trusted%s',
	        $relay->{ip}, !$in_internal ? '' : ', but no longer internal');
	  }
	  $in_internal = 0;	# if it's not trusted it's not internal
	} else {
	  # internal_networks matches?
	  if ($in_internal && !$relay->{auth} && !$internal->contains_ip($relay->{ip})) {
	    $in_internal = 0;
	  }
	  # msa_networks matches?
	  if ($msa->contains_ip($relay->{ip})) {
	    dbg('received-header: found MSA relay, remaining relays will be'.
		' considered trusted: '.($in_trusted ? 'yes' : 'no').
		' internal: '.($in_internal ? 'yes' : 'no'));
	    $found_msa = 1;
	    $relay->{msa} = 1;
	  }
	}
      }
    }

    dbg("received-header: relay ".$relay->{ip}.
	" trusted? ".($in_trusted ? "yes" : "no").
	" internal? ".($in_internal ? "yes" : "no").
	" msa? ".($relay->{msa} ? "yes" : "no"));

    $relay->{internal} = $in_internal;
    $relay->{msa} ||= 0;

    # be sure to mark up the as_string version for users too
    $relay->{as_string} =~ s/ intl=\d / intl=$relay->{internal} /;
    $relay->{as_string} =~ s/ msa=\d / msa=$relay->{msa} /;

    if ($in_trusted) {
      push (@{$self->{relays_trusted}}, $relay);
      $self->{allow_fetchmail_markers} = 1;
      $self->{last_trusted_relay_index}++;
    } else {
      push (@{$self->{relays_untrusted}}, $relay);
      $self->{allow_fetchmail_markers} = 0;
    }

    if ($in_internal) {
      push (@{$self->{relays_internal}}, $relay);
      $self->{last_internal_relay_index}++;
    } else {
      push (@{$self->{relays_external}}, $relay);
    }
  }

  $self->{relays_trusted_str} = join(' ', map { $_->{as_string} }
                    @{$self->{relays_trusted}});
  $self->{relays_untrusted_str} = join(' ', map { $_->{as_string} }
                    @{$self->{relays_untrusted}});
  $self->{relays_internal_str} = join(' ', map { $_->{as_string} }
                    @{$self->{relays_internal}});
  $self->{relays_external_str} = join(' ', map { $_->{as_string} }
                    @{$self->{relays_external}});

  # OK, we've now split the relay list into trusted and untrusted.

  # add the stringified representation to the message object, so Bayes
  # and rules can use it.  Note that rule_tests.t does not impl put_metadata,
  # so protect against that here.  These will not appear in the final
  # message; they're just used internally.

  if ($self->{msg}->can ("delete_header")) {
    $self->{msg}->delete_header ("X-Spam-Relays-Trusted");
    $self->{msg}->delete_header ("X-Spam-Relays-Untrusted");
    $self->{msg}->delete_header ("X-Spam-Relays-Internal");
    $self->{msg}->delete_header ("X-Spam-Relays-External");

    if ($self->{msg}->can ("put_metadata")) {
      $self->{msg}->put_metadata ("X-Spam-Relays-Trusted",
			$self->{relays_trusted_str});
      $self->{msg}->put_metadata ("X-Spam-Relays-Untrusted",
			$self->{relays_untrusted_str});
      $self->{msg}->put_metadata ("X-Spam-Relays-Internal",
			$self->{relays_internal_str});
      $self->{msg}->put_metadata ("X-Spam-Relays-External",
			$self->{relays_external_str});
    }
  }

  # be helpful; save some cumbersome typing
  $self->{num_relays_trusted} = scalar (@{$self->{relays_trusted}});
  $self->{num_relays_untrusted} = scalar (@{$self->{relays_untrusted}});
  $self->{num_relays_internal} = scalar (@{$self->{relays_internal}});
  $self->{num_relays_external} = scalar (@{$self->{relays_external}});

  dbg("metadata: X-Spam-Relays-Trusted: ".$self->{relays_trusted_str});
  dbg("metadata: X-Spam-Relays-Untrusted: ".$self->{relays_untrusted_str});
  dbg("metadata: X-Spam-Relays-Internal: ".$self->{relays_internal_str});
  dbg("metadata: X-Spam-Relays-External: ".$self->{relays_external_str});
}

# ---------------------------------------------------------------------------

# returns undef if the header just couldn't be parsed
# returns 0 if the header was specifically skipped
# returns a hash of information if the header is parsed, including:
#    ip => $ip,
#    by => $by,
#    helo => $helo,
#    id => $id,
#    ident => $ident,
#    envfrom => $envfrom,
#    lc_by => (lc $by),
#    lc_helo => (lc $helo),
#    auth => $auth
#
sub parse_received_line {
  my ($self) = shift;
  local ($_) = shift;
  local ($1,$2,$3,$4,$5,$6);

  s/\s+/ /g;
  s/^ //;
  s/ $//;

  # get rid of invalid semicolon at the end of the header
  1 while s/\s?;$//;

  my $ip = '';
  my $helo = '';
  my $rdns = '';
  my $by = '';
  my $id = '';
  my $ident = '';
  my $envfrom = '';
  my $mta_looked_up_dns = 0;
  my $IP_ADDRESS = IP_ADDRESS;
  my $IP_PRIVATE = IP_PRIVATE;
  my $LOCALHOST = LOCALHOST;
  my $auth = '';

# ---------------------------------------------------------------------------

  # We care about lines starting with from.  all of the others are ignorable:
  # Bug 4943: give /^(from/ a chance to be parsed
  #
  # (qmail 27981 invoked by uid 225); 14 Mar 2003 07:24:34 -0000
  # (qmail 84907 invoked from network); 13 Feb 2003 20:59:28 -0000
  # (ofmipd 208.31.42.38); 17 Mar 2003 04:09:01 -0000
  # by faerber.muc.de (OpenXP/32 v3.9.4 (Win32) alpha @ 2003-03-07-1751d); 07 Mar 2003 22:10:29 +0000
  # by x.x.org (bulk_mailer v1.13); Wed, 26 Mar 2003 20:44:41 -0600
  # by SPIDERMAN with Internet Mail Service (5.5.2653.19) id <19AF8VY2>; Tue, 25 Mar 2003 11:58:27 -0500
  # by oak.ein.cz (Postfix, from userid 1002) id DABBD1BED3; Thu, 13 Feb 2003 14:02:21 +0100 (CET)
  # OTM-MIX(otm-mix00) id k5N1aDtp040896; Fri, 23 Jun 2006 10:36:14 +0900 (JST)
  # at Infodrom Oldenburg (/\##/\ Smail-3.2.0.102 1998-Aug-2 #2) from infodrom.org by finlandia.Infodrom.North.DE via smail from stdin id <m1FglM8-000okjC@finlandia.Infodrom.North.DE> for debian-security-announce@lists.debian.org; Thu, 18 May 2006 18:28:08 +0200 (CEST)
  # with ECARTIS (v1.0.0; list bind-announce); Fri, 18 Aug 2006 07:19:58 +0000 (UTC)
  # Received: Message by Barricade wilhelm.eyp.ee with ESMTP id h1I7hGU06122 for <spamassassin-talk@lists.sourceforge.net>; Tue, 18 Feb 2003 09:43:16 +0200
  return 0 if (!/^\(?from /i);

  # from www-data by wwwmail.documenta.de (Exim 4.50) with local for <example@vandinter.org> id 1GFbZc-0006QV-L8; Tue, 22 Aug 2006 21:06:04 +0200
  # from server.yourhostingaccount.com with local  for example@vandinter.org  id 1GDtdl-0002GU-QE (8710); Thu, 17 Aug 2006 21:59:17 -0400
  return 0 if /\bwith local for\b/;

  # Received: from virtual-access.org by bolero.conactive.com ; Thu, 20 Feb 2003 23:32:58 +0100
  # Received: FROM ca-ex-bridge1.nai.com BY scwsout1.nai.com ; Fri Feb 07 10:18:12 2003 -0800
  # but not: Received: from [86.122.158.69] by mta2.iomartmail.com; Thu, 2 Aug 2007 21:50:04 -0200
  if (/^from (\S+) by [^\s;]+ ?;/i && $1 !~ /^\[[\d.]+\]$/) { return 0; }

# ---------------------------------------------------------------------------

  # Let's get rid of the date at the end
  # ; Tue, 23 May 2006 13:06:35 -0400
  s/[\s;]+(?:(?:Mon|T(?:ue|hu)|Wed|Fri|S(?:at|un)), )?\d+ (?:J(?:an|u[nl])|Feb|Ma[ry]|A(?:pr|ug)|Sep|Oct|Nov|Dec) \d+ \d+:\d+(?::\d+)? \S+$//;

  # from av0001.technodiva.com (localhost [127.0.0.1])by  localhost.technodiva.com (Postfix) with ESMTP id 846CF2117for  <proftp-user@lists.sourceforge.net>; Mon,  7 Aug 2006 17:48:07 +0200 (MEST)
  s/\)by /) by /;

# ---------------------------------------------------------------------------

  # OK -- given knowledge of most Received header formats,
  # break them down.  We have to do something like this, because
  # some MTAs will swap position of rdns and helo -- so we can't
  # simply use simplistic regexps.

  # try to catch unique message identifier
  if (/ id <?([^\s<>;]{3,})/) {
    $id = $1;
  }

  if (/\bhelo=([-A-Za-z0-9\.\^+_&:=?!@%*\$\\\/]+)(?:[^-A-Za-z0-9\.\^+_&:=?!@%*\$\\\/]|$)/) {
      $helo = $1;
  }
  elsif (/\b(?:HELO|EHLO) ([-A-Za-z0-9\.\^+_&:=?!@%*\$\\\/]+)(?:[^-A-Za-z0-9\.\^+_&:=?!@%*\$\\\/]|$)/) {
      $helo = $1;
  }
  if (/ by (\S+)(?:[^-A-Za-z0-9\;\.]|$)/) { $by = $1; }

# ---------------------------------------------------------------------------

  # try to catch authenticated message identifier
  #
  # with ESMTPA, ESMTPSA, LMTPA, LMTPSA should cover RFC 3848 compliant MTAs,
  # UTF8SMTPA and UTF8LMTPA are covered by RFC 4954 and RFC 6531,
  # with ASMTP (Authenticated SMTP) is used by Earthlink, Exim 4.34, and others
  # with HTTP should only be authenticated webmail sessions
  # with HTTPU is used by Communigate Pro with Pronto! webmail interface
  # IANA registry: http://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml
  if (/ by / && / with ((?:ES|L|UTF8S|UTF8L)MTPS?A|ASMTP|HTTPU?)(?: |;|$)/i) {
    $auth = $1;
  }
  # GMail should use ESMTPSA to indicate that it is in fact authenticated,
  # but doesn't.
  elsif (/ by mx\.google\.com with ESMTPS id [a-z0-9]{1,4}sm[0-9]{2,9}[a-z]{3}\.[0-9]{1,3}\.[0-9]{4}\.(?:[0-6][0-9]\.){4}[0-6][0-9]/ && /\(version=([^ ]+) cipher=([^\)]+)\)/ ) {
    $auth = 'GMail - transport=' . $1 . ' cipher=' . $2;
  }
  # Courier v0.47 and possibly others
  elsif (/^from .*?(?:\]\)|\)\]) \(AUTH: (LOGIN|PLAIN|DIGEST-MD5|CRAM-MD5) \S+(?:, .*?)?\) by /) {
    $auth = $1;
  }
  # Sendmail, MDaemon, some webmail servers, and others
  elsif (/authenticated/ && /^from .*?(?:\](?: \([^)]*\))?\)|\)\]) .*?\(.*?authenticated.*?\).*? by/) {
    $auth = 'Sendmail';
  }
  # workaround for GMX, which authenticates users but does not indicate it properly - # SMTP version
  elsif (/from \S* \((?:HELO|EHLO) (\S*)\) \[(${IP_ADDRESS})\] by (mail\.gmx\.(?:net|com)) \([^\)]+\) with ((?:ESMTP|SMTP))/) {
    $auth = "GMX ($4 / $3)";
  }
  # Critical Path Messaging Server
  elsif (/ \(authenticated as /&&/\) by .+ \(\d{1,2}\.\d\.\d{3}(?:\.\d{1,3})?\) \(authenticated as .+\) id /) {
    $auth = 'CriticalPath';
  }
  # Postfix 2.3 and later with "smtpd_sasl_authenticated_header yes"
  elsif (/\) \(Authenticated sender: \S+\) by \S+ \(Postfix\) with /) {
    $auth = 'Postfix';
  }
  # Communigate Pro - Bug 6495 adds HTTP as possible transmission method
  elsif (/CommuniGate Pro (HTTP|SMTP)/ && / \(account /) {
    $auth = 'Communigate';
  }
  # Microsoft Exchange (complete with syntax error)
  elsif (/ with Microsoft Exchange Server HTTP-DAV\b/) {
    $auth = 'HTTP-DAV';
  }
  # froufrou mailers like United Internet use a '(via HTTP)' comment, Bug 7101
  elsif (/ by / && / \(via (HTTP.?)\)(?: |;|$)/i) {
    $auth = $1;
  }

# ---------------------------------------------------------------------------

  if (s/^from //) {
    # try to catch enveloper senders
    if (/(?:return-path:? |envelope-(?:sender|from)[ =])(\S+)\b/i) {
      $envfrom = $1;
    }

    # from 142.169.110.122 (SquirrelMail authenticated user synapse) by
    # mail.nomis80.org with HTTP; Sat, 3 Apr 2004 10:33:43 -0500 (EST)
    # Expanded to NaSMail Bug 6783
    if (/ \((?:SquirrelMail|NaSMail) authenticated user /) {
      #REVERTING bug 3236 and implementing re: bug 6549
      if (/(${IP_ADDRESS})\b(?![.-]).{10,80}by (\S+) with HTTP/) {
        $ip = $1; $by = $2; goto enough;
      }
    }

    # AOL WebMail headers
    if (/aol\.com/ && /with HTTP \(WebMailUI\)/) {
      # Received: from 82.135.198.129 by FWM-M18.sysops.aol.com (64.12.168.82) with HTTP (WebMailUI); Tue, 19 Jun 2007 11:16:54 -0400
      if(/(${IP_ADDRESS}) by (\S+) \(${IP_ADDRESS}\) with HTTP \(WebMailUI\)/) {
        $ip = $1; $by = $2; goto enough;
      }
    }

    # catch MS-ish headers here
    if (/ SMTPSVC/) {
      # MS servers using this fmt do not lookup the rDNS.
      # Received: from inet-vrs-05.redmond.corp.microsoft.com ([157.54.6.157])
      # by INET-IMC-05.redmond.corp.microsoft.com with Microsoft
      # SMTPSVC(5.0.2195.6624); Thu, 6 Mar 2003 12:02:35 -0800
      # Received: from 0 ([61.31.135.91]) by bass.bass.com.eg with Microsoft
      # SMTPSVC(5.0.2195.6713); Tue, 21 Sep 2004 08:59:06 +0300
      # Received: from 0 ([61.31.138.57] RDNS failed) by nccdi.com with 
      # Microsoft SMTPSVC(6.0.3790.0); Thu, 23 Sep 2004 08:51:06 -0700
      # Received: from tthompson ([217.35.105.172] unverified) by
      # mail.neosinteractive.com with Microsoft SMTPSVC(5.0.2195.5329);
      # Tue, 11 Mar 2003 13:23:01 +0000
      # Received: from  ([172.16.1.78]) by email2.codeworksonline.com with Microsoft SMTPSVC(5.0.2195.6713); Wed, 6 Sep 2006 21:14:29 -0400
      if (/^(\S*) \(\[(${IP_ADDRESS})\][^\)]{0,40}\) by (\S+) with Microsoft SMTPSVC/) {
        $helo = $1; $ip = $2; $by = $3; goto enough;
      }

      # Received: from mail pickup service by mail1.insuranceiq.com with
      # Microsoft SMTPSVC; Thu, 13 Feb 2003 19:05:39 -0500
      if (/^mail pickup service by (\S+) with Microsoft SMTPSVC$/) {
        return 0;
      }
    }

    elsif (/\[XMail /) { # bug 3791, bug 4053
      # Received: from list.brainbuzz.com (63.146.189.86:23198) by mx1.yourtech.net with [XMail 1.20 ESMTP Server] id <S72E> for <jason@ellingson.org.spamassassin.org> from <bounce-cscommunity-11965901@list.cramsession.com.spamassassin.org>; Sat, 18 Sep 2004 23:17:54 -0500
      # Received: from list.brainbuzz.com (63.146.189.86:23198) by mx1.yourtech.net (209.32.147.34:25) with [XMail 1.20 ESMTP Server] id <S72E> for <jason@ellingson.org.spamassassin.org> from <bounce-cscommunity-11965901@list.cramsession.com.spamassassin.org>; Sat, 18 Sep 2004 23:17:54 -0500
      if (/^(\S+) \((\[?${IP_ADDRESS}\]?)(?::\d+)\) by (\S+)(?: \(\S+\))? with \[XMail/)
      {
	$helo = $1; $ip = $2; $by = $3;
        / id <(\S+)>/ and $id = $1;
        / from <(\S+)>/ and $envfrom = $1;
        goto enough;
      }
    }

    # from ([10.225.209.19:33672]) by ecelerity-va-1 (ecelerity HEAD) with SMTP id EE/20-30863-33CE1054; Fri, 08 Sep 2006 18:18:27 -0400
    # from ([127.0.0.1:32923]) by bm1-21.ed10.com (ecelerity 2.1.1ea r(11031M)) with ECSTREAM id 8B/57-16227-3764EB44 for <example@vandinter.org>; Wed, 19 Jul 2006 10:49:23 -0400
    # from ([192.168.1.151:49601] helo=dev1.democracyinaction.org) by m12.prod.democracyinaction.com (ecelerity 2.1.1.3 r(11743)) with ESMTP id 52/92-02454-89FBA054 for <example@vandinter.org>; Fri, 15 Sep 2006 10:58:32 -0400
    elsif (/\(ecelerity\b/) {
      if (/^\(\[(${IP_ADDRESS}):\d+\] helo=(\S+)\) by (\S+) /) {
        $ip = $1; $helo = $2; $by = $3;
        goto enough;
      }

      if (/^\S+ \(\[(${IP_ADDRESS}):\d+\]\) by (\S+) /) {
        $ip = $1; $by = $2;
        goto enough;
      }
    }

    elsif (/Exim/) {
      # one of the HUGE number of Exim formats :(
      # This must be scriptable.  (update: it is. cf bug 3950, 3582)
      # mss 2004-09-27: See <http://www.exim.org/exim-html-4.40/doc/html/spec_14.html#IX1315>

      # from root (helo=candygram.thunk.org) by thunker.thunk.org with local-esmtps  (tls_cipher TLS-1.0:RSA_AES_256_CBC_SHA:32)  (Exim 4.50 #1 (Debian)) id 1FwHqR-0008Bw-OG; Fri, 30 Jun 2006 08:11:35 -0400
      # from root (helo=localhost) by broadcast.iac.iafrica.com with local-bsmtp (Exim 4.30; FreeBSD) id 1GN22d-0000xp-2K for example@vandinter.org; Tue, 12 Sep 2006 08:46:43 +0200
      # from smarter (helo=localhost) by mx1-out.lists.smarterliving.com with local-bsmtp (Exim 4.24) id 1GIRA2-0007IZ-4n for example@vandinter.org; Wed, 30 Aug 2006 10:35:22 -0400
      # Received: from andrew by trinity.supernews.net with local (Exim 4.12) id 18xeL6-000Dn1-00; Tue, 25 Mar 2003 02:39:00 +0000
      if (/\bwith local(?:-\S+)? /) { return 0; }

      # Received: from [61.174.163.26] (helo=host) by sc8-sf-list1.sourceforge.net with smtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t2z0-0001NX-00 for <razor-users@lists.sourceforge.net>; Wed, 12 Mar 2003 01:57:10 -0800
      # Received: from [218.19.142.229] (helo=hotmail.com ident=yiuhyotp) by yzordderrex with smtp (Exim 3.35 #1 (Debian)) id 194BE5-0005Zh-00; Sat, 12 Apr 2003 03:58:53 +0100
      if (/^\[(${IP_ADDRESS})\] \((.*?)\) by (\S+) /) {
	$ip = $1; my $sub = $2; $by = $3;
	$sub =~ s/helo=(\S+)// and $helo = $1;
	$sub =~ s/ident=(\S*)// and $ident = $1;
	goto enough;
      }

      # Received: from sc8-sf-list1-b.sourceforge.net ([10.3.1.13] helo=sc8-sf-list1.sourceforge.net) by sc8-sf-list2.sourceforge.net with esmtp (Exim 3.31-VA-mm2 #1 (Debian)) id 18t301-0007Bh-00; Wed, 12 Mar 2003 01:58:13 -0800
      # Received: from dsl092-072-213.bos1.dsl.speakeasy.net ([66.92.72.213] helo=blazing.arsecandle.org) by sc8-sf-list1.sourceforge.net with esmtp (Cipher TLSv1:DES-CBC3-SHA:168) (Exim 3.31-VA-mm2 #1 (Debian)) id 18lyuU-0007TI-00 for <SpamAssassin-talk@lists.sourceforge.net>; Thu, 20 Feb 2003 14:11:18 -0800
      # Received: from eclectic.kluge.net ([66.92.69.221] ident=[W9VcNxE2vKxgWHD05PJbLzIHSxcmZQ/O]) by sc8-sf-list1.sourceforge.net with esmtp (Cipher TLSv1:DES-CBC3-SHA:168) (Exim 3.31-VA-mm2 #1 (Debian)) id 18m0hT-00031I-00 for <spamassassin-talk@lists.sourceforge.net>; Thu, 20 Feb 2003 16:06:00 -0800
      # Received: from mail.ssccbelen.edu.pe ([216.244.149.154]) by yzordderrex
      # with esmtp (Exim 3.35 #1 (Debian)) id 18tqiz-000702-00 for
      # <jm@example.com>; Fri, 14 Mar 2003 15:03:57 +0000
      # Received: from server040.webpack.hosteurope.de ([80.237.130.48]:52313)
      # by vps832469583.serverpool.info with esmtps
      # (TLS-1.0:DHE_RSA_3DES_EDE_CBC_SHA:24) (Exim 4.50) id 1GzVLs-0002Oz-7b...
      if (/^(\S+) \(\[(${IP_ADDRESS})\](.*?)\) by (\S+) /) {
        $rdns=$1; $ip = $2; my $sub = $3; $by = $4;
        $helo=$rdns;     # default, apparently: bug 5112
        $sub =~ s/helo=(\S+)// and $helo = $1;
        $sub =~ s/ident=(\S*)// and $ident = $1;
        goto enough;
      }

      # Received: from boggle.ihug.co.nz [203.109.252.209] by grunt6.ihug.co.nz
      # with esmtp (Exim 3.35 #1 (Debian)) id 18SWRe-0006X6-00; Sun, 29 Dec 
      # 2002 18:57:06 +1300
      if (/^(\S+) \[(${IP_ADDRESS})\](:\d+)? by (\S+) /) {
	$rdns= $1; $ip = $2; $helo = $1; $by = $4; goto enough;
      }

      # attempt to deal with other odd Exim formats; just match little bits
      # of the header.
      # Received: from helene8.i.pinwand.net (helene.cats.ms) [10.0.8.6.13219]
      # (mail) by lisbeth.i.pinwand.net with esmtp (Exim 3.35 #1 (Debian)) id
      # 1CO5y7-0001vC-00; Sun, 31 Oct 2004 04:01:23 +0100
      if (/^(\S+) /) {
        $rdns= $1;      # assume this is the rDNS, not HELO.  is this appropriate?
      }
      if (/ \((\S+)\) /) {
        $helo = $1;
      }
      if (/ \[(${IP_ADDRESS})(?:\.\d+)?\] /) {
        $ip = $1;
      }
      if (/by (\S+) /) {
        $by = $1;
        # now, if we have a "by" and an IP, that's enough for most uses;
        # we have to make do with that.
        if ($ip) { goto enough; }
      }

      # else it's probably forged. fall through
    }

    elsif (/ \(Postfix\) with/) {
      # Received: from localhost (unknown [127.0.0.1])
      # by cabbage.jmason.org (Postfix) with ESMTP id A96E18BD97
      # for <jm@localhost>; Thu, 13 Mar 2003 15:23:15 -0500 (EST)
      if ( /^(\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) / ) {
	$mta_looked_up_dns = 1;
	$helo = $1; $rdns = $2; $ip = $3; $by = $4;
	if ($rdns eq 'unknown') { $rdns = ''; }
	goto enough;
      }

      # Received: from 207.8.214.3 (unknown[211.94.164.65])
      # by puzzle.pobox.com (Postfix) with SMTP id 9029AFB732;
      # Sat,  8 Nov 2003 17:57:46 -0500 (EST)
      # (Pobox.com version: reported in bug 2745)
      if ( /^(\S+) \((\S+)\[(${IP_ADDRESS})\]\) by (\S+) / ) {
	$mta_looked_up_dns = 1;
	$helo = $1; $rdns = $2; $ip = $3; $by = $4;
	if ($rdns eq 'unknown') { $rdns = ''; }
	goto enough;
      }
    }

    elsif (/\(Scalix SMTP Relay/) {
      # from DPLAPTOP ( 72.242.176.162) by mail.puryear-it.com (Scalix SMTP Relay 10.0.1.3) via ESMTP; Fri, 23 Jun 2006 16:39:47 -0500 (CDT)
      if (/^(\S+) \( ?(${IP_ADDRESS})\) by (\S+)/) {
	$helo = $1; $ip = $2; $by = $3; goto enough;
      }
    }

    elsif (/ \(Lotus Domino /) {
      # it seems Domino never records the rDNS: bug 5926
      if (/^(\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) \(Lotus/) {
        $mta_looked_up_dns = 0;
	$helo = $1; $ip = $2; $by = $3; goto enough;
      }
    }

    # Received: from 217.137.58.28 ([217.137.58.28])
    # by webmail.ukonline.net (IMP) with HTTP
    # for <anarchyintheuk@localhost>; Sun, 11 Apr 2004 00:31:07 +0100
    if (/\bwith HTTP\b/ &&        # more efficient split up this way
        /^(${IP_ADDRESS}) \(\[${IP_ADDRESS}\]\) by (\S+)/)
    {
      # some smarty-pants decided to fake a numeric HELO for HTTP
      # no rDNS for this format?
      $ip = $1; $by = $2; goto enough;
    }

    # MiB: 2003/11/29 Some qmail-ldap headers may be misinterpreted as sendmail-headers
    #      resulting in a messed-up interpretation. We have to skip sendmail tests
    #      if we find evidence that this is a qmail-ldap header.
    #
    unless (/ by \S+ \(qmail-\S+\) with /) {
      #
      # sendmail:
      # Received: from mail1.insuranceiq.com (host66.insuranceiq.com [65.217.159.66] (may be forged)) by dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id h2F0c2x31856 for <jm@jmason.org>; Sat, 15 Mar 2003 00:38:03 GMT
      # Received: from BAY0-HMR08.adinternal.hotmail.com (bay0-hmr08.bay0.hotmail.com [65.54.241.207]) by dogma.slashnull.org (8.11.6/8.11.6) with ESMTP id h2DBpvs24047 for <webmaster@efi.ie>; Thu, 13 Mar 2003 11:51:57 GMT
      # Received: from ran-out.mx.develooper.com (IDENT:qmailr@one.develooper.com [64.81.84.115]) by dogma.slashnull.org (8.11.6/8.11.6) with SMTP id h381Vvf19860 for <jm-cpan@jmason.org>; Tue, 8 Apr 2003 02:31:57 +0100
      # from rev.net (natpool62.rev.net [63.148.93.62] (may be forged)) (authenticated) by mail.rev.net (8.11.4/8.11.4) with ESMTP id h0KKa7d32306 for <spamassassin-talk@lists.sourceforge.net>
      #
      if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\].*\) by (\S+) \(/) {
        $mta_looked_up_dns = 1;
        $helo = $1; $rdns = $2; $ip = $3; $by = $4;
        $rdns =~ s/^IDENT:([^\@]*)\@// and $ident = $1; # remove IDENT lookups
        $rdns =~ s/^([^\@]*)\@// and $ident = $1;	# remove IDENT lookups
        goto enough;
      }
    }

# ---------------------------------------------------------------------------

    ## OK, AT THIS POINT FORMATS GET A BIT NON-STANDARD

    # Received: from ns.elcanto.co.kr (66.161.246.58 [66.161.246.58]) by
    # mail.ssccbelen.edu.pe with SMTP (Microsoft Exchange Internet Mail Service
    # Version 5.5.1960.3) id G69TW478; Thu, 13 Mar 2003 14:01:10 -0500
    if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) with \S+ \(/) {
      $mta_looked_up_dns = 1;
      $rdns = $2; $ip = $3; $helo = $1; $by = $4; goto enough;
    }

    # from mail2.detr.gsi.gov.uk ([51.64.35.18] helo=ahvfw.dtlr.gsi.gov.uk) by mail4.gsi.gov.uk with smtp id 190K1R-0000me-00 for spamassassin-talk-admin@lists.sourceforge.net; Tue, 01 Apr 2003 12:33:46 +0100
    if (/^(\S+) \(\[(${IP_ADDRESS})\] helo=(\S+)\) by (\S+) with /) {
      $rdns = $1; $ip = $2; $helo = $3; $by = $4;
      goto enough;
    }

    # from 12-211-5-69.client.attbi.com (<unknown.domain>[12.211.5.69]) by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <2002112823351305300akl1ue>; Thu, 28 Nov 2002 23:35:13 +0000
    if (/^(\S+) \(<unknown\S*>\[(${IP_ADDRESS})\]\) by (\S+) /) {
      $helo = $1; $ip = $2; $by = $3;
      goto enough;
    }

    # from attbi.com (h000502e08144.ne.client2.attbi.com[24.128.27.103]) by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <20030222193438053008f7tee>; Sat, 22 Feb 2003 19:34:39 +0000
    if (/^(\S+) \((\S+\.\S+)\[(${IP_ADDRESS})\]\) by (\S+) /) {
      $mta_looked_up_dns = 1;
      $helo = $1; $rdns = $2; $ip = $3; $by = $4;
      goto enough;
    }


    # Received: from 4wtgRl (kgbxn@[211.244.147.115]) by dogma.slashnull.org (8.11.6/8.11.6) with SMTP id h8BBsUJ18848; Thu, 11 Sep 2003 12:54:31 +0100
    if (/^(\S+) \((\S*)\@\[(${IP_ADDRESS})\].*\) by (\S+) \(/) {
      $mta_looked_up_dns = 1;	# this one does.  there just wasn't one
      $helo = $1; $ip = $3; $by = $4;
      $ident = $2;
      goto enough;
    }

    # Received: from 213.123.174.21 by lw11fd.law11.hotmail.msn.com with HTTP;
    # Wed, 24 Jul 2002 16:36:44 GMT
    if (/by (\S+\.hotmail\.msn\.com) /) {
      $by = $1;
      /^(\S+) / and $ip = $1;
      goto enough;
    }

    # Received: from x71-x56-x24-5.webspeed.dk (HELO niels) (69.96.3.15) by la.mx.develooper.com (qpsmtpd/0.27-dev) with SMTP; Fri, 02 Jan 2004 19:26:52 -0800
    # Received: from sc8-sf-sshgate.sourceforge.net (HELO sc8-sf-netmisc.sourceforge.net) (66.35.250.220) by la.mx.develooper.com (qpsmtpd/0.27-dev) with ESMTP; Fri, 02 Jan 2004 14:44:41 -0800
    # Received: from mx10.topofferz.net (HELO ) (69.6.60.10) by blazing.arsecandle.org with SMTP; 3 Mar 2004 20:34:38 -0000
    if (/^(\S+) \((?:HELO|EHLO) (\S*)\) \((${IP_ADDRESS})\) by (\S+) \(qpsmtpd\/\S+\) with (?:ESMTP|SMTP)/) {
      $rdns = $1; $helo = $2; $ip = $3; $by = $4; goto enough;
    }

    # from dslb-082-083-045-064.pools.arcor-ip.net (EHLO homepc) [82.83.45.64] by mail.gmx.net (mp010) with SMTP; 03 Feb 2007 13:13:47 +0100
    if (/^(\S+) \((?:HELO|EHLO) (\S*)\) \[(${IP_ADDRESS})\] by (\S+) \([^\)]+\) with (?:ESMTP|SMTP)/) {
      $rdns = $1; $helo = $2; $ip = $3; $by = $4; goto enough;
    }

    # MiB (Michel Bouissou, 2003/11/16)
    # Moved some tests up because they might match on qmail tests, where this
    # is not qmail
    #
    # Received: from imo-m01.mx.aol.com ([64.12.136.4]) by eagle.glenraven.com
    # via smtpd (for [198.85.87.98]) with SMTP; Wed, 08 Oct 2003 16:25:37 -0400
    if (/^(\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) via smtpd \(for \S+\) with SMTP\(/) {
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Try to match most of various qmail possibilities
    #
    # General format:
    # Received: from postfix3-2.free.fr (HELO machine.domain.com) (foobar@213.228.0.169) by totor.bouissou.net with SMTP; 14 Nov 2003 08:05:50 -0000
    #
    # "from (remote.rDNS|unknown)" is always there
    # "(HELO machine.domain.com)" is there only if HELO differs from remote rDNS.
    # HELO may be "" -- ie no string. "HELO" may also be "EHLO".  HELO string
    # may be an IP in fmt [1.2.3.4] -- do not strip [ and ], they are important.
    # "foobar@" is remote IDENT info, specified only if ident given by remote
    # Remote IP always appears between (parentheses), with or without IDENT@
    # "by local.system.domain.com" always appears
    #
    # Protocol can be different from "SMTP", i.e. "RC4-SHA encrypted SMTP" or "QMQP"
    # qmail's reported protocol shouldn't be "ESMTP", so by allowing only "with (.* )(SMTP|QMQP)"
    # we should avoid matching on some sendmailish Received: lines that reports remote IP
    # between ([218.0.185.24]) like qmail-ldap does, but use "with ESMTP".
    #
    # Normally, qmail-smtpd remote IP isn't between square brackets [], but some versions of
    # qmail-ldap seem to add square brackets around remote IP. These versions of qmail-ldap
    # use a longer format that also states the (envelope-sender <sender@domain>) and the
    # qmail-ldap version. Example:
    # Received: from unknown (HELO terpsichore.farfalle.com) (jdavid@[216.254.40.70]) (envelope-sender <jdavid@farfalle.com>) by mail13.speakeasy.net (qmail-ldap-1.03) with SMTP for <jm@jmason.org>; 12 Feb 2003 18:23:19 -0000
    #
    # Some others of the numerous qmail patches out there can also add variants of their own
    #
    # Received: from 211.245.85.228  (EHLO ) (211.245.85.228) by mta232.mail.scd.yahoo.com with SMTP; Sun, 25 Jan 2004 00:24:37 -0800
    #
    # bug 4813: make sure that the line doesn't have " id " after the
    # protocol since that's a sendmail line and not qmail ...
    if (/^\S+( \((?:HELO|EHLO) \S*\))? \((\S+\@)?\[?${IP_ADDRESS}\]?\)( \(envelope-sender <\S+>\))? by \S+( \(.+\))* with (.* )?(SMTP|QMQP)(?! id )/ ) {
       if (/^(\S+) \((?:HELO|EHLO) ([^ \(\)]*)\) \((\S*)\@\[?(${IP_ADDRESS})\]?\)( \(envelope-sender <\S+>\))? by (\S+)/) {
         $rdns = $1; $helo = $2; $ident = $3; $ip = $4; $by = $6;
       }
       elsif (/^(\S+) \((?:HELO|EHLO) ([^ \(\)]*)\) \(\[?(${IP_ADDRESS})\]?\)( \(envelope-sender <\S+>\))? by (\S+)/) {
         $rdns = $1; $helo = $2; $ip = $3; $by = $5;
       }
       elsif (/^(\S+) \((\S*)\@\[?(${IP_ADDRESS})\]?\)( \(envelope-sender <\S+>\))? by (\S+)/) {
	 # note: absence of HELO means that it matched rDNS in qmail-land
         $helo = $rdns = $1; $ident = $2; $ip = $3; $by = $5;
       }
       elsif (/^(\S+) \(\[?(${IP_ADDRESS})\]?\)( \(envelope-sender <\S+>\))? by (\S+)/) {
         $helo = $rdns = $1; $ip = $2; $by = $4;
       }
       # qmail doesn't perform rDNS requests by itself, but is usually called
       # by tcpserver or a similar daemon that passes rDNS information to qmail-smtpd.
       # If qmail puts something else than "unknown" in the rDNS field, it means that
       # it received this information from the daemon that called it. If qmail-smtpd
       # writes "Received: from unknown", it means that either the remote has no
       # rDNS, or qmail was called by a daemon that didn't gave the rDNS information.
       if ($rdns ne "unknown") {
          $mta_looked_up_dns = 1;
       } else {
          $rdns = '';
       }
       goto enough;

    }
    # /MiB
    
    # Received: from [193.220.176.134] by web40310.mail.yahoo.com via HTTP;
    # Wed, 12 Feb 2003 14:22:21 PST
    if (/ via HTTP$/&&/^\[(${IP_ADDRESS})\] by (\S+) via HTTP$/) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from 192.168.5.158 ( [192.168.5.158]) as user jason@localhost by mail.reusch.net with HTTP; Mon, 8 Jul 2002 23:24:56 -0400
    if (/^(\S+) \( \[(${IP_ADDRESS})\]\).*? by (\S+) /) {
      # TODO: is $1 helo?
      $ip = $2; $by = $3; goto enough;
    }

    # Received: from (64.52.135.194 [64.52.135.194]) by mail.unearthed.com with ESMTP id BQB0hUH2 Thu, 20 Feb 2003 16:13:20 -0700 (PST)
    if (/^\((\S+) \[(${IP_ADDRESS})\]\) by (\S+) /) {
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from [65.167.180.251] by relent.cedata.com (MessageWall 1.1.0) with SMTP; 20 Feb 2003 23:57:15 -0000
    if (/^\[(${IP_ADDRESS})\] by (\S+) /) {
      $ip = $1; $by = $2; goto enough;
    }

    # from  ([172.16.1.78]) by email2.codeworksonline.com with Microsoft SMTPSVC(5.0.2195.6713); Wed, 6 Sep 2006 21:14:29 -0400
    # from (130.215.36.186) by mcafee.wpi.edu via smtp id 021b_7e19a55a_ea7e_11da_83a9_00304811e63a; Tue, 23 May 2006 13:06:35 -0400
    # from ([172.21.2.10]) by out-relay4.mtahq.org with ESMTP  id 4420961.8281; Tue, 22 Aug 2006 17:53:08 -0400
    if (/^\(\[?(${IP_ADDRESS})\]?\) by (\S+) /) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from acecomms [202.83.84.95] by mailscan.acenet.net.au [202.83.84.27] with SMTP (MDaemon.PRO.v5.0.6.R) for <spamassassin-talk@lists.sourceforge.net>; Fri, 21 Feb 2003 09:32:27 +1000
    if (/^(\S+) \[(${IP_ADDRESS})\] by (\S+) \[(\S+)\] with /) {
      $mta_looked_up_dns = 1;
      $helo = $1; $ip = $2;
      $by = $4; # use the IP addr for "by", more useful?
      goto enough;
    }

    # Received: from mail.sxptt.zj.cn ([218.0.185.24]) by dogma.slashnull.org
    # (8.11.6/8.11.6) with ESMTP id h2FH0Zx11330 for <webmaster@efi.ie>;
    # Sat, 15 Mar 2003 17:00:41 GMT
    if (/^(\S+) \(\[(${IP_ADDRESS})\]\) by (\S+) \(/) { # sendmail
      $mta_looked_up_dns = 1;
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from umr-mail7.umr.edu (umr-mail7.umr.edu [131.151.1.64]) via ESMTP by mrelay1.cc.umr.edu (8.12.1/) id h06GHYLZ022481; Mon, 6 Jan 2003 10:17:34 -0600
    # Received: from Agni (localhost [::ffff:127.0.0.1]) (TLS: TLSv1/SSLv3, 168bits,DES-CBC3-SHA) by agni.forevermore.net with esmtp; Mon, 28 Oct 2002 14:48:52 -0800
    # Received: from gandalf ([4.37.75.131]) (authenticated bits=0) by herald.cc.purdue.edu (8.12.5/8.12.5/herald) with ESMTP id g9JLefrm028228 for <spamassassin-talk@lists.sourceforge.net>; Sat, 19 Oct 2002 16:40:41 -0500 (EST)
    # Received: from bushinternet.com (softdnserr [::ffff:61.99.99.67]) by mail.cs.helsinki.fi with esmtp; Fri, 22 Aug 2003 12:25:41 +0300
    if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\]\).*? by (\S+)\b/) { # sendmail
      if ($2 eq 'softdnserr') {
        $mta_looked_up_dns = 0; # bug 2326: couriertcpd
      } else {
        $mta_looked_up_dns = 1; $rdns = $2;
      }
      $helo = $1; $ip = $3; $by = $4; goto enough;
    }

    # from jsoliday.acs.internap.com ([63.251.66.24.63559]) by
    # mailhost.acs.internap.com with esmtp  (v3.35.1) id 1GNrLz-000295-00;
    # Thu, 14 Sep 2006 09:34:07 -0400
    if (/^(\S+) \(\[(${IP_ADDRESS})(?:[.:]\d+)?\]\).*? by (\S+) /) {
      $mta_looked_up_dns = 1;
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from roissy (p573.as1.exs.dublin.eircom.net [159.134.226.61])
    # (authenticated bits=0) by slate.dublin.wbtsystems.com (8.12.6/8.12.6)
    # with ESMTP id g9MFWcvb068860 for <jm@jmason.org>;
    # Tue, 22 Oct 2002 16:32:39 +0100 (IST)
    if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\]\)(?: \(authenticated bits=\d+\))? by (\S+) \(/) { # sendmail
      $mta_looked_up_dns = 1;
      $helo = $1; $rdns = $2; $ip = $3; $by = $4; goto enough;
    }

    # Received: from cabbage.jmason.org [127.0.0.1]
    # by localhost with IMAP (fetchmail-5.9.0)
    # for jm@localhost (single-drop); Thu, 13 Mar 2003 20:39:56 -0800 (PST)
    if (/fetchmail/&&/^(\S+) (?:\[(${IP_ADDRESS})\] )?by (\S+) with \S+ \(fetchmail/) {
      $self->found_pop_fetcher_sig();
      return 0;		# skip fetchmail handovers
    }

    # Let's try to support a few qmailish formats in one;
    # http://issues.apache.org/SpamAssassin/show_bug.cgi?id=2744#c14 :
    # Received: from unknown (HELO feux01a-isp) (213.199.4.210) by totor.bouissou.net with SMTP; 1 Nov 2003 07:05:19 -0000 
    # Received: from adsl-207-213-27-129.dsl.lsan03.pacbell.net (HELO merlin.net.au) (Owner50@207.213.27.129) by totor.bouissou.net with SMTP; 10 Nov 2003 06:30:34 -0000 
    if (/^(\S+) \((?:HELO|EHLO) ([^\)]*)\) \((\S*@)?\[?(${IP_ADDRESS})\]?\).* by (\S+) /)
    {
      $mta_looked_up_dns = 1;
      $rdns = $1; 
      $helo = $2; 
      $ident = (defined $3) ? $3 : '';
      $ip = $4; 
      $by = $5;
      if ($ident) { 
        $ident =~ s/\@$//; 
      }
      goto enough;
    }

    # Received: from x1-6-00-04-bd-d2-e0-a3.k317.webspeed.dk (benelli@80.167.158.170) by totor.bouissou.net with SMTP; 5 Nov 2003 23:18:42 -0000
    if (/^(\S+) \((\S*@)?\[?(${IP_ADDRESS})\]?\).* by (\S+) /)
    {
      $mta_looked_up_dns = 1;
      # bug 2744 notes that if HELO == rDNS, qmail drops it.
      $rdns = $1; $helo = $rdns; $ident = (defined $2) ? $2 : '';
      $ip = $3; $by = $4;
      if ($ident) { $ident =~ s/\@$//; }
      goto enough;
    }

    # Received: from [129.24.215.125] by ws1-7.us4.outblaze.com with http for
    # _bushisevil_@mail.com; Thu, 13 Feb 2003 15:59:28 -0500
    if (/ with http for /&&/^\[(${IP_ADDRESS})\] by (\S+) with http for /) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from po11.mit.edu [18.7.21.73]
    # by stark.dyndns.tv with POP3 (fetchmail-5.9.7)
    # for stark@localhost (single-drop); Tue, 18 Feb 2003 10:43:09 -0500 (EST)
    # by po11.mit.edu (Cyrus v2.1.5) with LMTP; Tue, 18 Feb 2003 09:49:46 -0500
    if (/ with POP3 /&&/^(\S+) \[(${IP_ADDRESS})\] by (\S+) with POP3 /) {
      $rdns = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from snake.corp.yahoo.com(216.145.52.229) by x.x.org via smap (V1.3)
    # id xma093673; Wed, 26 Mar 03 20:43:24 -0600
    if (/ via smap /&&/^(\S+)\((${IP_ADDRESS})\) by (\S+) via smap /) {
      $mta_looked_up_dns = 1;
      $rdns = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from smtp.greyware.com(208.14.208.51, HELO smtp.sff.net) by x.x.org via smap (V1.3)
    # id xma002908; Fri, 27 Feb 04 14:16:56 -0800
    if (/^(\S+)\((${IP_ADDRESS}), (?:HELO|EHLO) (\S*)\) by (\S+) via smap /) {
      $mta_looked_up_dns = 1;
      $rdns = $1; $ip = $2; $helo = $3; $by = $4; goto enough;
    }

    # Received: from [192.168.0.71] by web01-nyc.clicvu.com (Post.Office MTA
    # v3.5.3 release 223 ID# 0-64039U1000L100S0V35) with SMTP id com for
    # <x@x.org>; Tue, 25 Mar 2003 11:42:04 -0500
    if (/ \(Post/&&/^\[(${IP_ADDRESS})\] by (\S+) \(Post/) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from [127.0.0.1] by euphoria (ArGoSoft Mail Server 
    # Freeware, Version 1.8 (1.8.2.5)); Sat, 8 Feb 2003 09:45:32 +0200
    if (/ \(ArGoSoft/&&/^\[(${IP_ADDRESS})\] by (\S+) \(ArGoSoft/) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from 157.54.8.23 by inet-vrs-05.redmond.corp.microsoft.com
    # (InterScan E-Mail VirusWall NT); Thu, 06 Mar 2003 12:02:35 -0800
    # Received: from 10.165.130.62 by CNNIMAIL12.CNN.COM (SMTPL release 1.0d) with TCP; Fri, 1 Sep 2006 20:28:14 -0400
    if (/^(${IP_ADDRESS}) by (\S+) \((?:SMTPL|InterScan)\b/) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from faerber.muc.de by slarti.muc.de with BSMTP (rsmtp-qm-ot 0.4)
    # for asrg@ietf.org; 7 Mar 2003 21:10:38 -0000
    if (/ with BSMTP/&&/^\S+ by \S+ with BSMTP/) {
      return 0;	# BSMTP != a TCP/IP handover, ignore it
    }

    # Received: from spike (spike.ig.co.uk [193.32.60.32]) by mail.ig.co.uk with
    # SMTP id h27CrCD03362 for <asrg@ietf.org>; Fri, 7 Mar 2003 12:53:12 GMT
    if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\]\) by (\S+) with /) {
      $mta_looked_up_dns = 1;
      $helo = $1; $rdns = $2; $ip = $3; $by = $4; goto enough;
    }

    # Received: from customer254-217.iplannetworks.net (HELO AGAMENON) 
    # (baldusi@200.69.254.217 with plain) by smtp.mail.vip.sc5.yahoo.com with
    # SMTP; 11 Mar 2003 21:03:28 -0000
    if (/^(\S+) \((?:HELO|EHLO) (\S*)\) \((\S+).*?\) by (\S+) with /) {
      $mta_looked_up_dns = 1;
      $rdns = $1; $helo = $2; $ip = $3; $by = $4;
      $ip =~ s/([^\@]*)\@//g and $ident = $1;	# remove IDENT lookups
      goto enough;
    }

    # Received: from [192.168.1.104] (account nazgul HELO [192.168.1.104])
    # by somewhere.com (CommuniGate Pro SMTP 3.5.7) with ESMTP-TLS id 2088434;
    # Fri, 07 Mar 2003 13:05:06 -0500
    if (/^\[(${IP_ADDRESS})\] \((?:account \S+ )?(?:HELO|EHLO) (\S*)\) by (\S+) \(/) {
      $ip = $1; $helo = $2; $by = $3; goto enough;
    }

    # Received: from host.example.com ([192.0.2.1] verified)
    # by mail.example.net (CommuniGate Pro SMTP 5.1.13)
    # with ESMTP id 9786656 for user@example.net; Thu, 27 Mar 2008 15:08:17 +0600
    if (/ \(CommuniGate Pro/ && /^(\S+) \(\[(${IP_ADDRESS})\] verified\) by (\S+) \(/) {
      $mta_looked_up_dns = 1;
      $rdns = $1; $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from ([10.0.0.6]) by mail0.ciphertrust.com with ESMTP ; Thu,
    # 13 Mar 2003 06:26:21 -0500 (EST)
    if (/^\(\[(${IP_ADDRESS})\]\) by (\S+) with /) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from ironport.com (10.1.1.5) by a50.ironport.com with ESMTP; 01 Apr 2003 12:00:51 -0800
    # Received: from dyn-81-166-39-132.ppp.tiscali.fr (81.166.39.132) by cpmail.dk.tiscali.com (6.7.018)
    if (/^([^\d]\S+) \((${IP_ADDRESS})\) by (\S+) /) {
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from scv3.apple.com (scv3.apple.com) by mailgate2.apple.com (Content Technologies SMTPRS 4.2.1) with ESMTP id <T61095998e1118164e13f8@mailgate2.apple.com>; Mon, 17 Mar 2003 17:04:54 -0800
    # bug 4704: Only let this match Content Technologies so it stops breaking things that come after it by matching first
    if (/^\S+ \(\S+\) by \S+ \(Content Technologies /) {
      return 0;		# useless without the $ip anyway!
    }

    # Received: from 01al10015010057.ad.bls.com ([90.152.5.141] [90.152.5.141])
    # by aismtp3g.bls.com with ESMTP; Mon, 10 Mar 2003 11:10:41 -0500
    if (/^(\S+) \(\[(\S+)\] \[(\S+)\]\) by (\S+) with /) {
      # not sure what $3 is ;)
      $helo = $1; $ip = $2; $by = $4;
      goto enough;
    }

    # Received: from 206.47.0.153 by dm3cn8.bell.ca with ESMTP (Tumbleweed MMS
    # SMTP Relay (MMS v5.0)); Mon, 24 Mar 2003 19:49:48 -0500
    if (/^(${IP_ADDRESS}) by (\S+) with /) {
      $ip = $1; $by = $2;
      goto enough;
    }

    # Received: from pobox.com (h005018086b3b.ne.client2.attbi.com[66.31.45.164])
    # by rwcrmhc53.attbi.com (rwcrmhc53) with SMTP id <2003031302165605300suph7e>;
    # Thu, 13 Mar 2003 02:16:56 +0000
    if (/^(\S+) \((\S+)\[(${IP_ADDRESS})\]\) by (\S+) /) {
      $mta_looked_up_dns = 1;
      $helo = $1; $rdns = $2; $ip = $3; $by = $4; goto enough;
    }

    # Received: from [10.128.128.81]:50999 (HELO dfintra.f-secure.com) by fsav4im2 ([10.128.128.74]:25) (F-Secure Anti-Virus for Internet Mail 6.0.34 Release) with SMTP; Tue, 5 Mar 2002 14:11:53 -0000
    if (/^\[(${IP_ADDRESS})\]\S+ \((?:HELO|EHLO) (\S*)\) by (\S+) /) {
      $ip = $1; $helo = $2; $by = $3; goto enough;
    }

    # Received: from 62.180.7.250 (HELO daisy) by smtp.altavista.de (209.228.22.152) with SMTP; 19 Sep 2002 17:03:17 +0000
    if (/^(${IP_ADDRESS}) \((?:HELO|EHLO) (\S*)\) by (\S+) /) {
      $ip = $1; $helo = $2; $by = $3; goto enough;
    }

    # Received: from oemcomputer [63.232.189.195] by highstream.net (SMTPD32-7.07) id A4CE7F2A0028; Sat, 01 Feb 2003 21:39:10 -0500
    if (/^(\S+) \[(${IP_ADDRESS})\] by (\S+) /) {
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # from nodnsquery(192.100.64.12) by herbivore.monmouth.edu via csmap (V4.1) id srcAAAyHaywy
    if (/^(\S+)\((${IP_ADDRESS})\) by (\S+) /) {
      $rdns = $1; $ip = $2; $by = $3; goto enough;
    }

    # Received: from [192.168.0.13] by <server> (MailGate 3.5.172) with SMTP;
    # Tue, 1 Apr 2003 15:04:55 +0100
    if (/^\[(${IP_ADDRESS})\] by (\S+) \(MailGate /) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from jmason.org (unverified [195.218.107.131]) by ni-mail1.dna.utvinternet.net <B0014212518@ni-mail1.dna.utvinternet.net>; Tue, 11 Feb 2003 12:18:12 +0000
    if (/^(\S+) \(unverified \[(${IP_ADDRESS})\]\) by (\S+) /) {
      $helo = $1; $ip = $2; $by = $3; goto enough;
    }

    # # from 165.228.131.11 (proxying for 139.130.20.189) (SquirrelMail authenticated user jmmail) by jmason.org with HTTP
    # if (/^from (\S+) \(proxying for (${IP_ADDRESS})\) \([A-Za-z][^\)]+\) by (\S+) with /) {
    # $ip = $2; $by = $3; goto enough;
    # }
    if (/^(${IP_ADDRESS}) \([A-Za-z][^\)]+\) by (\S+) with /) {
      $ip = $1; $by = $2; goto enough;
    }

    # Received: from [212.87.144.30] (account seiz [212.87.144.30] verified) by x.imd.net (CommuniGate Pro SMTP 4.0.3) with ESMTP-TLS id 5026665 for spamassassin-talk@lists.sourceforge.net; Wed, 15 Jan 2003 16:27:05 +0100
    # bug 4704 This pattern was checked as just an Exim format, but it does exist elsewhere
    # Received: from [206.51.230.145] (helo=t-online.de)
    #   by mxeu2.kundenserver.de with ESMTP (Nemesis),
    #  id 0MKpdM-1CkRpr14PF-000608; Fri, 31 Dec 2004 19:49:15 +0100
    # Received: from [218.19.142.229] (helo=hotmail.com ident=yiuhyotp)
    #   by yzordderrex with smtp (Exim 3.35 #1 (Debian)) id 194BE5-0005Zh-00; Sat, 12 Apr 2003 03:58:53 +0100
    if (/^\[(${IP_ADDRESS})\] \(([^\)]+)\) by (\S+) /) {
      $ip = $1; my $sub = $2; $by = $3;
      $sub =~ s/helo=(\S+)// and $helo = $1;
      $sub =~ s/ident=(\S*)// and $ident = $1;
      goto enough;
    }

    # Received: from mtsbp606.email-info.net (?dXqpg3b0hiH9faI2OxLT94P/YKDD3rQ1?@64.253.199.166) by kde.informatik.uni-kl.de with SMTP; 30 Apr 2003 15:06:29
    if (/^(\S+) \((?:\S+\@)?(${IP_ADDRESS})\) by (\S+) with /) {
      $rdns = $1; $ip = $2; $by = $3; goto enough;
    }

    # Obtuse smtpd: http://www.obtuse.com/
    # Received: from TCE-E-7-182-54.bta.net.cn(202.106.182.54) via SMTP
    #  by st.tahina.priv.at, id smtpdEDUB8h; Sun Nov 13 14:50:12 2005
    # Received: from pl027.nas934.d-osaka.nttpc.ne.jp(61.197.82.27), claiming to be "foo.woas.net" via SMTP
    #  by st.tahina.priv.at, id smtpd1PBsZT; Sun Nov 13 15:38:52 2005
    if (/^(\S+)\((${IP_ADDRESS})\)(?:, claiming to be "(\S+)")? via \S+ by (\S+),/) {
      $rdns = $1; $ip = $2; $helo = (defined $3) ? $3 : ''; $by = $4;
      if ($1 ne 'UNKNOWN') {
	$mta_looked_up_dns = 1;
	$rdns = $1;
      }
      goto enough;
    }

    # Yahoo Authenticated SMTP; Bug #6535
    # from itrqtnlnq (lucilleskinner@93.124.107.183 with login) by smtp111.mail.ne1.yahoo.com with SMTP; 17 Jan 2011 08:23:27 -0800 PST
    if (/^(\S+) \((\S+)@(${IP_ADDRESS}) with login\) by (\S+\.yahoo\.com) with SMTP/) {
      $helo = $1; $ip = $3; $by = $4; goto enough;
    }

    # a synthetic header, generated internally:
    # Received: X-Originating-IP: 1.2.3.4
    if (/^X-Originating-IP: (\S+)$/) {
      $ip = $1; $by = ''; goto enough;
    }

    ## STUFF TO IGNORE ##

    # Received: from raptor.research.att.com (bala@localhost) by
    # raptor.research.att.com (SGI-8.9.3/8.8.7) with ESMTP id KAA14788 
    # for <asrg@example.com>; Fri, 7 Mar 2003 10:37:56 -0500 (EST)
    # make this localhost-specific, so we know it's safe to ignore
    if (/^\S+ \([^\s\@]+\@${LOCALHOST}\) by \S+ \(/) { return 0; }

    # from paul (helo=felix) by felix.peema.org with local-esmtp (Exim 4.43)
    # id 1Ccq0j-0002k2-Lk; Fri, 10 Dec 2004 19:01:01 +0000
    # Exim doco says this is local submission, cf switch -oMr
    if (/^\S+ \S+ by \S+ with local-e?smtp /) { return 0; }

    # from 127.0.0.1 (AVG SMTP 7.0.299 [265.6.8]); Wed, 05 Jan 2005 15:06:48 -0800
    if (/^127\.0\.0\.1 \(AVG SMTP \S+ \[\S+\]\)/) { return 0; }

    # from qmail-scanner-general-admin@lists.sourceforge.net by alpha by uid 7791 with qmail-scanner-1.14 (spamassassin: 2.41. Clear:SA:0(-4.1/5.0):. Processed in 0.209512 secs)
    if (/^\S+\@\S+ by \S+ by uid \S+ /) { return 0; }

    # Received: from DSmith1204@aol.com by imo-m09.mx.aol.com (mail_out_v34.13.) id 7.53.208064a0 (4394); Sat, 11 Jan 2003 23:24:31 -0500 (EST)
    if (/^\S+\@\S+ by \S+ /) { return 0; }

    # Received: from Unknown/Local ([?.?.?.?]) by mailcity.com; Fri, 17 Jan 2003 15:23:29 -0000
    if (/^Unknown\/Local \(/) { return 0; }

    # Received: from localhost (mailnull@localhost) by x.org (8.12.6/8.9.3) 
    # with SMTP id h2R2iivG093740; Wed, 26 Mar 2003 20:44:44 -0600 
    # (CST) (envelope-from x@x.org)
    # Received: from localhost (localhost [127.0.0.1]) (uid 500) by mail with local; Tue, 07 Jan 2003 11:40:47 -0600
    if (/^${LOCALHOST} \((?:\S+\@)?${LOCALHOST}[\)\[]/) { return 0; }

    # Received: from olgisoft.com (127.0.0.1) by 127.0.0.1 (EzMTS MTSSmtp
    # 1.55d5) ; Thu, 20 Mar 03 10:06:43 +0100 for <asrg@ietf.org>
    if (/^\S+ \((?:\S+\@)?${LOCALHOST}\) /) { return 0; }

    # Received: from casper.ghostscript.com (raph@casper [127.0.0.1]) h148aux8016336verify=FAIL); Tue, 4 Feb 2003 00:36:56 -0800
    if (/^\S+ \(\S+\@\S+ \[${LOCALHOST}\]\) /) { return 0; }

    # Received: from (AUTH: e40a9cea) by vqx.net with esmtp (courier-0.40) for <asrg@ietf.org>; Mon, 03 Mar 2003 14:49:28 +0000
    if (/^\(AUTH: \S+\) by \S+ with /) { return 0; }

    # from localhost (localhost [[UNIX: localhost]]) by home.barryodonovan.com
    # (8.12.11/8.12.11/Submit) id iBADHRP6011034; Fri, 10 Dec 2004 13:17:27 GMT
    if (/^localhost \(localhost \[\[UNIX: localhost\]\]\) by /) { return 0; }

    # Internal Amazon traffic
    # Received: from dc-mail-3102.iad3.amazon.com by mail-store-2001.amazon.com with ESMTP (peer crosscheck: dc-mail-3102.iad3.amazon.com)
    if (/^\S+\.amazon\.com by \S+\.amazon\.com with ESMTP \(peer crosscheck: /) { return 0; }

    # Received: from GWGC6-MTA by gc6.jefferson.co.us with Novell_GroupWise; Tue, 30 Nov 2004 10:09:15 -0700
    if (/^[^\.]+ by \S+ with Novell_GroupWise/) { return 0; }

    # Received: from no.name.available by [165.224.43.143] via smtpd (for [165.224.216.89]) with ESMTP; Fri, 28 Jan 2005 13:06:39 -0500
    # Received: from no.name.available by [165.224.216.88] via smtpd (for lists.sourceforge.net [66.35.250.206]) with ESMTP; Fri, 28 Jan 2005 15:42:30 -0500
    # These are from an internal host protected by a Raptor firewall, to hosts
    # outside the firewall.  We can only ignore the handover since we don't have
    # enough info in those headers; however, from googling, it appears that
    # all samples are cases where the handover is safely ignored.
    if (/^no\.name\.available by \S+ via smtpd \(for /) { return 0; }

    # from 156.56.111.196 by blazing.arsecandle.org (envelope-from <gentoo-announce-return-530-rod=arsecandle.org@lists.gentoo.org>, uid 502) with qmail-scanner-1.24 (clamdscan: 0.80/594. f-prot: 4.4.2/3.14.11. Clear:RC:0(156.56.111.196):. Processed in 0.288806 secs); 06 Feb 2005 21:11:38 -0000
    # these are safe to ignore.  the previous handover line has the full
    # details of the handover described here, it's just qmail-scanner
    # logging a little more.
    if (/^\S+ by \S+ \(.{0,100}\) with qmail-scanner/) {
      $envfrom =~ s/^\s*<*//gs; $envfrom =~ s/>*\s*$//gs;
      $envfrom =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
      $self->{qmail_scanner_env_from} = $envfrom; # hack!
      return 0;
    }

    # Received: from mmail by argon.connect.org.uk with local (connectmail/exim)
    # id 18tOsg-0008FX-00; Thu, 13 Mar 2003 09:20:06 +0000
    if (/^\S+ by \S+ with local/) { return 0; }

    # HANDOVERS WE KNOW WE CAN'T DEAL WITH: TCP transmission, but to MTAs that
    # just don't log enough info for us to use (ie. no IP address present).
    # Note: "return 0" is strongly recommended here, unless you're sure
    # the regexp won't match something in the field; otherwise ALL_TRUSTED may
    # fire even in the presence of an unparseable Received header.

    # Received: from CATHY.IJS.SI by CATHY.IJS.SI (PMDF V4.3-10 #8779) id <01KTSSR50NSW001MXN@CATHY.IJS.SI>; Fri, 21 Mar 2003 20:50:56 +0100
    # Received: from MATT_LINUX by hippo.star.co.uk via smtpd (for mail.webnote.net [193.120.211.219]) with SMTP; 3 Jul 2002 15:43:50 UT
    # Received: from cp-its-ieg01.mail.saic.com by cpmx.mail.saic.com for me@jmason.org; Tue, 23 Jul 2002 14:09:10 -0700
    if (/^\S+ by \S+ (?:with|via|for|\()/) { return 0; }

    # from senmail2.senate.gov with LMTP by senmail2 (3.0.2/sieved-3-0-build-942) for <example@vandinter.org>; Fri, 30 Jun 2006 10:58:41 -0400
    # from zimbramail.artsit.org.uk (unverified) by MAILSWEEP.birminghamartsit.org.uk (Clearswift SMTPRS 5.1.7) with ESMTP id <T78926b35f2c0a80003da8@MAILSWEEP.birminghamartsit.org.uk> for <discuss@lists.surbl.org>; Tue, 30 May 2006 15:56:15 +0100
    if (/^\S+ (?:(?:with|via|for) \S+|\(unverified\)) by\b/) { return 0; }

    # from DL1GSPMX02 (dl1gspmx02.gamestop.com) by email.ebgames.com (LSMTP for Windows NT v1.1b) with SMTP id <21.000575A0@email.ebgames.com>; Tue, 12 Sep 2006 21:06:43 -0500
    if (/\(LSMTP for/) { return 0; }
  
    # if at this point we still haven't figured out the HELO string, see if we
    # can't just guess
    if (!$helo && /^(\S+)[^-A-Za-z0-9\.]/) { $helo = $1; }
  }

# ---------------------------------------------------------------------------

  elsif (s/^FROM //) {
    # simta: http://rsug.itd.umich.edu/software/simta/
    # Note the ugly uppercase FROM/BY/ID
    # Received: FROM hackers.mr.itd.umich.edu (smtp.mail.umich.edu [141.211.14.81])
    #  BY madman.mr.itd.umich.edu ID 434B508E.174A6.13932 ; 11 Oct 2005 01:41:34 -0400
    # Received: FROM [192.168.1.24] (s233-64-90-216.try.wideopenwest.com [64.233.216.90])
    #  BY hackers.mr.itd.umich.edu ID 434B5051.8CDE5.15436 ; 11 Oct 2005 01:40:33 -0400
    if (/^(\S+) \((\S+) \[(${IP_ADDRESS})\]\) BY (\S+) ID (\S+)$/ ) {
      $mta_looked_up_dns = 1;
      $helo = $1; $rdns = $2; $ip = $3; $by = $4; $id = $5;
      goto enough;
    }
  }

# ---------------------------------------------------------------------------

  elsif (s/^\(from //) {
    # Norton AntiVirus Gateway
    # Received: (from localhost [24.180.47.240])
    #  by host.name (NAVGW 2.5.2.12) with SMTP id M2006060503484615455
    #  for <user@domain.co.uk>; Mon, 05 Jun 2006 03:48:47 +0100
    if (/^(\S*) \[(${IP_ADDRESS})\]\) by (\S+) \(NAVGW .*?\) with /) {
      $helo = $1; $ip = $2; $by = $3;
      goto enough;
    }

    # header produced by command line /usr/bin/sendmail -t -f username@example.com
    # Received: (from username@localhost) by home.example.com
    # (8.12.11/8.12.11/Submit) id iBADHRP6011034; Fri, 10 Dec 2004 13:17:27 GMT
    if (/^\S+\@localhost\) by \S+ /) { return 0; }

    # Received: (from vashugins@juno.com)  by m06.lax.untd.com (jqueuemail) id LRVB3JAJ; Fri, 02 Jun 2006 08:15:21 PDT
    if (/^[^\s\@]+\@[^)]+\) by \S+\(jqueuemail\) id [^\s;]+/) { return 0; }
  }

# ---------------------------------------------------------------------------

  # FALL-THROUGH: OK, at this point let's try some general patterns for things
  # we may not have already parsed out.
  if (!$ip && /\[(${IP_ADDRESS})\]/) { $ip = $1; }

# ---------------------------------------------------------------------------

  # We need to have a minimal amount of information to have a useful parse.
  # If we have the IP and the "by" name, move forward.  If we don't, we'll
  # drop into the unparseable area.
  if ($ip && $by) { goto enough; }

  # Ok, we can't handle this header, go ahead and return that.
  return;

# ---------------------------------------------------------------------------

enough:

  # OK, line parsed (at least partially); now deal with the contents

  # flag handovers we couldn't get an IP address from at all
  if ($ip eq '') {
    dbg("received-header: could not parse IP address from: $_");
  }

  # DISABLED: if we cut out localhost-to-localhost SMTP handovers,
  # we will give FPs on SPF checks -- since the SMTP "MAIL FROM" addr
  # will be recorded, but we won't have the relays handover recorded
  # for that SMTP transaction, so we wind up checking the wrong IP
  # for the addr.
  if (0) {
    if ($ip eq '127.0.0.1') {
      dbg("received-header: ignoring localhost handover");
      return 0;   # ignore localhost handovers
    }
  }

  if ($rdns =~ /^unknown$/i) {
    $rdns = '';		# some MTAs seem to do this
  }
  
  $ip =~ s/^ipv6://i;   # remove "IPv6:" prefix
  $ip =~ s/^\[//; $ip =~ s/\]\z//;

  # IPv6 Scoped Address (RFC 4007, RFC 6874, RFC 3986 "unreserved" charset)
  $ip =~ s/%[A-Z0-9._~-]*\z//si;  # scoped address? remove <zone_id>

  # remove "::ffff:" prefix from IPv4-mapped-in-IPv6 addresses,
  # so we can treat them simply as IPv4 addresses
  # (only handles 'alternative form', not 'preferred form' - to be improved)
  $ip =~ s/^0*:0*:(?:0*:)*ffff:(\d+\.\d+\.\d+\.\d+)$/$1/i;

  $envfrom =~ s/^\s*<*//gs; $envfrom =~ s/>*\s*$//gs;
  $by =~ s/\;$//;

  # ensure invalid chars are stripped.  Replace with '!' to flag their
  # presence, though.  NOTE: this means "[1.2.3.4]" IP addr HELO
  # strings, which are legit by RFC-2821, look like "!1.2.3.4!".
  # still useful though.
  $ip =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
  $rdns =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
  $helo =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
  $by =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
  $ident =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;
  $envfrom =~ s/[\s\000\#\[\]\(\)\<\>\|]/!/gs;

  my $relay = {
    ip => $ip,
    by => $by,
    helo => $helo,
    id => $id,
    ident => $ident,
    envfrom => $envfrom,
    lc_by => (lc $by),
    lc_helo => (lc $helo),
    auth => $auth
  };

  if ($rdns eq '') {
    if ($mta_looked_up_dns) {
      # we know the MTA always does lookups, so this means the host
      # really has no rDNS (rather than that the MTA didn't bother
      # looking it up for us).
      $relay->{no_reverse_dns} = 1;
      $rdns = '';
    } else {
      $relay->{rdns_not_in_headers} = 1;
    }
  }

  $relay->{rdns} = $rdns;
  $relay->{lc_rdns} = lc $rdns;

  $self->make_relay_as_string($relay);

  my $is_private = ($ip =~ /${IP_PRIVATE}/o);
  $relay->{ip_private} = $is_private;

  # add it to an internal array so Eval tests can use it
  return $relay;
}

sub make_relay_as_string {
  my ($self, $relay) = @_;

  # as-string rep. use spaces so things like Bayes can tokenize them easily.
  # NOTE: when tokenizing or matching, be sure to note that new
  # entries may be added to this string later.   However, the *order*
  # of entries must be preserved, so that regexps that assume that
  # e.g. "ip" comes before "helo" will still work.
  #
  my $asstr = "[ ip=$relay->{ip} rdns=$relay->{rdns} helo=$relay->{helo} by=$relay->{by} ident=$relay->{ident} envfrom=$relay->{envfrom} intl=0 id=$relay->{id} auth=$relay->{auth} msa=0 ]";
  dbg("received-header: parsed as $asstr");
  $relay->{as_string} = $asstr;
}

# restart the parse if we find a fetchmail marker or similar.
# spamcop does this, and it's a great idea ;)
sub found_pop_fetcher_sig {
  my ($self) = @_;
  if ($self->{allow_fetchmail_markers}) {
    dbg("received-header: found fetchmail marker, restarting parse");
    $self->{relays_trusted} = [ ];
    $self->{relays_internal} = [ ];
    $self->{relays_external} = [ ];
  } else {
    dbg("received-header: found fetchmail marker outside trusted area, ignored");
  }
}

# ---------------------------------------------------------------------------

1;
