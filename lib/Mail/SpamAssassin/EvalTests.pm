#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Dns;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::MailingList;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::SHA1 qw(sha1);
use Mail::SpamAssassin::TextCat;
use Time::Local;
use strict;
eval "use bytes";

use vars qw{
	$IP_ADDRESS
	$CCTLDS_WITH_LOTS_OF_OPEN_RELAYS
	$ROUND_THE_WORLD_RELAYERS
	$WORD_OBFUSCATION_CHARS 
};

use constant HAS_EMAIL_ISFREE => eval { require Email::IsFree; };

# sad but true. sort it out, sysadmins!
$CCTLDS_WITH_LOTS_OF_OPEN_RELAYS = qr{(?:kr|cn|cl|ar|hk|il|th|tw|sg|za|tr|ma|ua|in|pe|br)};
$ROUND_THE_WORLD_RELAYERS = qr{(?:net|com|ca)};

# Here's how that RE was determined... relay rape by country (as of my
# spam collection on Dec 12 2001):
#
#     10 in     10 ua     11 ma     11 tr     11 za     12 gr
#     13 pl     14 se     15 hu     17 sg     19 dk     19 pt
#     19 th     21 us     22 hk     24 il     26 ch     27 ar
#     27 es     29 cz     32 cl     32 mx     37 nl     38 fr
#     41 it     43 ru     59 au     62 uk     67 br     70 ca
#    104 tw    111 de    123 jp    130 cn    191 kr
#
# However, since some ccTLDs just have more hosts/domains (skewing those
# figures), I cut down this list using data from
# http://www.isc.org/ds/WWW-200107/. I used both hostcount and domain counts
# for figuring this. any ccTLD with > about 40000 domains is left out of this
# regexp.  Then I threw in some unscientific seasoning to taste. ;)

$IP_ADDRESS = qr/(?:\b|[^\d])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\b|[^\d])/;
$WORD_OBFUSCATION_CHARS = '*_.,/|-+=';

###########################################################################
# HEAD TESTS:
###########################################################################

sub check_for_from_mx {
  my ($self) = @_;

  my $from = $self->get ('Reply-To:addr');
  if (!defined $from || $from !~ /\@\S+/) {
    $from = $self->get ('From:addr');
  }
  return 0 unless ($from =~ /\@(\S+)/);
  $from = $1;

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();
  $self->load_resolver();

  if ($from eq 'compiling.spamassassin.taint.org') {
    # only used when compiling
    return 0;
  }

  if ($self->{conf}->{check_mx_attempts} < 1) {
    return 0;
  }

  # Try check_mx_attempts times to protect against temporary outages.
  # sleep between checks to give the DNS a chance to recover.
  for my $i (1..$self->{conf}->{check_mx_attempts}) {
    my @mx = Net::DNS::mx($self->{res}, $from);
    dbg ("DNS MX records found: " . scalar(@mx));
    return 0 if (scalar @mx > 0);

    my $query = $self->{res}->search($from);
    if ($query) {
      my $count = 0;
      foreach my $rr ($query->answer) {
	$count++ if ($rr->type eq "A");
      }
      dbg ("DNS A records found: $count");
      return 0 if ($count > 0);
    }
    if ($i < $self->{conf}->{check_mx_attempts}) {sleep $self->{conf}->{check_mx_delay}; };
  }

  return 1;
}

###########################################################################

# From and To have same address, but are not exactly the same and
# neither contains intermediate spaces.
sub check_for_from_to_same {
  my ($self) = @_;

  my $hdr_from = $self->get('From');
  my $hdr_to = $self->get('To');
  return 0 if (!length($hdr_from) || !length($hdr_to) ||
	       $hdr_from eq $hdr_to);

  my $addr_from = $self->get('From:addr');
  my $addr_to = $self->get('To:addr');
  # BUG: From:addr and To:addr sometimes contain whitespace
  $addr_from =~ s/\s+//g;
  $addr_to =~ s/\s+//g;
  return 0 if (!length($addr_from) || !length($addr_to) ||
	       $addr_from ne $addr_to);

  if ($hdr_from =~ /^\s*\S+\s*$/ && $hdr_to =~ /^\s*\S+\s*$/) {
    return 1;
  }
}

sub check_recipients {
  my ($self, $min, $max, $length, $count) = @_;

  my $test = "similar.tocc.$length.$count";
  if (!exists $self->{$test}) {
    $self->_check_recipients($length, $count);
  }
  return (($min eq 'undef' || $self->{$test} >= $min) &&
	  ($max eq 'undef' || $self->{$test} < $max));
}

sub _check_recipients {
  my ($self) = @_;

  my $to = $self->get('ToCc');	# get all recipients
  $to =~ s/\(.*?\)//g;		# strip out the (comments)
  my @address = ($to =~ m/([\w.=-]+\@\w+(?:[\w.-]+\.)+\w+)/g);

  # length of 1 is good, 2 or 3 may be needed
  for my $length ((1, 2, 3)) {
    # at least 5 addresses is good, 4 does not seem like enough
    for my $count ((4, 5, 6)) {
      $self->{"similar.tocc.$length.$count"} = 0;
      if (scalar (@address) >= $count) {
	my @user = map { m/\@(.{0,$length})/ } @address;
	my @host = map { substr($_,0,$length) } @address;
	my $hits = 0;
	my $combinations = 0;
	for (my $i = 0; $i <= $#address; $i++) {
	  for (my $j = $i+1; $j <= $#address; $j++) {
	    $hits++ if $user[$i] eq $user[$j];
	    $hits++ if $host[$i] eq $host[$j];
	    $combinations++;
	  }
	}
	$self->{"similar.tocc.$length.$count"} = $hits / $combinations;
      }
    }
  }
}

###########################################################################

# The MTA probably added the Message-ID if either of the following is true:
#
# (1) The Message-ID: comes before a Received: header.
#
# (2) The Message-ID is the first header after all Received headers and
#     the From address domain is not the same as the Message-ID domain and
#     the Message-ID domain matches the last Received "by" domain.
#
# These two tests could be combined into a single rule, but they are
# separated because the first test is more accurate than the second test.
# However, we only run the primary function once for better performance.

sub check_for_mta_message_id_first {
  my ($self) = @_;

  if (! exists $self->{mta_first}) {
    $self->_check_mta_message_id();
  }
  return $self->{mta_first};
}

sub check_for_mta_message_id_later {
  my ($self) = @_;

  if (! exists $self->{mta_later}) {
    $self->_check_mta_message_id();
  }
  return $self->{mta_later};
}

sub _check_mta_message_id {
  my ($self) = @_;

  $self->{mta_first} = 0;
  $self->{mta_later} = 0;

  my $all = $self->get ('ALL');
  my $later_mta;

  if ($all =~ /\nMessage-(?:ID|Id|id):.*\nReceived:/s) {
    # Message-ID is before a Received
    $later_mta = 1;
  }
  elsif ($all =~ /\nReceived:[^\n]*\n(?:[\t ][^\n]*\n)*Message-(?:ID|Id|id):/s) {
    # Message-ID is not before a Received but is directly after a Received
    $later_mta = 0;
  }
  else {
    # go fish
    return;
  }

  my $id = $self->get ('Message-Id');

  # Yahoo! and Wanadoo.fr do add their Message-Id on transport time:
  # Yahoo! MIDs can depend on the country: yahoo.com, yahoo.fr, yahoo.co.uk, etc.
  # Wanadoo MIDs end always in wanadoo.fr
  return if $id =~ /\@[a-z0-9.-]+\.(?:yahoo|wanadoo)(?:\.[a-z]{2,3}){1,2}>/;

  # no further checks in simple case
  if ($later_mta) {
    $self->{mta_later} = 1;
    return;
  }

  # further checks required
  my $from = $self->get ('From:addr');
  my $received = $self->get ('Received');
  my @relay;
  my $first;

  # BUG: From:addr sometimes contains whitespace
  $from =~ s/\s+//g;

  # strip down to the host name
  $id =~ s/.*\@//;
  $id =~ s/[>\s]+$//;
  $id = lc($id);
  $from =~ s/.*\@//;
  $from = lc($from);
  while ($received =~ s/[\t ]+by[\t ]+(\w+([\w.-]+\.)+\w+)//i) {
    push (@relay, $1);
  }
  $first = lc(pop(@relay));

  # need to have a dot (test for addr-spec validity should be in another test)
  return if ($id !~ /\./ || $from !~ /\./);

  # strip down to last two parts of hostname
  $id =~ s/.*\.(\S+\.\S+)$/$1/;
  $from =~ s/.*\.(\S+\.\S+)$/$1/;

  # if $from equals $id, then message is much less likely to be spam
  return if $from eq $id;

  # strip down the first relay now
  $first =~ s/.*\.(\S+\.\S+)$/$1/;

  # finally, the test
  if ($first eq $id) {
    $self->{mta_first} = 1;
    return;
  }
}

###########################################################################

# yet another test for faked Received: headers (FORGED_RCVD_TRAIL).

sub check_for_forged_received_trail {
  my ($self) = @_;

  my @received = grep(/\S/, split(/\n/, $self->get ('Received')));
  my @by;
  my @from;
  my @fromip;
  my $mismatch = 0;

  for (my $i = 0; $i < $#received; $i++) {
    if ($received[$i] =~ s/\bby[\t ]+(\w+(?:[\w.-]+\.)+\w+)//i) {
      $by[$i] = lc($1);
      $by[$i] =~ s/.*\.(\S+\.\S+)$/$1/;
    }
    if ($received[$i] =~ s/\bfrom[\t ]+(\w+(?:[\w.-]+\.)+\w+)//i) {
      $from[$i] = lc($1);
      $from[$i] =~ s/.*\.(\S+\.\S+)$/$1/;
    }
    if ($received[$i] =~ s/^ \((?:\S+ |)\[(${IP_ADDRESS})\]\)//i) {
      $fromip[$i] = $1;
    }

    if (defined ($from[$i]) && defined($fromip[$i])) {
      if ($from[$i] =~ /^localhost(?:\.localdomain|)$/) {
        if ($fromip[$i] eq '127.0.0.1') {
          # valid: bouncing around inside 1 machine, via the localhost interface.
          # freshmeat newsletter does this.
          $from[$i] = undef;
        }
      }
    }

    if ($i > 0 && defined($by[$i]) && defined($from[$i - 1]) &&
	($by[$i] ne $from[$i - 1]))
    {
      $mismatch++;
    }

    dbg ("forged_rcvd_trail: entry $i:"
        ." by=".(defined $by[$i] ? $by[$i] : "(undef)")
        ." from=".(defined $from[$i] ? $from[$i] : "(undef)")
        ." mismatches=$mismatch");
  }

  return ($mismatch > 1);
}

# FORGED_HOTMAIL_RCVD
sub _check_for_forged_hotmail_received_headers {
  my ($self) = @_;

  if (defined $self->{hotmail_addr_but_no_hotmail_received}) { return; }

  $self->{hotmail_addr_with_forged_hotmail_received} = 0;
  $self->{hotmail_addr_but_no_hotmail_received} = 0;

  my $rcvd = $self->get ('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  return if ($rcvd =~
        /from mail pickup service by hotmail\.com with Microsoft SMTPSVC;/);

  my $ip = $self->get ('X-Originating-Ip');
  if ($ip =~ /$IP_ADDRESS/) { $ip = 1; } else { $ip = 0; }

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # spammers do not ;)

  if ($self->gated_through_received_hdr_remover()) { return; }

  if ($rcvd =~ /from \S*hotmail.com \(\S+\.hotmail(?:\.msn|)\.com[ \)]/ && $ip)
                { return; }
  if ($rcvd =~ /from \S+ by \S+\.hotmail(?:\.msn|)\.com with HTTP\;/ && $ip)
                { return; }
  if ($rcvd =~ /from \[66\.218.\S+\] by \S+\.yahoo\.com/ && $ip)
                { return; }

  if ($rcvd =~ /(?:from |HELO |helo=)\S*hotmail\.com\b/) {
    # HELO'd as hotmail.com, despite not being hotmail
    $self->{hotmail_addr_with_forged_hotmail_received} = 1;
  } else {
    # check to see if From claimed to be @hotmail.com
    my $from = $self->get ('From:addr');
    if ($from !~ /hotmail.com/) { return; }
    $self->{hotmail_addr_but_no_hotmail_received} = 1;
  }
}

# FORGED_HOTMAIL_RCVD
sub check_for_forged_hotmail_received_headers {
  my ($self) = @_;
  $self->_check_for_forged_hotmail_received_headers();
  return $self->{hotmail_addr_with_forged_hotmail_received};
}

# FORGED_HOTMAIL_RCVD
sub check_for_no_hotmail_received_headers {
  my ($self) = @_;
  $self->_check_for_forged_hotmail_received_headers();
  return $self->{hotmail_addr_but_no_hotmail_received};
}

# MSN_GROUPS
sub check_for_msn_groups_headers {
  my ($self) = @_;

  return 0 unless ($self->get('To') =~ /<(\S+)\@groups\.msn\.com>/i);
  my $listname = $1;

  # from Theo Van Dinter, see
  # http://www.hughes-family.org/bugzilla/show_bug.cgi?id=591
  return 0 unless $self->get('Message-Id') =~ /^<$listname-\S+\@groups\.msn\.com>/;
  return 0 unless $self->get('X-Loop') =~ /^notifications\@groups\.msn\.com/;
  return 0 unless $self->get('Return-Path') =~ /<$listname-bounce\@groups\.msn\.com>/;

  $_ = $self->get ('Received');
  return 0 if !/from mail pickup service by groups\.msn\.com\b/;
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

}

###########################################################################

sub check_for_forged_eudoramail_received_headers {
  my ($self) = @_;

  my $from = $self->get ('From:addr');
  if ($from !~ /eudoramail.com/) { return 0; }

  my $rcvd = $self->get ('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  my $ip = $self->get ('X-Sender-Ip');
  if ($ip =~ /$IP_ADDRESS/) { $ip = 1; } else { $ip = 0; }

  # Eudoramail formats its received headers like this:
  # Received: from Unknown/Local ([?.?.?.?]) by shared1-mail.whowhere.com;
  #      Thu Nov 29 13:44:25 2001
  # Message-Id: <JGDHDEHPPJECDAAA@shared1-mail.whowhere.com>
  # Organization: QUALCOMM Eudora Web-Mail  (http://www.eudoramail.com:80)
  # X-Sender-Ip: 192.175.21.146
  # X-Mailer: MailCity Service

  if ($self->gated_through_received_hdr_remover()) { return 0; }

  if ($rcvd =~ /by \S*whowhere.com\;/ && $ip) { return 0; }
  
  return 1;
}

###########################################################################

sub check_for_forged_excite_received_headers {
  my ($self) = @_;

  my $from = $self->get ('From:addr');
  if ($from !~ /excite.com/) { return 0; }

  my $rcvd = $self->get ('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  # Excite formats its received headers like this:
  # Received: from bucky.excite.com ([198.3.99.218]) by vaxc.cc.monash.edu.au
  #    (PMDF V6.0-24 #38147) with ESMTP id
  #    <01K53WHA3OGCA5W9MM@vaxc.cc.monash.edu.au> for luv@luv.asn.au;
  #    Sat, 23 Jun 2001 13:36:20 +1000
  # Received: from hippie.excite.com ([199.172.148.180]) by bucky.excite.com
  #    (InterMail vM.4.01.02.39 201-229-119-122) with ESMTP id
  #    <20010623033612.NRCY6361.bucky.excite.com@hippie.excite.com> for
  #    <luv@luv.asn.au>; Fri, 22 Jun 2001 20:36:12 -0700
  # spammers do not ;)

  if ($self->gated_through_received_hdr_remover()) { return 0; }

  if ($rcvd =~ /from \S*excite.com (\S+) by \S*excite.com/) { return 0; }
  
  return 1;
}

###########################################################################

sub check_for_forged_yahoo_received_headers {
  my ($self) = @_;

  my $from = $self->get ('From:addr');
  if ($from !~ /yahoo\.com$/) { return 0; }

  my $rcvd = $self->get ('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  # not sure about this
  #if ($rcvd !~ /from \S*yahoo\.com/) { return 0; }

  if ($self->gated_through_received_hdr_remover()) { return 0; }

  if ($rcvd =~ /by web\S+\.mail\.yahoo\.com via HTTP/) { return 0; }
  if ($rcvd =~ /by smtp\.\S+\.yahoo\.com with SMTP/) { return 0; }
  if ($rcvd =~
      /from \[$IP_ADDRESS\] by \S+\.(?:groups|grp\.scd)\.yahoo\.com with NNFMP/) {
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
                && $from =~ /\@reply\.yahoo\.com$/) { return 0; }

  if ($rcvd =~ /by \w+\.\w+\.yahoo\.com \(\d+\.\d+\.\d+\/\d+\.\d+\.\d+\) id \w+/) {
      # possibly sent from "mail this story to a friend"
      return 0;
  }

  return 1;
}

sub check_for_forged_juno_received_headers {
  my ($self) = @_;

  my $from = $self->get('From:addr');
  if($from !~ /\bjuno.com/) { return 0; }

  if($self->gated_through_received_hdr_remover()) { return 0; }

  my $xmailer = $self->get('X-Mailer');
  my $xorig = $self->get('X-Originating-IP');
  my $rcvd = $self->get('Received');

  if (!$xorig) {  # New style Juno has no X-Originating-IP header, and other changes
    if($rcvd !~ /from.*\bjuno\.com.*[\[\(]$IP_ADDRESS[\]\)].*by/
        && $rcvd !~ / cookie\.juno\.com /) { return 1; }
    if($xmailer !~ /Juno /) { return 1; }
  } else {
    if($rcvd !~ /from.*\bmail\.com.*\[$IP_ADDRESS\].*by/) { return 1; }
    if($xorig !~ /$IP_ADDRESS/) { return 1; }
    if($xmailer !~ /\bmail\.com/) { return 1; }
  }

  return 0;   
}

#Received: from dragnet.sjc.ebay.com (dragnet.sjc.ebay.com [10.6.21.14])
#	by bashir.ebay.com (8.10.2/8.10.2) with SMTP id g29JpwB10940
#	for <rod@begbie.com>; Sat, 9 Mar 2002 11:51:58 -0800

sub check_for_from_domain_in_received_headers {
  my ($self, $domain, $desired) = @_;
  
  if (exists $self->{from_domain_in_received}) {
      if (exists $self->{from_domain_in_received}->{$domain}) {
	  if ($desired eq 'true') {
	      # See use of '0e0' below for why we force int() here:
	      return int($self->{from_domain_in_received}->{$domain});
	  }
	  else {
	      # And why we deliberately do NOT use integers here:
	      return !$self->{from_domain_in_received}->{$domain};
	  }
      }
  } else {
      $self->{from_domain_in_received} = {};
  }

  my $from = $self->get('From:addr');
  if ($from !~ /\b\Q$domain\E/i) {
      # '0e0' is Perl idiom for "true but zero":
      $self->{from_domain_in_received}->{$domain} = '0e0';
      return 0;
  }

  my $rcvd = $self->get('Received');

  if ($rcvd =~ /from.*\b\Q$domain\E.*[\[\(]$IP_ADDRESS[\]\)].*by.*\b\Q$domain\E/) {
      $self->{from_domain_in_received}->{$domain} = 1;
      return ($desired eq 'true');
  }

  $self->{from_domain_in_received}->{$domain} = 0;
  return ($desired ne 'true');   
}

# ezmlm has a very bad habit of removing Received: headers! bad ezmlm.
#
sub gated_through_received_hdr_remover {
  my ($self) = @_;

  my $txt = $self->get ("Mailing-List");
  if (defined $txt && $txt =~ /^contact \S+\@\S+\; run by ezmlm$/) {
    my $dlto = $self->get ("Delivered-To");
    my $rcvd = $self->get ("Received");

    # ensure we have other indicative headers too
    if ($dlto =~ /^mailing list \S+\@\S+/ &&
      	$rcvd =~ /qmail \d+ invoked by .{3,20}\); \d+ ... \d+/)
    {
      return 1;
    }
    # jm: this line *was* included:
    #   $rcvd =~ /qmail \d+ invoked from network\); \d+ ... \d+/ &&
    # but I've found FPs where it did not appear in the mail; it's
    # not required.
  }

  if ($self->get ("Received") !~ /\S/) {
    # we have no Received headers!  These tests cannot run in that case
    return 1;
  }

  # MSN groups removes Received lines. thanks MSN
  if ($self->get ("Received") =~ /from groups\.msn\.com \(\S+\.msn\.com /) {
    return 1;
  }

  return 0;
}

###########################################################################

sub check_for_bad_helo {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('X-Authentication-Warning');
  return 0 if (!defined $_);

  s/\s+/ /gs;   # ignore whitespace
  return 0 if (!/host (.*) claimed to be (.*)/i);

  my $relayer = $1;
  my $claimed = $2;
  my $relayip;
  my $claimip;

  if ($relayer =~ s/\[(\d\S+)\]//gs) { $relayip = $1; }
  if ($claimed =~ s/\[(\d\S+)\]//gs) { $claimip = $1; }
  $relayer =~ s/^\s+//; $relayer =~ s/\s+$//;
  $claimed =~ s/^\s+//; $claimed =~ s/\s+$//;

  # If reverse DNS differs from claimed on a lookback injection,
  # then it's probably because of a bad configuration
  return 0 if ($relayip eq "127.0.0.1");

  if ($relayer eq $claimed) { goto telling_truth; }
  if (defined $relayip && defined $claimip && $relayip eq $claimip)
                         { goto telling_truth; }

  dbg ("fake_helo: mail relayed by ".	
  	"$relayip (HELO '$claimed', rev DNS says '$relayer')");

  # next stuff is DNS testing; local mode just return 0
  return 0 unless $self->is_dns_available();
  $self->load_resolver();

  if ($relayer eq '') {         # there was no rev DNS at relay time

    # check to see if the host it claims to be, has an interface with
    # the IP address it came from.  This could still break with firewalls
    # though :(

    my $query = $self->{res}->search ($claimed);
    my $claimaddrs = '';
    if ($query) {
      foreach my $rr ($query->answer) {
        next unless $rr->type eq "A";
        $claimaddrs .= $rr->address." ";
      }
    }

    dbg ("fake_helo: DNS A records for '$claimed': $claimaddrs");
    if ($claimaddrs =~ /\Q$relayip\E/) {
      goto telling_truth;
    }

    chop $claimaddrs;
    #$self->test_log ("$claimed is $claimaddrs, not $relayip");
  }

  dbg ("fake_helo: relayer was lying in HELO");
  return 1;             # relayer was fibbing

telling_truth:
  dbg ("fake_helo: relayer was telling the truth in HELO");
  return 0;             # relayer was not fibbing
}

###########################################################################

# Bug 1133

# Some spammers will, through HELO, tell the server that their machine
# name *is* the relay; don't know why. An example:

# from mail1.mailwizards.com (m448-mp1.cvx1-b.col.dial.ntli.net
#        [213.107.233.192])
#        by mail1.mailwizards.com

# When this occurs for real, the from name and HELO name will be the
# same, unless the "helo" name is localhost, or the from and by hostsnames
# themselves are localhost
sub _check_received_helos {
  my ($self) = @_;

  my @received = grep(/\S/, split(/\n/, $self->get ('Received')));

  for (my $i = 0; $i < @received; $i++) {
    # Ignore where HELO is in reserved IP space; regexp matches
    # "[W.X.Y.Z]" immediatly followed by a ")", which should only
    # sho up at the end of the HELO part of a Received header
    if ($received[$i] =~ /\[([\d.]+)\]\)/) {
      my $ip = $1;

      next if $ip =~  /${IP_IN_RESERVED_RANGE}/o;;
    }

    # $helo_host regexp is "([\w.-]+\.[\w.-]+)" so that at least
    # one "." must be present, thus avoiding domainless hostnames
    # and "(HELO hostname)" situations.
    #
    # $from_host and $by_host regexps are "([\w.-]+)" to exclude
    # things like "[1.2.3.4]"; we don't deal with numeric-only
    # addresses
    my $from_host;
    my $helo_host;
    my $by_host;

    # TODO: Use Allen's Received-parser code.  Allen, these regexps
    # may help

    if ($received[$i] =~
		/from ([-\w.]+\.[-\w.]+) \(\S+ helo=([-\w.]+)\) by ([-\w.]+)/)
    {
      # Exim: from ns.egenix.com ([217.115.138.139] helo=www.egenix.com) by
      # mail.python.org with esmtp (Exim 4.05) id 1829w0-0007uf-00; Thu, 17 Oct
      # 2002 08:39:28 -0400
      $from_host = $1; $helo_host = $2; $by_host = $3;
    }
    elsif ($received[$i] =~
		/from ([-\w.]+\.[-\w.]+) \(HELO ([-\w.]+)\) \(\S+\) by ([-\w.]+)/)
    {
      # qmail: from 64-251-145-11-cablemodem-roll.fidnet.com (HELO gabriels)
      # (64.251.145.11) by three.fidnet.com with SMTP; 4 Dec 2002 16:01:35 -0000
      $from_host = $1; $helo_host = $2; $by_host = $3;
    }
    elsif ($received[$i] =~
		/from ([-\w.]+\.[-\w.]+) \(\[\S+\]\).* by ([-\w.]+)/)
    {
      # Received: from ralph.jamiemccarthy.com ([65.88.171.80]) by red.harvee.home
      # (8.11.6/8.11.6) with ESMTP id gB4KuQ130187 for <zzzzzzzz@tb.tf>;
      # Wed, 4 Dec 2002 15:56:27 -0500   [helo = from == good]
      $from_host = $helo_host = $1; $by_host = $2;
    }
    elsif ($received[$i] =~
		/from ([-\w.]+) \(([-\w.]+\.[-\w.]+).* by ([-\w.]+)/)
    {
      # I'm pretty sure from and HELO were the wrong way around here.  e.g.  in
      # "from lycos.co.uk (newwww-37.st1.spray.net [212.78.202.47]) by
      # outmail-3.st1.spray.net", the HELO is 'lycos.co.uk', NOT
      # 'newwww-37.st1.spray.net' -- the latter is from reverse DNS, and is
      # therefore trustworthy, whereas HELO is not.  (Nov 12 2002 jm) So
      # accordingly, I've changed the order of $from_host and $helo_host below.
      $helo_host = $1; $from_host = $2; $by_host = $3;
    }
    next unless defined($helo_host);

    # Check for a faked dotcom HELO, e.g.
    # Received: from mx02.hotmail.com (www.sucasita.com.mx [148.223.251.99])...
    # this can be a stronger spamsign than the normal case, since the
    # big dotcoms don't screw up their rDNS normally ;), so less FPs.
    # Since spammers like sending out their mails from the dotcoms (esp.
    # hotmail and AOL) this will catch those forgeries.
    #
    # allow stuff before the dot-com for both from-name and HELO-name,
    # so HELO="outgoing.aol.com" and from="mx34853495.mx.aol.com" works OK.
    #
    $self->{faked_dotcom_helo} = 0;
    if ($helo_host =~ /(?:\.|^)(lycos\.com|lycos\.co\.uk|hotmail\.com
		|localhost\.com|excite\.com|caramail\.com
		|cs\.com|aol\.com|msn\.com|yahoo\.com|drizzle\.com)$/ix)
    {
      my $dom = $1;
      if ($from_host !~ /^${IP_ADDRESS}$/ && $from_host !~ /(?:\.|^)${dom}$/i) {
	dbg ("Received: faked dotcom HELO: from=$from_host HELO=$helo_host");
	$self->{faked_dotcom_helo} = 1;
      }
    }
  }
} # _check_received_helos()

sub check_for_fake_dotcom_helo {
  my ($self) = @_;
  if (!exists $self->{faked_dotcom_helo}) { $self->_check_received_helos(@_); }
  return $self->{faked_dotcom_helo};
}

###########################################################################

sub check_subject_for_lotsa_8bit_chars {
  my ($self) = @_;
  local ($_);

  $_ = $self->get('Subject');

  # cut [ and ] because 8-bit posts to mailing lists may not get
  # hit otherwise. e.g.: Subject: [ILUG] X�uX .  Also cut
  # *, since mail that goes through spamassassin multiple times will
  # not be tagged on the second pass otherwise.
  s/[\[\]\* ]//g;

  return 1 if ($self->are_more_high_bits_set ($_));
  return 0;
}

sub are_more_high_bits_set {
  my ($self, $str) = @_;

  my @highbits = ($str =~ /[\200-\377]/g);
  my $numhis = $#highbits+1;
  my $numlos = length($str) - $numhis;

  ($numlos <= $numhis && $numhis > 3);
}

###########################################################################

sub check_for_missing_to_header {
  my ($self) = @_;

  my $hdr = $self->get ('To');
  $hdr ||= $self->get ('Apparently-To');
  return 1 if ($hdr eq '');

  return 0;
}

###########################################################################

# Check if the apparent sender (in the last received header) had
# no reverse lookup for it's IP
#
# Look for headers like:
#
#   Received: from mx1.eudoramail.com ([204.32.147.84])
sub check_for_sender_no_reverse {
  my ($self) = @_;

  my @received = grep(/\S/, split(/\n/, $self->get ('Received')));

  # Ignore received lines like "(qmail 12345 invoked by uid 789)"
  @received = grep(/\bfrom\b.*\bby\b/s, @received);

  # Sender recveived header is the last in the sequence
  my $sender_rcvd = $received[$#received];

  # Ignore if the from host is domainless (has no dot)
  return 0 unless (defined $sender_rcvd && $sender_rcvd =~
                   /^from (\S+\.\S+) \(\[([\d.]+)\]\)/);

  my $from = $1;
  my $ip   = $2;

  return 0 if ($ip =~ /${IP_IN_RESERVED_RANGE}/o);

  return 1;
} # check_for_sender_no_reverse()

###########################################################################

sub check_from_in_whitelist {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{conf}->{whitelist_from}, $_)) {
      return 1;
    }
    if ($self->_check_whitelist_rcvd ($self->{conf}->{whitelist_from_rcvd}, $_)) {
      return 1;
    }
  }
}

###########################################################################

sub _check_whitelist_rcvd {
  my ($self, $list, $addr) = @_;
  $addr = lc $addr;
  # study $addr; # study isn't worth it for strings this size.
  foreach my $white_addr (keys %{$list}) {
    my $regexp = $list->{$white_addr}{re};
    my $domain = $list->{$white_addr}{domain};
    # warn("checking $addr against $regexp + $domain\n");
    if ($addr =~ /$regexp/i) {
      # warn("Looking for $domain\n");
      my $rcvd = $self->get('Received');
      if ($rcvd =~ /from.*\b\Q$domain\E.*[\[\(][0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[\]\)].*\bby\b/) {
        # warn("Found it.\n");
        return 1;
      }
    }
  }

  return 0;
}

###########################################################################

sub _check_whitelist {
  my ($self, $list, $addr) = @_;
  $addr = lc $addr;
  if (defined ($list->{$addr})) { return 1; }
  study $addr;
  foreach my $regexp (values %{$list}) {
    if ($addr =~ /$regexp/i) {
      return 1;
    }
  }

  return 0;
}

sub all_from_addrs {
  my ($self) = @_;

  if (exists $self->{all_from_addrs}) { return @{$self->{all_from_addrs}}; }

  my @addrs;

  # Resent- headers take priority, if present. see bug 672
  # http://www.hughes-family.org/bugzilla/show_bug.cgi?id=672
  my $resent = $self->get ('Resent-From');
  if (defined $resent && $resent =~ /\S/) {
    @addrs = $self->{main}->find_all_addrs_in_line (
  	 $self->get ('Resent-From'));

  } else {
    @addrs = $self->{main}->find_all_addrs_in_line
  	($self->get ('From') .                  # std
  	 $self->get ('Envelope-Sender') .       # qmail: new-inject(1)
  	 $self->get ('Resent-Sender') .         # procmailrc manpage
  	 $self->get ('X-Envelope-From') .       # procmailrc manpage
  	 $self->get ('Return-Path') .           # Postfix, sendmail; rfc821
  	 $self->get ('Resent-From'));
    # http://www.cs.tut.fi/~jkorpela/headers.html is useful here
  }

  dbg ("all '*From' addrs: ".join (" ", @addrs));
  $self->{all_from_addrs} = \@addrs;
  return @addrs;
}

sub all_to_addrs {
  my ($self) = @_;

  if (exists $self->{all_to_addrs}) { return @{$self->{all_to_addrs}}; }

  my @addrs;

  # Resent- headers take priority, if present. see bug 672
  # http://www.hughes-family.org/bugzilla/show_bug.cgi?id=672
  my $resent = $self->get ('Resent-To') . $self->get ('Resent-Cc');
  if (defined $resent && $resent =~ /\S/) {
    @addrs = $self->{main}->find_all_addrs_in_line (
  	 $self->get ('Resent-To') .             # std, rfc822
  	 $self->get ('Resent-Cc'));             # std, rfc822

  } else {
    # OK, a fetchmail trick: try to find the recipient address from
    # the most recent 3 Received lines.  This is required for sendmail,
    # since it does not add a helpful header like exim, qmail
    # or Postfix do.
    #
    my $rcvd = $self->get ('Received');
    $rcvd =~ s/\n[ \t]+/ /gs;
    $rcvd =~ s/\n+/\n/gs;

    my @rcvdlines = split (/\n/, $rcvd, 4); pop @rcvdlines; # forget last one
    my @rcvdaddrs = ();
    foreach my $line (@rcvdlines) {
      if ($line =~ / for (\S+\@\S+);/) { push (@rcvdaddrs, $1); }
    }

    @addrs = $self->{main}->find_all_addrs_in_line (
	 join (" ", @rcvdaddrs)."\n" .
         $self->get ('To') .                    # std
  	 $self->get ('Apparently-To') .         # sendmail, from envelope
  	 $self->get ('Delivered-To') .          # Postfix, poss qmail
  	 $self->get ('Envelope-Recipients') .   # qmail: new-inject(1)
  	 $self->get ('Apparently-Resent-To') .  # procmailrc manpage
  	 $self->get ('X-Envelope-To') .         # procmailrc manpage
  	 $self->get ('Envelope-To') .           # exim
         $self->get ('Cc'));                    # std
  }

  dbg ("all '*To' addrs: ".join (" ", @addrs));
  $self->{all_to_addrs} = \@addrs;
  return @addrs;

# http://www.cs.tut.fi/~jkorpela/headers.html is useful here, also
# http://www.exim.org/pipermail/exim-users/Week-of-Mon-20001009/021672.html
}

###########################################################################

sub check_obfuscated_words {
  my ($self, $body) = @_;
  foreach my $line (@$body) {
      while ($line =~ /[\w$WORD_OBFUSCATION_CHARS]/) {
        # TODO, it seems ;)
      }
  }
}

###########################################################################

sub check_from_in_blacklist {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->all_from_addrs()) {
    if ($self->_check_whitelist ($self->{conf}->{blacklist_from}, $_)) {
      return 1;
    }
  }
}

###########################################################################
# added by DJ

sub check_to_in_whitelist {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{conf}->{whitelist_to}, $_)) {
      return 1;
    }
  }
}


###########################################################################
# added by DJ

sub check_to_in_more_spam {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{conf}->{more_spam_to}, $_)) {
      return 1;
    }
  }
}


###########################################################################
# added by DJ

sub check_to_in_all_spam {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->all_to_addrs()) {
    if ($self->_check_whitelist ($self->{conf}->{all_spam_to}, $_)) {
      return 1;
    }
  }
}

###########################################################################

sub check_lots_of_cc_lines {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('Cc');
  my @count = /\n/gs;
  if ($#count > 20) { return 1; }
  return 0;
}

###########################################################################

sub check_rbl {
  my ($self, $set, $rbl_domain, $needresult) = @_;
  local ($_);
  # How many IPs max you check in the received lines;
  my $checklast=$self->{conf}->{num_check_received} - 1;
  
  dbg ("checking RBL $rbl_domain, set $set", "rbl", -1);

  my $rcv = $self->get ('Received');
  my @fullips = ($rcv =~ /[\[\(]($IP_ADDRESS)[\]\)]/g);
  return 0 unless ($#fullips >= 0);

  # Let's go ahead and trim away all Reserved ips (KLC)
  my @ips = ();
  foreach my $ip (@fullips) {
    if (!($ip =~ /${IP_IN_RESERVED_RANGE}/o)) { push(@ips,$ip); }
  }

  # First check that DNS is available, if not do not perform this check
  return 0 if $self->{conf}->{skip_rbl_checks};
  return 0 unless $self->is_dns_available();
  $self->load_resolver();

  dbg("Got the following IPs: ".join(", ", @ips), "rbl", -3);
  if ($#ips > 1) {
    # If the set name is foo-lastN, check only the Received header that is
    # N hops from the final MTA (where 0 only checks the final Received
    # header).
    if ($set =~ /-last(\d+)$/) {
      @ips = ($ips[$1]);
    }
    # If the set name is foo-firstN, only check the address that is N from
    # the header generated by the first MTA.
    elsif ($set =~ /-first(\d+)$/) {
      @ips = ($ips[$#ips - $1]);
    }
    else {
      @ips = @ips[$#ips-$checklast .. $#ips]; # only check the originating IPs
    }
  }
  dbg("But only inspecting the following IPs: ".join(", ", @ips), "rbl", -3);

  if (!defined $self->{$set}->{rbl_IN_As_found}) {
    $self->{$set}->{rbl_IN_As_found} = ' ';
    $self->{$set}->{rbl_matches_found} = ' ';
  }

  my $already_matched_in_other_zones = ' '.$self->{$set}->{rbl_matches_found}.' ';
  my $found = 0;

  # First check that DNS is available. If not, do not perform this check.
  # Stop after the first positive.
  eval {
    my $i=0;
    my ($b1,$b2,$b3,$b4);
    my $dialupreturn;
    foreach my $ip (@ips) {
      $i++;
      # Some of the matches in other zones, like a DUL match on a first hop 
      # may be negated by another rule, so preventing a match in two zones
      # is better done with a Z_FUDGE_foo rule that uses check_both_rbl_results
      # and sets a negative score to compensate 
      # It's also useful to be able to flag mail that went through an IP that
      # is on two different blacklists  -- Marc
      #next if ($already_matched_in_other_zones =~ / ${ip} /);
      if ($already_matched_in_other_zones =~ / ${ip} /) {
	dbg("Skipping $ip, already matched in other zones for $set", "rbl", -1);
	next;
      }
      next unless ($ip =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
     ($b1, $b2, $b3, $b4) = ($1, $2, $3, $4);
      
      # By default, we accept any return on an RBL
      undef $dialupreturn;
      
      # foo-firsthop are special rule names that only match on the
      # first Received line (used to give a negative score to counter the
      # normal dialup rule and not penalize people who relayed through their
      # ISP) -- Marc
      # By default this rule won't get run unless it's the first hop IP
      if ($set =~ /-firsthop$/) {
	if ($#ips>0 and $i == $#ips + 1) {
	  dbg("Set dialupreturn on $ip for first hop", "rbl", -2);
	  $dialupreturn=$self->{conf}->{dialup_codes};
	  die "$self->{conf}->{dialup_codes} undef" if (!defined $dialupreturn);
	} else {
	  dbg("Not running firsthop rule against middle hop or direct dialup IP connection (ip $ip)", "rbl", -2);
	  next;
	}
      }
      
      $found = $self->do_rbl_lookup ($set, "$b4.$b3.$b2.$b1.".$rbl_domain, $ip, $found, $dialupreturn, $needresult);
      dbg("Got $found on $ip (item $i)", "rbl", -3);
    }
  };

  dbg("Check_rbl returning $found", "rbl", -3);
  $found;
}

###########################################################################

sub check_rbl_results_for {
  my ($self, $set, $addr) = @_;

  dbg ("checking RBL results in set $set for $addr", "rbl", -1);
  return 0 if $self->{conf}->{skip_rbl_checks};
  return 0 unless $self->is_dns_available();
  return 0 unless defined ($self->{$set});
  return 0 unless defined ($self->{$set}->{rbl_IN_As_found});

  my $inas = ' '.$self->{$set}->{rbl_IN_As_found}.' ';
  if ($inas =~ / ${addr} /) { return 1; }

  return 0;
}

###########################################################################

sub check_two_rbl_results {
  my ($self, $set1, $addr1, $set2, $addr2) = @_;

  return 0 if $self->{conf}->{skip_rbl_checks};
  return 0 unless $self->is_dns_available();
  return 0 unless defined ($self->{$set1});
  return 0 unless defined ($self->{$set2});
  return 0 unless defined ($self->{$set1}->{rbl_IN_As_found});
  return 0 unless defined ($self->{$set2}->{rbl_IN_As_found});

  my $inas1 = ' '.$self->{$set1}->{rbl_IN_As_found}.' ';
  my $inas2 = ' '.$self->{$set2}->{rbl_IN_As_found}.' ';
  if ($inas1 =~ / ${addr1} / and $inas2 =~ / ${addr2} /) { return 1; }

  return 0;
}


###########################################################################

sub check_for_unique_subject_id {
  my ($self) = @_;
  local ($_);
  $_ = lc $self->get ('Subject');
  study;

  my $id = 0;
  if (/[-_\.\s]{7,}([-a-z0-9]{4,})$/
	|| /\s{10,}(?:\S\s)?(\S+)$/
	|| /\s{3,}[-:\#\(\[]+([-a-z0-9]{4,})[\]\)]+$/
	|| /\s{3,}[:\#\(\[]*([a-f0-9]{4,})[\]\)]*$/
	|| /\s{3,}[-:\#]([a-z0-9]{5,})$/
	|| /[\s._]{3,}([^0\s._]\d{3,})$/
	|| /[\s._]{3,}\[(\S+)\]$/

        # (7217vPhZ0-478TLdy5829qicU9-0@26) and similar
        || /\(([-\w]{7,}\@\d+)\)$/

        # Seven or more digits at the end of a subject is almost certainly a id
        || /\b(\d{7,})\s*$/

        # stuff at end of line after "!" or "?" is usually an id
        || /[!\?]\s*(\d{4,}|\w+(-\w+)+)\s*$/

        # 9095IPZK7-095wsvp8715rJgY8-286-28 and similar
        || /\b(\w{7,}-\w{7,}(-\w+)*)\s*$/

        # #30D7 and similar
        || /\s#\s*([a-f0-9]{4,})\s*$/
     )
  {
    $id = $1;
    # exempt online purchases
    if ($id =~ /\d{5,}/
	&& /(?:item|invoice|order|number|confirmation).{1,6}\Q$id\E\s*$/)
    {
      $id = 0;
    }

    # for the "foo-bar-baz" case, otherwise it won't
    # be found in the dict:
    $id =~ s/-//;
  }

  return ($id && !$self->word_is_in_dictionary($id));
}

# word_is_in_dictionary()
#
# See if the word looks like an English word, by checking if each triplet
# of letters it contains is one that can be found in the English language.
# Does not include triplets only found in proper names, or in the Latin
# and Greek terms that might be found in a larger dictionary

my %triplets = ();
my $triplets_loaded = 0;

sub word_is_in_dictionary {
  my ($self, $word) = @_;
  local ($_);
  local $/ = "\n";		# Ensure $/ is set appropriately

  # $word =~ tr/A-Z/a-z/;	# already done by this stage
  $word =~ s/^\s+//;
  $word =~ s/\s+$//;

  # If it contains a digit, dash, etc, it's not a valid word.
  # Don't reject words like "can't" and "I'll"
  return 0 if ($word =~ /[^a-z\']/);

  # handle a few common "blah blah blah (comment)" styles
  return 1 if ($word eq "ot");	# off-topic
  return 1 if ($word =~ /(?:linux|nix|bsd)/); # not in most dicts
  return 1 if ($word =~ /(?:whew|phew|attn|tha?nx)/);  # not in most dicts

  my $word_len = length($word);

  # Unique IDs probably aren't going to be only one or two letters long
  return 1 if ($word_len < 3);

  if (!$triplets_loaded) {
    # take a copy to avoid modifying the real one
    my @default_triplets_path = @Mail::SpamAssassin::default_rules_path;
    @default_triplets_path = map { s,$,/triplets.txt,; $_; }
				    @default_triplets_path;
    my $filename = $self->{main}->first_existing_path (@default_triplets_path);

    unless ( defined $filename ) {
      dbg("failed to locate the triplets.txt file");
      return 1;
    }

    if (!open (TRIPLETS, "<$filename")) {
      dbg ("failed to open '$filename', cannot check dictionary");
      return 1;
    }

    while(<TRIPLETS>) {
      chomp;
      $triplets{$_} = 1;
    }
    close(TRIPLETS);

    $triplets_loaded = 1;
  } # if (!$triplets_loaded)


  my $i;

  for ($i = 0; $i < ($word_len - 2); $i++) {
    my $triplet = substr($word, $i, 3);
    if (!$triplets{$triplet}) {
      dbg ("Unique ID: Letter triplet '$triplet' from word '$word' not valid");
      return 0;
    }
  } # for ($i = 0; $i < ($word_len - 2); $i++)

  # All letter triplets in word were found to be valid
  return 1;
}

sub get_address_commonality_ratio {
  my ($self, $addr1, $addr2) = @_;


  # Ignore "@" and ".".  "@" will always be the same in both, and the
  # number of "." will almost always be the same
  $addr1 =~ s/[\@\.]//g;
  $addr2 =~ s/[\@\.]//g;

  my %counts1 = ();
  my %counts2 = ();

  foreach ( split(//, lc $addr1) ) {
    $counts1{$_}++;
  }
  foreach ( split(//, lc $addr2) ) {
    $counts2{$_}++;
  }

  my $different = 0;
  my $same      = 0;
  my $unique    = 0;
  my $char;
  my @chars     = keys %counts1;

  # Extract unique characters, and make the two hashes have the same
  # set of keys
  foreach $char (@chars) {
    if (!defined ($counts2{$char})) {
      $unique += $counts1{$char};
      delete ($counts1{$char});
    }
  }

  @chars = keys %counts2;

  foreach $char (@chars) {
    if (!defined ($counts1{$char})) {
      $unique += $counts2{$char};
      delete ($counts2{$char});
    }
  }

  # Hashes now have identical sets of keys; count the differences
  # between the values.
  @chars = keys %counts1;

  foreach $char (@chars) {
    my $count1 = $counts1{$char} || 0.0;
    my $count2 = $counts2{$char} || 0.0;

    if ($count1 == $count2) {
      $same += $count1;
    }
    else {
      $different += abs($count1 - $count2);
    }
  }

  $different += $unique / 2.0;

  $same ||= 1.0;
  my $ratio = $different / $same;

  #print STDERR "addrcommonality $addr1/$addr2($different<$unique>/$same)"
  # . " = $ratio\n";

  return $ratio;
}

###########################################################################

sub check_for_forged_gw05_received_headers {
  my ($self) = @_;
  local ($_);

  my $rcv = $self->get ('Received');

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

sub check_for_faraway_charset {
  my ($self, $body) = @_;

  my $type = $self->get ('Content-Type');

  my @locales = $self->get_my_locales();

  return 0 if grep { $_ eq "all" } @locales;

  $type = get_charset_from_ct_line ($type);

  if (defined $type &&
    !Mail::SpamAssassin::Locales::is_charset_ok_for_locales
		    ($type, @locales))
  {
    # sanity check.  Some charsets (e.g. koi8-r) include the ASCII
    # 7-bit charset as well, so make sure we actually have a high
    # number of 8-bit chars in the body text first.

    $body = join ("\n", @$body);

    if ($self->are_more_high_bits_set ($body)) {
      return 1;
    }
  }

  0;
}

sub check_for_faraway_charset_in_headers {
  my ($self) = @_;
  my $hdr;

  my @locales = $self->get_my_locales();

  return 0 if grep { $_ eq "all" } @locales;

  for my $h (qw(From Subject)) {
    my @hdrs = $self->get ("$h:raw");
    if ($#hdrs >= 0) {
      $hdr = join (" ", @hdrs);
    } else {
      $hdr = '';
    }
    while ($hdr =~ /=\?(.+?)\?.\?.*?\?=/g) {
      Mail::SpamAssassin::Locales::is_charset_ok_for_locales($1, @locales)
	  or return 1;
    }
  }
  0;
}

sub get_charset_from_ct_line {
  my $type = shift;
  if ($type =~ /charset="([^"]+)"/i) { return $1; }
  if ($type =~ /charset='([^']+)'/i) { return $1; }
  if ($type =~ /charset=(\S+)/i) { return $1; }
  return undef;
}

sub get_my_locales {
  my ($self) = @_;

  my @locales = split (' ', $self->{conf}->{ok_locales});
  my $lang = $ENV{'LC_ALL'};
  $lang ||= $ENV{'LANGUAGE'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  push (@locales, $lang) if defined($lang);
  return @locales;
}

###########################################################################

sub _check_for_round_the_world_received {
  my ($self) = @_;
  my ($relayer, $relayerip, $relay);

  $self->{round_the_world_revdns} = 0;
  $self->{round_the_world_helo} = 0;
  my $rcvd = $self->get ('Received');

  # trad sendmail/postfix fmt:
  # Received: from hitower.parkgroup.ru (unknown [212.107.207.26]) by
  #     mail.netnoteinc.com (Postfix) with ESMTP id B8CAC11410E for
  #     <me@netnoteinc.com>; Fri, 30 Nov 2001 02:42:05 +0000 (Eire)
  # Received: from fmx1.freemail.hu ([212.46.197.200]) by hitower.parkgroup.ru
  #     (Lotus Domino Release 5.0.8) with ESMTP id 2001113008574773:260 ;
  #     Fri, 30 Nov 2001 08:57:47 +1000
  if ($rcvd =~ /
  	\nfrom\b.{0,20}\s(\S+\.${CCTLDS_WITH_LOTS_OF_OPEN_RELAYS})\s\(.{0,200}
  	\nfrom\b.{0,20}\s([-_A-Za-z0-9.]+)\s.{0,30}\[($IP_ADDRESS)\]
  /osix) { $relay = $1; $relayer = $2; $relayerip = $3; goto gotone; }

  return 0;

gotone:
  my $revdns = $self->lookup_ptr ($relayerip);
  if (!defined $revdns) { $revdns = '(unknown)'; }

  dbg ("round-the-world: mail relayed through $relay by ".	
  	"$relayerip (HELO $relayer, rev DNS says $revdns)");

  if ($revdns =~ /\.${ROUND_THE_WORLD_RELAYERS}$/oi) {
    dbg ("round-the-world: yep, I think so (from rev dns)");
    $self->{round_the_world_revdns} = 1;
    return;
  }

  if ($relayer =~ /\.${ROUND_THE_WORLD_RELAYERS}$/oi) {
    dbg ("round-the-world: yep, I think so (from HELO)");
    $self->{round_the_world_helo} = 1;
    return;
  }

  dbg ("round-the-world: probably not");
  return;
}

sub check_for_round_the_world_received_helo {
  my ($self) = @_;
  if (!defined $self->{round_the_world_helo}) {
    $self->_check_for_round_the_world_received();
  }
  if ($self->{round_the_world_helo}) { return 1; }
  return 0;
}

sub check_for_round_the_world_received_revdns {
  my ($self) = @_;
  if (!defined $self->{round_the_world_revdns}) {
    $self->_check_for_round_the_world_received();
  }
  if ($self->{round_the_world_revdns}) { return 1; }
  return 0;
}

###########################################################################

sub check_for_shifted_date {
  my ($self, $min, $max) = @_;

  if (!exists $self->{date_diff}) {
    $self->_check_date_diff();
  }
  return (($min eq 'undef' || $self->{date_diff} >= (3600 * $min)) &&
	  ($max eq 'undef' || $self->{date_diff} < (3600 * $max)));
}

sub received_within_months {
  # filters out some false positives in old corpus mail - Allen
  my($self,$min,$max) = @_;

  unless (exists($self->{date_received})) {
    $self->_check_date_received();
  }
  my $diff = time() - $self->{date_received};

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
  my $self = $_[0];

  # a Resent-Date: header takes precedence over any Date: header
  my $date = $self->get('Resent-Date');
  my $time;
  if (defined($date) && length($date)) {
    chomp($date);
    $time = $self->_parse_rfc822_date($date);
  }
  unless (defined($time)) {
    $date = $self->get('Date');
    if (defined($date) && length($date)) {
      chomp($date);
      $time = $self->_parse_rfc822_date($date);
    }
  }
  if (defined($time)) {
    $self->{date_header_time} = $time;
  } else {
    $self->{date_header_time} = undef;
  }
}

sub _get_received_header_times {
  my $self = $_[0];

  $self->{received_header_times} = [ () ];
  $self->{received_fetchmail_time} = undef;

  my(@received);
  my $received = $self->get('Received');
  if (defined($received) && length($received)) {
    @received = grep {$_ =~ m/\S/} (split(/\n/,$received));
  }
  # if we have no Received: headers, chances are we're archived mail
  # with a limited set of headers
  unless (scalar(@received)) {
    return;
  }

  # handle fetchmail headers
  my(@local);
  if (($received[0] =~
      m/\bfrom (?:localhost\s|(?:\S+ ){1,2}\S*\b127\.0\.0\.1\b)/) ||
      ($received[0] =~ m/qmail \d+ invoked by uid \d+/)) {
    push @local, (shift @received);
  }
  if (scalar(@received) &&
      ($received[0] =~ m/\bby localhost with \w+ \(fetchmail-[\d.]+/)) {
    push @local, (shift @received);
  } elsif (scalar(@local)) {
    unshift @received, (shift @local);
  }

  my $rcvd;

  if (scalar(@local)) {
    my(@fetchmail_times);
    foreach $rcvd (@local) {
      if ($rcvd =~ m/(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+)/) {
	my $date = $1;
	dbg ("trying Received fetchmail header date for real time: $date",
	     "datediff", -2);
	my $time = $self->_parse_rfc822_date($date);
	if (defined($time) && (time() >= $time)) {
	  dbg ("time_t from date=$time, rcvd=$date", "datediff", -2);
	  push @fetchmail_times, $time;
	}
      }
    }
    if (scalar(@fetchmail_times) > 1) {
      $self->{received_fetchmail_time} =
       (sort {$b <=> $a} (@fetchmail_times))[0];
    } elsif (scalar(@fetchmail_times)) {
      $self->{received_fetchmail_time} = $fetchmail_times[0];
    }
  }

  my(@header_times);
  foreach $rcvd (@received) {
    if ($rcvd =~ m/(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+)/) {
      my $date = $1;
      dbg ("trying Received header date for real time: $date", "datediff", -2);
      my $time = $self->_parse_rfc822_date($date);
      if (defined($time)) {
	dbg ("time_t from date=$time, rcvd=$date", "datediff", -2);
	push @header_times, $time;
      }
    }
  }

  if (scalar(@header_times)) {
    $self->{received_header_times} = [ @header_times ];
  } else {
    dbg ("no dates found in Received headers", "datediff", -1);
  }
}

sub _check_date_received {
  my $self = $_[0];

  my(@dates_poss);

  $self->{date_received} = 0;

  unless (exists($self->{date_header_time})) {
    $self->_get_date_header_time();
  }

  if (defined($self->{date_header_time})) {
    push @dates_poss, $self->{date_header_time};
  }

  unless (exists($self->{received_header_times})) {
    $self->_get_received_header_times();
  }
  my(@received_header_times) = @{ $self->{received_header_times} };
  if (scalar(@received_header_times)) {
    push @dates_poss, $received_header_times[0];
  }
  if (defined($self->{received_fetchmail_time})) {
    push @dates_poss, $self->{received_fetchmail_time};
  }

  if (defined($self->{date_header_time}) && scalar(@received_header_times)) {
    unless (exists($self->{date_diff})) {
      $self->_check_date_diff();
    }
    push @dates_poss, $self->{date_header_time} - $self->{date_diff};
  }

  if (scalar(@dates_poss)) {	# use median
    $self->{date_received} = (sort {$b <=> $a}
			      (@dates_poss))[int($#dates_poss/2)];
    dbg("Date chosen from message: " .
	scalar(localtime($self->{date_received})), "datediff", -2);
  } else {
    dbg("no dates found in message", "datediff", -1);
  }
}

sub _check_date_diff {
  my $self = $_[0];

  $self->{date_diff} = 0;

  unless (exists($self->{date_header_time})) {
    $self->_get_date_header_time();
  }

  unless (defined($self->{date_header_time})) {
    return;			# already have tests for this
  }

  unless (exists($self->{received_header_times})) {
    $self->_get_received_header_times();
  }
  my(@header_times) = @{ $self->{received_header_times} };

  unless (scalar(@header_times)) {
    return;			# archived mail?
  }

  my(@diffs) = map {$self->{date_header_time} - $_} (@header_times);

  # if the last Received: header has no difference, then we choose to
  # exclude it
  if ($#diffs > 0 && $diffs[$#diffs] == 0) {
    pop(@diffs);
  }

  # use the date with the smallest absolute difference
  # (experimentally, this results in the fewest false positives)
  @diffs = sort { abs($a) <=> abs($b) } @diffs;
  $self->{date_diff} = $diffs[0];
}

# timezone mappings: in case of conflicts, use RFC 2822, then most
# common and least conflicting mapping
my %TZ = (
	# standard
	'UT'   => '+0000',
	'UTC'  => '+0000',
	# US and Canada
	'AST'  => '-0400',
	'ADT'  => '-0300',
	'EST'  => '-0500',
	'EDT'  => '-0400',
	'CST'  => '-0600',
	'CDT'  => '-0500',
	'MST'  => '-0700',
	'MDT'  => '-0600',
	'PST'  => '-0800',
	'PDT'  => '-0700',
	'HST'  => '-1000',
	'AKST' => '-0900',
	'AKDT' => '-0800',
	# European
	'GMT'  => '+0000',
	'BST'  => '+0100',
	'IST'  => '+0100',
	'WET'  => '+0000',
	'WEST' => '+0100',
	'CET'  => '+0100',
	'CEST' => '+0200',
	'EET'  => '+0200',
	'EEST' => '+0300',
	'MSK'  => '+0300',
	'MSD'  => '+0400',
	# Australian
	'AEST' => '+1000',
	'AEDT' => '+1100',
	'ACST' => '+0930',
	'ACDT' => '+1030',
	'AWST' => '+0800',
	);

sub _parse_rfc822_date {
  my ($self, $date) = @_;
  local ($_);
  my ($yyyy, $mmm, $dd, $hh, $mm, $ss, $mon, $tzoff);

  # make it a bit easier to match
  $_ = " $date "; s/, */ /gs; s/\s+/ /gs;

  # now match it in parts.  Date part first:
  if (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) / /i) {
    $dd = $1; $mon = $2; $yyyy = $3;
  } elsif (s/ (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(\d+) \d+:\d+:\d+ (\d{4}) / /i) {
    $dd = $2; $mon = $1; $yyyy = $3;
  } elsif (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{2,3}) / /i) {
    $dd = $1; $mon = $2; $yyyy = $3;
  } else {
    dbg ("time cannot be parsed: $date");
    return undef;
  }

  # handle two and three digit dates as specified by RFC 2822
  if (defined $yyyy) {
    if (length($yyyy) == 2 && $yyyy < 50) {
      $yyyy += 2000;
    }
    elsif (length($yyyy) != 4) {
      # three digit years and two digit years with values between 50 and 99
      $yyyy += 1900;
    }
  }

  # hh:mm:ss
  if (s/ (\d?\d):(\d\d)(:(\d\d))? / /) {
    $hh = $1; $mm = $2; $ss = $4 || 0;
  }

  # numeric timezones
  if (s/ ([-+]\d{4}) / /) {
    $tzoff = $1;
  }
  # UT, GMT, and North American timezones
  elsif (s/\b([A-Z]{2,4})\b/ / && exists $TZ{$1}) {
    $tzoff = $TZ{$1};
  }
  # all other timezones are considered equivalent to "-0000"
  $tzoff ||= '-0000';

  if (!defined $mmm && defined $mon) {
    my @months = qw(jan feb mar apr may jun jul aug sep oct nov dec);
    $mon = lc($mon);
    my $i; for ($i = 0; $i < 12; $i++) {
      if ($mon eq $months[$i]) { $mmm = $i+1; last; }
    }
  }

  $hh ||= 0; $mm ||= 0; $ss ||= 0; $dd ||= 0; $mmm ||= 0; $yyyy ||= 0;

  my $time;
  eval {		# could croak
    $time = timegm ($ss, $mm, $hh, $dd, $mmm-1, $yyyy);
  };

  if ($@) {
    dbg ("time cannot be parsed: $date, $yyyy-$mmm-$dd $hh:$mm:$ss");
    return undef;
  }

  if ($tzoff =~ /([-+])(\d\d)(\d\d)$/)	# convert to seconds difference
  {
    $tzoff = (($2 * 60) + $3) * 60;
    if ($1 eq '-') {
      $time += $tzoff;
    } else {
      $time -= $tzoff;
    }
  }

  return $time;
}

###########################################################################

sub subject_is_all_caps {
   my ($self) = @_;
   my $subject = $self->get('Subject');

   $subject =~ s/^\s+//;
   $subject =~ s/\s+$//;
   return 0 if $subject !~ /\s/;	# don't match one word subjects
   return 0 if (length $subject < 10);  # don't match short subjects
   $subject =~ s/[^a-zA-Z]//g;		# only look at letters
   return length($subject) && ($subject eq uc($subject));
}

###########################################################################

sub message_from_bugzilla {
  my ($self) = @_;

  my $all    = $self->get('ALL');
  
  # Let's look for a Bugzilla Subject...
  if ($all   =~ /^Subject: [^\n]{0,10}\[Bug \d+\] /m && (
        # ... in combination with either a Bugzilla message header...
        $all =~ /^X-Bugzilla-[A-Z][a-z]+: /m ||
        # ... or sender.
        $all =~ /^From: bugzilla/mi
     )) {
    return 1;
  }

  return 0;
}

sub message_from_debian_bts {
  my ($self)  = @_;

  my  $all    = $self->get('ALL');

  # This is the main case; A X-<Project>-PR-Message header exists and the
  # Subject looks "buggy". Watch out: The DBTS is used not only by Debian
  # but by other <Project>s, eg. KDE, too.
  if ($all    =~ /^X-[A-Za-z0-9]+-PR-Message: [a-z-]+ \d+$/m &&
      $all    =~ /^Subject: Bug#\d+: /m) {
    return 1;
  }
  # Sometimes the DBTS sends out messages which don't include the X- header.
  # In this case we look if the message is From a DBTS account and Subject
  # and Message-Id look good.
  elsif ($all =~ /^From: owner\@/mi &&
         $all =~ /^Subject: Processed(?: \([^)]+\))?: /m &&
         $all =~ /^Message-ID: <handler\./m) {
    return 1;
  }

  return 0;
}

sub message_is_habeas_swe {
  my ($self) = @_;

  my $all = $self->get('ALL');
  if ($all =~ /\n(X-Habeas-SWE-1:.{0,512}X-Habeas-SWE-9:[^\n]{0,64}\n)/si) {
    my $text = $1;
    $text =~ tr/A-Z/a-z/;
    $text =~ tr/ / /s;
    $text =~ s/\/?>/\/>/;
    return sha1($text) eq "42ab3d716380503f66c4d44017c7f37b04458a9a";
  }
  return 0;
}

###########################################################################
# BODY TESTS:
###########################################################################

sub check_for_uppercase {
  my ($self, $body, $min, $max) = @_;
  local ($_);

  if (exists $self->{uppercase}) {
    return ($self->{uppercase} > $min && $self->{uppercase} <= $max);
  }

  # Dec 20 2002 jm: trade off some speed for low memory footprint, by
  # iterating over the array computing sums, instead of joining the
  # array into a giant string and working from that.

  my $len = 0;
  my $lower = 0;
  my $upper = 0;
  foreach (@{$body}) {
    # examine lines in the body that have an intermediate space
    next unless /\S\s+\S/;
    # strip out lingering base64 (currently possible for forwarded messages)
    next if /^(?:[A-Za-z0-9+\/=]{60,76} ){2}/;

    my $line = $_;	# copy so we don't muck up the original
    # remove shift-JIS charset codes
    $line =~ s/\x1b\$B.*\x1b\(B//gs;

    $len += length($line);

    # count numerals as lower case, otherwise 'date|mail' is spam
    $lower += ($line =~ tr/a-z0-9//d);
    $upper += ($line =~ tr/A-Z//);
  }

  # report only on mails above a minimum size; otherwise one
  # or two acronyms can throw it off
  if ($len < 200) {
    $self->{uppercase} = 0;
    return 0;
  }
  if (($upper + $lower) == 0) {
    $self->{uppercase} = 0;
  } else {
    $self->{uppercase} = ($upper / ($upper + $lower)) * 100;
  }

  return ($self->{uppercase} > $min && $self->{uppercase} <= $max);
}

sub check_for_yelling {
  my ($self, $body) = @_;
    
  if (exists $self->{num_yelling_lines}) {
    return $self->{num_yelling_lines} > 0;
  }

  # Dec 20 2002 jm: trade off some speed for low memory footprint, by
  # iterating over the array computing sums, instead of joining the
  # array into a giant string and working from that.

  my $num_lines = 0;
  foreach my $line (@{$body}) {
    # lines in the body that have some non-letters
    next unless ($line =~ /[^A-Za-z]/);

    # Try to eliminate lines which might be newsletter section headers,
    # which are often in all caps; we do this by removing most lines
    # that start with whitespace.  However, some spam will match
    # this as well, so keep lines which have "!" or "$$" (spam often
    # has a yelling line indent with spaces, but surround by dollar
    # signs), or a "." which appears to end a sentence.
    next unless ($line =~ /^\S|!|\$\$|\.(?:\s|$)/);

    $_ = $line;		 # copy to preserve originals

    # Get rid of everything but upper AND lower case letters
    tr/A-Za-z \t//cd;

    # Remove leading and trailing whitespace
    s/^\s+//; s/\s+$//;

    # Now that we have a mixture of upper and lower case, see if it's
    # 1) All upper case
    # 2) 20 or more characters in length
    # 3) Has at least one whitespace in it; we don't want to catch things
    #    like lines of genetic data ("...AGTAGC...")
    if (/^[A-Z\s]{20,}$/ && /\s/) {
      $num_lines++;
    }
  }

  $self->{num_yelling_lines} = $num_lines;

  return ($num_lines > 0);
}

sub check_for_num_yelling_lines {
  my ($self, $body, $threshold) = @_;
    
  $self->check_for_yelling($body);
    
  return ($self->{num_yelling_lines} >= $threshold);
}

sub check_language {            # UNDESIRED_LANGUAGE_BODY
  my ($self, $body) = @_;

  my @languages = split (' ', $self->{conf}->{ok_languages});

  return 0 if grep { $_ eq "all" } @languages;

  $body = join ("\n", @{$body});
  $body =~ s/^Subject://i;

  # need about 256 bytes for reasonably accurate match (experimentally derived)
  if (length($body) < 256)
  {
     dbg("Message too short for language analysis");
     return 0;
  }

  my @matches = Mail::SpamAssassin::TextCat::classify($self, $body);
  # not able to get a match, assume it's okay
  if (! @matches) {
    return 0;
  }

  # see if any matches are okay
  foreach my $match (@matches) {
    $match =~ s/\..*//;
    foreach my $language (@languages) {
      if ($match eq $language) {
	return 0;
      }
    }
  }
  return 1;
}

sub check_signature {
  my ($self, $full, $min, $max, $blank) = @_;

  if (!exists $self->{signature_lines}) {
    $self->_check_signature($full);
  }
  return (($self->{signature_lines} >= $min) &&
	  ($self->{signature_lines} <= $max) &&
	  ($self->{signature_blank} == $blank));
}


sub _check_signature {
  my ($self, $full) = @_;

  $self->{signature_blank} = 0;
  $self->{signature_lines} = 0;

  # remove headers
  my ($body) = ($$full =~ /.*?\n\n(.*)/s);

  # signature must follow one non-whitespace character
  if (defined($body) && $body =~ /\S\s*\n-- \n((.*\n){1,15}?)\s*\Z/m) {
    my $signature = $1;

    if ($signature =~ /\n\s*\n\s*\S/m) {
      $self->{signature_blank} = 1;
    }
    if ($signature =~ /\S/m) {
      $self->{signature_lines} = ($signature =~ tr/\n/\n/);
    }
  }
}

sub check_carriage_returns {
  my ($self, $rawbody) = @_;

  $rawbody = join ("\n", @$rawbody);

  my $cr = ($rawbody =~ tr/\r/x/);
  my $nl = ($rawbody =~ tr/\n/x/);

  return ($nl > 0 && ($cr / $nl) > 0.5);
}

###########################################################################
# MIME/uuencode attachment tests
###########################################################################

sub check_for_mime_base64_encoded_text {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_base64_encoded_text};
  return $self->{mime_base64_encoded_text};
}

sub check_for_mime_faraway_charset {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_faraway_charset};
  return $self->{mime_faraway_charset};
}

sub check_for_mime_html_no_charset {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_html_no_charset};
  return $self->{mime_html_no_charset};
}

# HTML without some other type of MIME text part
sub check_for_mime_html_only {
  my ($self) = @_;

  my $ctype = $self->get('Content-Type');
  return 1 if (defined($ctype) && $ctype =~ m@text/html@i);

  $self->_check_attachments unless exists $self->{mime_body_html_count};
  return ($self->{mime_body_html_count} > 0 &&
	  $self->{mime_body_text_count} == 0);
}

sub check_for_mime_missing_boundary {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_missing_boundary};
  return $self->{mime_missing_boundary};
}

sub check_for_mime_excessive_qp {
  my ($self, undef, $min) = @_;

  $self->_check_attachments unless exists $self->{mime_qp_ratio};

  return $self->{mime_qp_ratio} >= $min;
}

sub check_for_mime_long_line_qp {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_long_line_qp};
  return $self->{mime_long_line_qp};
}

sub check_for_mime_suspect_name { # MIME_SUSPECT_NAME
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{mime_suspect_name};
  return $self->{mime_suspect_name};
}

sub check_for_microsoft_executable {
  my ($self) = @_;

  $self->_check_attachments unless exists $self->{microsoft_executable};
  return $self->{microsoft_executable};
}

sub _check_mime_header {
  my ($self, $ctype, $cte, $cd, $charset, $name) = @_;

  if ($ctype =~ m@^text/html@i) {
    $self->{mime_body_html_count}++;
  }
  elsif ($ctype =~ m@^(?:text|message)@i) {
    $self->{mime_body_text_count}++;
  }

  if ($ctype =~ /^text/ &&
      $cte =~ /base64/ &&
      !($cd && $cd =~ /^(?:attachment|inline)/))
  {
    $self->{mime_base64_encoded_text} = 1;
  }

  if ($ctype =~ /^text\/html/ &&
      !(defined($charset) && $charset) &&
      !($cd && $cd =~ /^(?:attachment|inline)/))
  {
    $self->{mime_html_no_charset} = 1;
  }

  if ($charset =~ /[a-z]/i && ! $self->{mime_faraway_charset}) {
    my @l = $self->get_my_locales();

    if (!(grep { $_ eq "all" } @l) &&
	!Mail::SpamAssassin::Locales::is_charset_ok_for_locales($charset, @l))
    {
      $self->{mime_faraway_charset} = 1;
    }
  }

  if ($name && $ctype ne "application/octet-stream") {
    # MIME_SUSPECT_NAME triggered here
    $name =~ s/.*\.//;
    $ctype =~ s@/(x-|vnd\.)@/@;

    if (((($name eq "txt") || ($name =~ /^[px]?html?$/) ||
	  ($name eq "xml")) &&
	 ($ctype !~
	  m@^text/(?:plain|[px]?html?|english|sgml|xml|enriched|richtext)@) &&
	 ($ctype !~ m@^message/external-body@)) # RFC-Editor emails...
	|| ((($name =~ /^(?:jpe?g|tiff?)$/) || ($name eq "gif") ||
	     ($name eq "png"))
	    && ($ctype !~ m@^image/@)
	    && ($ctype !~ m@^application/mac-binhex@))
	|| ($name eq "vcf" && $ctype ne "text/vcard")
	|| ($name =~ /^(?:bat|com|exe|pif|scr|swf|vbs)$/
	    && $ctype !~ m@^application/@)
	|| ($name eq "doc" && $ctype !~ m@^application/.*word$@)
	|| ($name eq "ppt" && $ctype !~ m@^application/.*(?:powerpoint|ppt)$@)
	|| ($name eq "xls" && $ctype !~ m@^application/.*excel$@)
       )
    {
       $self->{mime_suspect_name} = 1;
    }
  }
}

sub _check_attachments {
  my ($self) = @_;

  my $previous = 'undef';	# the previous line

  # MIME status
  my $where = -1;		# -1 = start, 0 = nowhere, 1 = header, 2 = body
  my @boundary;			# list of MIME boundaries
  my %state;			# state of each MIME part
  my $qp_bytes = 0;		# total bytes in QP regions
  my $qp_count = 0;		# QP-encoded bytes in QP regions

  # MIME header information
  my $ctype;			# Content-Type
  my $cte;			# Content-Transfer-Encoding
  my $cd;			# Content-Disposition
  my $charset;			# charset
  my $name;			# name or filename

  # regular expressions
  my $re_boundary = qr/\bboundary\s*=\s*["']?(.*?)["']?(?:;|$)/i;
  my $re_charset = qr/\bcharset\s*=\s*["']?(.*?)["']?(?:;|$)/i;
  my $re_name = qr/name\s*=\s*["']?(.*?)["']?(?:;|$)/i;
  my $re_ctype = qr/^Content-Type:\s*(.+?)(?:;|\s|$)/i;
  my $re_cte = qr/^Content-Transfer-Encoding:\s*(.+)/i;
  my $re_cd = qr/^Content-Disposition:\s*(.+)/i;

  # results
  $self->{microsoft_executable} = 0;
  $self->{mime_base64_encoded_text} = 0;
  $self->{mime_body_html_count} = 0;
  $self->{mime_body_text_count} = 0;
  $self->{mime_faraway_charset} = 0;
  $self->{mime_html_no_charset} = 0;
  $self->{mime_long_line_qp} = 0;
  $self->{mime_missing_boundary} = 0;
  $self->{mime_qp_ratio} = 0;
  $self->{mime_suspect_name} = 0;

  # message headers
  $ctype = $self->get('Content-Type');
  $cte = $self->get('Content-Transfer-Encoding');
  chomp($cte = defined($cte) ? lc($cte) : "");
  if ($ctype =~ /$re_boundary/m && $1 ne '') {
    push (@boundary, "\Q$1\E");
  }
  if ($ctype =~ /^text\//i && $cte =~ /base64/) {
    $self->{mime_base64_encoded_text} = 1;
  }

  # Note: We don't use rawbody because it removes MIME parts.  Instead,
  # we get the raw unfiltered body.  We must not change any lines and
  # we might see some SpamAssassin mark-up.
  for (@{$self->{msg}->get_body()}) {
    if (/^--/) {
      foreach my $boundary (@boundary) {
	if (/^--$boundary$/) {
	  $state{$boundary} = 1;
	  $ctype = $cte = $cd = $charset = $name = 0;
	  $where = 1;
	}
	if (/^--$boundary--$/) {
	  $state{$boundary}--;
	  $where = 0;
	}
      }
    }
    if ($where == 2) {
      if ($previous =~ /^$/ && /^TVqQAAMAAAAEAAAA/) {
	$self->{microsoft_executable} = 1;
      }
      if ($self->{mime_html_no_charset} &&
	  $ctype =~ /^text\/html/ &&
	  /charset=/i)
      {
	$self->{mime_html_no_charset} = 0;
      }
    }
    if ($where == 1) {
      if (/^$/) {
	$where = 2;
	$self->_check_mime_header($ctype, $cte, $cd, $charset, $name);
      }
      if (/$re_boundary/) { push(@boundary, "\Q$1\E"); }
      if (/$re_charset/) { $charset = lc($1); }
      if (/$re_name/) { $name = lc($1); }
      if (/$re_ctype/) { $ctype = lc($1); }
      elsif (/$re_cte/) { $cte = lc($1); }
      elsif (/$re_cd/) { $cd = lc($1); }
    }
    if ($previous =~ /^begin [0-7]{3} ./ && /^M35J0``,````\$````/) {
      $self->{microsoft_executable} = 1;
    }
    if ($where != 1 && $cte eq "quoted-printable" && ! /^SPAM: /) {
      if (length > 77) {
	$self->{mime_long_line_qp} = 1;
      }
      $qp_bytes += length;
      if (index($_, '=') != -1) {
	# whoever wrote this next line is an evil hacker -- jm
	my $qp = () = m/=(?:09|3[0-9ABCEF]|[2456][0-9A-F]|7[0-9A-E])/g;
	if ($qp) {
	  $qp_count += $qp;
	  # tabs and spaces at end of encoded line are okay.  Also, multiple
	  # whitespace at the end of a line are OK, like ">=20=20=20=20=20=20".
	  my ($trailing) = m/((?:=09|=20)+)\s*$/g;
	  if ($trailing) {
	    $qp_count -= (length($trailing) / 3);
	  }
	}
      }
    }
    $previous = $_;
  }
  if ($qp_bytes) {
    $self->{mime_qp_ratio} = $qp_count / $qp_bytes;
  }
  foreach my $str (keys %state) {
    if ($state{$str} != 0) {
      $self->{mime_missing_boundary} = 1;
      last;
    }
  }
}

###########################################################################
# FULL-MESSAGE TESTS:
###########################################################################

sub check_razor1 {
  my ($self) = @_;

  return 0 unless ($self->is_razor1_available());
  return 0 if ($self->{already_checked_razor1});

  $self->{already_checked_razor1} = 1;

  # note: we don't use $fulltext. instead we get the raw message,
  # unfiltered, for razor1 to check.  ($fulltext removes MIME
  # parts etc.)
  my $full = $self->get_full_message_as_text();
  return $self->razor1_lookup (\$full);
}

sub check_razor2 {
  my ($self) = @_;

  return 0 unless ($self->is_razor2_available());
  return $self->{razor2_result} if ( defined $self->{razor2_result} );

  # note: we don't use $fulltext. instead we get the raw message,
  # unfiltered, for razor2 to check.  ($fulltext removes MIME
  # parts etc.)
  my $full = $self->get_full_message_as_text();
  return $self->razor2_lookup (\$full);
}

sub check_pyzor {
  my ($self, $fulltext) = @_;

  return 0 unless ($self->is_pyzor_available());
  return 0 if ($self->{already_checked_pyzor});

  $self->{already_checked_pyzor} = 1;

  # note: we don't use $fulltext. instead we get the raw message,
  # unfiltered, for pyzor to check.  ($fulltext removes MIME
  # parts etc.)
  my $full = $self->get_full_message_as_text();
  return $self->pyzor_lookup (\$full);
}

sub check_dcc {
  my ($self, $fulltext) = @_;

  return 0 unless ($self->is_dcc_available());
  return 0 if ($self->{already_checked_dcc});

   $self->{already_checked_dcc} = 1;

  # First check if there's already a X-DCC header with value of "bulk"
  # and short-circuit if there is -- someone upstream might already have
  # checked DCC for us.
  $_ = $self->get('X-DCC-(?:[^:]+-)?Metrics');
  return 1 if /bulk/;
  
  # note: we don't use $fulltext. instead we get the raw message,
  # unfiltered, for DCC to check.  ($fulltext removes MIME
  # parts etc.)
  my $full = $self->get_full_message_as_text();
  return $self->dcc_lookup (\$full);
}

###########################################################################

sub check_for_fake_aol_relay_in_rcvd {
  my ($self) = @_;
  local ($_);

  $_ = $self->get ('Received'); s/\s/ /gs;

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

###########################################################################

sub check_for_to_in_subject {
  my ($self,$check) = @_;
  $check ||= 1;

  my $to = $self->get ('To:addr');
  return 0 unless $to; # no To:?
  $to =~ s/\@.*$//; # just the username please

  my $subject = $self->get('Subject');

  return 1 if ( $check == 1 && $subject =~ /^\s*\Q$to\E,/ );    # "user,"   case sensitive
  return 1 if ( $check == 2 && $subject =~ /^\s*\Q$to\E,/i );   # "user,"   case insensitive
  return 1 if ( $check == 3 && $subject =~ /^\s*\Q$to\E,\S/ );  # "user,\S" case sensitive
  return 1 if ( $check == 4 && $subject =~ /^\s*\Q$to\E,\S/i ); # "user,\S" case insensitive
  return 1 if ( $check == 5 && $subject =~ /\b\Q$to\E\b/ );     # "user"    case sensitive
  return 1 if ( $check == 6 && $subject =~ /\b\Q$to\E\b/i );    # "user"    case insensitive

  return 0;
}

###########################################################################

sub check_bayes {
  my ($self, $fulltext, $min, $max) = @_;

  if (!exists ($self->{bayes_score})) {
    $self->{bayes_score} = $self->{main}->{bayes_scanner}->scan
			      ($self->{msg}, $fulltext);
  }

  if (($min == 0 || $self->{bayes_score} > $min) &&
      ($max eq "undef" || $self->{bayes_score} <= $max))
  {
      if ($self->{bayes_score}) {
          if ($self->{conf}->{detailed_bayes_score}) {
              $self->test_log(sprintf ("score: %3.4f, hits: %s",
                                       $self->{bayes_score},
                                       $self->{bayes_hits}));
          }
          else {
              $self->test_log(sprintf ("score: %3.4f", $self->{bayes_score}));
          }
      }
      return 1;
  }
  return 0;

}

###########################################################################

# valid Outlookish Message-Ids contain the top word of the system time
# when the message was sent!
# We can verify this, by decoding the Date header, extracting
# the time token from the Message-Id, and comparing them.
#
sub check_outlook_timestamp_token {
  my ($self) = @_;
  local ($_);

  my $id = $self->get ('MESSAGEID');
  return 0 unless ($id =~ /^<[0-9a-f]{4}([0-9a-f]{8})\$[0-9a-f]{8}\$[0-9a-f]{8}\@/);

  my $timetoken = hex($1);

  # convert UNIX time_t to Windows FILETIME.  From MSDN:
  #
  #     LONGLONG ll = Int32x32To64(t, 10000000) + 116444736000000000;
  #     pft->dwLowDateTime = (DWORD) ll;
  #     pft->dwHighDateTime = ll >>32;
  #
  # IOW, ((tt * a) + b) / c = id .
  # Now to avoid using any kind of LONGLONG data type, we do this:
  #     => tt * (a/c) + (b/c) = id
  #     let x = (a/c) = 0.0023283064365387
  #     let y = (b/c) = 27111902.8329849
  #
  my $x = 0.0023283064365387;
  my $y = 27111902.8329849;

  # quite generous, but we just want to be in the right ballpark, so we
  # can handle mostly-correct values OK, but catch random strings.
  my $fudge = 250;

  $_ = $self->get ('Date');
  $_ = $self->_parse_rfc822_date($_); $_ ||= 0;
  my $expected = int (($_ * $x) + $y);
  my $diff = $timetoken - $expected;
  dbg("time token found: $timetoken expected (from Date): $expected: $diff");
  if (abs ($diff) < $fudge) { return 0; }

  # also try last date in Received header, Date could have been rewritten
  $_ = $self->get ('Received');
  /(\s.?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+).*?$/;
  dbg("last date in Received: $1");
  $_ = $self->_parse_rfc822_date($_); $_ ||= 0;
  $expected = int (($_ * $x) + $y);
  $diff = $timetoken - $expected;
  dbg("time token found: $timetoken expected (from Received): $expected: $diff");
  if (abs ($diff) < $fudge) { return 0; }

  return 1;
}

# Check the cf value of a given message and return if it's within the given range
sub check_razor2_range {
  my ($self,$fulltext,$min,$max) = @_;

  # If the Razor2 general test is disabled, don't continue.
  return 0 unless ( $self->{conf}{scores}{'RAZOR2_CHECK'} );

  # If Razor2 hasn't been checked yet, go ahead and run it.
  unless ( defined $self->{razor2_result} ) {
    # note: we don't use $fulltext. instead we get the raw message,
    # unfiltered, for razor2 to check.  ($fulltext removes MIME
    # parts etc.)
    my $full = $self->get_full_message_as_text();
    $self->razor2_lookup (\$full);
  }

  if ( $self->{razor2_cf_score} >= $min && $self->{razor2_cf_score} <= $max ) {
    $self->test_log(sprintf ("cf: %3d", $self->{razor2_cf_score}));
    return 1;
  }
  return 0;
}

# I don't know if we should simply copy Email::IsFree or source it.
# It was first released on 2002-09-18 and hasn't been updated since then.
sub check_email_isfree {
  my ($self, $body) = @_;

#  return 0 unless HAS_EMAIL_ISFREE;

  foreach (@{$body}) {
    my @domains = /\@[.\w-]{2,}/g;
    foreach my $domain (@domains) {
      #$domain =~ s/\@//;
      #$domain = lc $domain;
      #print STDERR "EMAIL $domain\n";
#      return 1 if Email::IsFree::by_domain($domain);
    }
  }

  return 0;
}

sub check_messageid_not_usable {
  my ($self) = @_;
  local ($_);

  # Lyris eats message-ids.  also some ezmlm, I think :(
  $_ = $self->get ("List-Unsubscribe");
  return 1 if (/<mailto:(?:leave-\S+|\S+-unsubscribe)\@\S+>$/);

  # ezmlm again
  if($self->gated_through_received_hdr_remover()) { return 1; }

  # Allen notes this as 'Wacky sendmail version?'
  $_ = $self->get ("Received");
  return 1 if /\/CWT\/DCE\)/;

  # too old; older versions of clients used different formats
  return 1 if ($self->received_within_months('6','undef'));

  return 0;
}

1;
