#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Dns;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::AutoWhitelist;
use IO::Socket;
use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES
	$CCTLDS_WITH_LOTS_OF_OPEN_RELAYS
	$ROUND_THE_WORLD_RELAYERS
};

# persistent spam sources. These are not in the RBL though :(
$KNOWN_BAD_DIALUP_RANGES = q(
    .da.uu.net .prod.itd.earthlink.net .pub-ip.psi.net .prserv.net
);

# sad but true. sort it out, sysadmins!
$CCTLDS_WITH_LOTS_OF_OPEN_RELAYS = qr{(?:kr|cn|cl|ar|hk|us|il|th|tw|sg|za|tr|ma|ua|in|pe)};
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

###########################################################################
# HEAD TESTS:
###########################################################################

sub check_for_from_mx {
  my ($self) = @_;

  my $from = $self->get ('From:addr');
  return 0 unless ($from =~ /\@(\S+)/);
  $from = $1;

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();
  $self->load_resolver();

  if ($from eq 'compiling.spamassassin.taint.org') {
    # only used when compiling
    return 0;
  }

  # Try 3 times to protect against temporary outages.  sleep between checks
  # to give the DNS a chance to recover.
  for my $i (1..$self->{conf}->{check_mx_attempts}) {
    my @mx = Net::DNS::mx ($self->{res}, $from);
    dbg ("DNS MX records found: ".scalar (@mx));
    if (scalar @mx > 0) { return 0; }
    if ($i < $self->{conf}->{check_mx_attempts}) {sleep $self->{conf}->{check_mx_delay}; };
  }

  return 1;
}

###########################################################################

sub check_for_bad_dialup_ips {
  my ($self) = @_;
  local ($_);

  my $knownbad = $KNOWN_BAD_DIALUP_RANGES;
  $knownbad =~ s/^\s+//g;
  $knownbad =~ s/\s+$//g;
  $knownbad =~ s/\./\\./g;
  $knownbad =~ s/\s+/\|/g;

  $_ = $self->get ('Received');
  /${knownbad}/o;
}

###########################################################################

sub check_for_from_to_equivalence {
  my ($self) = @_;
  my $from = $self->get ('From:addr');
  my $to = $self->get ('To:addr');

  if ($from eq '' && $to eq '') { return 0; }
  ($from eq $to);
}

###########################################################################

sub check_for_forged_hotmail_received_headers {
  my ($self) = @_;

  my $to = $self->get ('To:addr');
  if ($to !~ /hotmail.com/) { return 0; }

  my $rcvd = $self->get ('Received');

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # spammers do not ;)

  if ($rcvd !~ /from hotmail.com/) { return 0; }

  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  if ($rcvd =~ /from \S*hotmail.com \(\S+\.hotmail(?:\.msn|)\.com /) { return 0; }
  if ($rcvd =~ /from \S+ by \S+\.hotmail(?:\.msn|)\.com with HTTP\;/) { return 0; }

  return 1;
}

###########################################################################

sub check_for_forged_yahoo_received_headers {
  my ($self) = @_;

  my $to = $self->get ('To:addr');
  if ($to !~ /yahoo.com/) { return 0; }

  my $rcvd = $self->get ('Received');

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # spammers do not ;)

  if ($rcvd !~ /from \S*yahoo\.com/) { return 0; }

  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  if ($rcvd =~ /by web\S+\.mail\.yahoo\.com via HTTP/) { return 0; }

  return 1;
}

###########################################################################

sub check_for_bad_helo {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('X-Authentication-Warning');

  (/host \S+ \[(\S+)\] claimed to be.*\[(\S+)\]/i && $1 ne $2);
}

###########################################################################

sub check_subject_for_lotsa_8bit_chars {
  my ($self) = @_;
  local ($_);

  $_ = $self->get ('Subject');

  # cut [ and ] because 8-bit posts to mailing lists may not get
  # hit otherwise. e.g.: Subject: [ILUG] 出售傳真號碼 .  Also cut
  # *, since mail that goes through spamassassin multiple times will
  # not be tagged on the second pass otherwise.
  s/\[\]\* //g;

  my @highbits = /[\200-\377]/g; my $numhis = $#highbits+1;
  my $numlos = length($_) - $numhis;

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

sub check_from_in_whitelist {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('From:addr');
  return $self->_check_whitelist ($self->{conf}->{whitelist_from}, $_);
}

sub _check_whitelist {
  my ($self, $list, $addr) = @_;
  $addr = lc $addr;

  if (defined ($list->{$addr})) { return 1; }

  study $addr;
  foreach my $regexp (values %{$list->{$addr}}) {
    if ($addr =~ /$regexp/) { return 1; }
  }

  return 0;
}

###########################################################################

sub check_from_in_blacklist {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('From:addr');
  return $self->_check_whitelist ($self->{conf}->{blacklist_from}, $_);
}

###########################################################################
# added by DJ

sub check_to_in_whitelist {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('To:addr');
  return $self->_check_whitelist ($self->{conf}->{whitelist_to}, $_);
}


###########################################################################
# added by DJ

sub check_to_in_more_spam {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('To:addr');
  return $self->_check_whitelist ($self->{conf}->{more_spam_to}, $_);
}


###########################################################################
# added by DJ

sub check_to_in_all_spam {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('To:addr');
  return $self->_check_whitelist ($self->{conf}->{all_spam_to}, $_);
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

sub check_from_name_eq_from_address {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('From');

  /\"(\S+)\" <(\S+)>/ or return 0;
  if ($1 eq $2) { return 1; }
  return 0;
}

###########################################################################

sub check_rbl {
  my ($self, $set, $rbl_domain) = @_;
  local ($_);
  dbg ("checking RBL $rbl_domain, set $set");

  my $rcv = $self->get ('Received');
  my @ips = ($rcv =~ /\[(\d+\.\d+\.\d+\.\d+)\]/g);
  return 0 unless ($#ips >= 0);

  # First check that DNS is available, if not do not perform this check
  return 0 if $self->{conf}->{skip_rbl_checks};
  return 0 unless $self->is_dns_available();
  $self->load_resolver();

  if ($#ips > 1) {
    @ips = @ips[$#ips-1 .. $#ips];        # only check the originating 2
  }

  if (!defined $self->{$set}->{rbl_IN_As_found}) {
    $self->{$set}->{rbl_IN_As_found} = ' ';
    $self->{$set}->{rbl_matches_found} = ' ';
  }

  init_rbl_check_reserved_ips();
  my $already_matched_in_other_zones = ' '.$self->{$set}->{rbl_matches_found}.' ';
  my $found = 0;

  # First check that DNS is available, if not do not perform this check.
  # Stop after the first positive.
  eval {
    foreach my $ip (@ips) {
      next if ($ip =~ /${IP_IN_RESERVED_RANGE}/o);
      next if ($already_matched_in_other_zones =~ / ${ip} /);
      next unless ($ip =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
      $found = $self->do_rbl_lookup ($set, "$4.$3.$2.$1.".$rbl_domain, $ip, $found);
    }
  };

  $found;
}

###########################################################################

sub check_rbl_results_for {
  my ($self, $set, $addr) = @_;

  dbg ("checking RBL results in set $set for $addr");
  return 0 if $self->{conf}->{skip_rbl_checks};
  return 0 unless $self->is_dns_available();
  return 0 unless defined ($self->{$set});
  return 0 unless defined ($self->{$set}->{rbl_IN_As_found});

  my $inas = ' '.$self->{$set}->{rbl_IN_As_found}.' ';
  if ($inas =~ / ${addr} /) { return 1; }

  return 0;
}

###########################################################################

sub check_for_unique_subject_id {
  my ($self) = @_;
  local ($_);
  $_ = lc $self->get ('Subject');
  study;

  my $id = undef;
  if (/[-_\.\s]{7,}([-a-z0-9]{4,})$/
	|| /\s{3,}[-:\#\(\[]+([-a-z0-9]{4,})[\]\)]+$/
	|| /\s{3,}[:\#\(\[]*([0-9]{4,})[\]\)]*$/
	|| /\s{3,}[-:\#]([a-z0-9]{5,})$/)
  {
    $id = $1;
  }

  if (!defined($id) || $self->word_is_in_dictionary ($id)) {
    return 0;
  } else {
    return 1;
  }
}

# IMO, ideally the check-for-dict code should *not* actually use a dict, it
# should just use an algorithm which can recognise english-like
# consonant-vowel strings and pass them.
# 
# Really, we just want to distinguish between (solved) (amusing) (funny)
# (bug) (attn) (urgent) and (kdsjf) (ofdiax) (zkdwo) ID-type strings.

sub word_is_in_dictionary {
  my ($self, $word) = @_;
  local ($_);
  local $/ = "\n";		# Ensure $/ is set appropriately

  # $word =~ tr/A-Z/a-z/;	# already done by this stage
  $word =~ s/^\s+//;
  $word =~ s/\s+$//;
  return 0 if ($word =~ /[^a-z]/);

  study $word;

  # handle a few common "blah blah blah (comment)" styles
  return 1 if ($word =~ /^ot$/);	# off-topic

  # handle some common word bits that may not be in the dict.
  return 1 if ($word =~ /(?:ness$|ion|ity$|ing$|ish|ed$|en$|est|ier)/);
  return 1 if ($word =~ /(?:age|ify|ize|ise|ful|less|lly|like|nny$)/);
  return 1 if ($word =~ /(?:bug|fixed|solve|ette|ble|ism|nce)/);
  return 1 if ($word =~ /(?:ome|ent|ies|ain|end|ire|ong|arg)/);

  return 1 if ($word =~ /(?:spam|linux|nix|bsd|win)/); # not in most dicts
  return 1 if ($word =~ /(?:post|mail|topic|whew|phew)/);

  if (!open (DICT, "</usr/dict/words") &&
  	!open (DICT, "</usr/share/dict/words"))
  {
    dbg ("failed to open /usr/dict/words, cannot check dictionary");
    return 1;		# fail safe
  }

  dbg ("checking dictionary for \"$word\"");

  # make a search pattern that will match anywhere in the dict-line.
  # we just want to see if the word is english-like...
  my $wordre = qr/${word}/;

  # use DICT as a file, rather than making a hash; keeps memory
  # usage down, and the OS should cache the file contents anyway
  # if the system has enough memory.
  #
  while (<DICT>) {
    if (/${wordre}/) { close DICT; return 1; }
  }

  close DICT; return 0;
}

###########################################################################

sub get_address_commonality_ratio {
  my ($self, $addr1, $addr2) = @_;

  my %counts = ();
  map { $counts{$_}++; } split (//, lc $addr1);
  map { $counts{$_}++; } split (//, lc $addr2);

  my $foundonce = 0;
  my $foundtwice = 0;
  foreach my $char (keys %counts) {
    if ($counts{$char} == 1) { $foundonce++; next; }
    if ($counts{$char} == 2) { $foundtwice++; next; }
  }

  $foundtwice ||= 1.0;
  my $ratio = ($foundonce / $foundtwice);

  #print "addrcommonality: $foundonce $foundtwice $addr1/$addr2 $ratio\n";

  return $ratio;
}

sub check_for_spam_reply_to {
  my ($self) = @_;

  my $rpto = $self->get ('Reply-To:addr');
  return 0 if ($rpto eq '');

  my $ratio1 = $self->get_address_commonality_ratio
  				($rpto, $self->get ('From:addr'));
  my $ratio2 = $self->get_address_commonality_ratio
  				($rpto, $self->get ('To:addr'));

  # 2.0 means twice as many chars different as the same
  if ($ratio1 > 2.0 && $ratio2 > 2.0) { return 1; }

  return 0;
}

###########################################################################

sub check_for_auto_whitelist {
  my ($self) = @_;

  my $addr = lc $self->get ('From:addr');
  if ($addr !~ /\S/) { return 0; }

  my $list = Mail::SpamAssassin::AutoWhitelist->new ($self->{main});
  $self->{auto_whitelist} = $list;

  if ($list->check_address ($addr)) {
    return 1;
  }

  0;
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
			\d\d\d\d\s+\d\d:\d\d:\d\d\s+[-+]*\d\d\d\d\n$/xs);

  if (defined ($h1) && defined ($h2) && $h2 !~ /\./) {
    return 1;
  }

  0;
}

###########################################################################

sub check_for_faraway_charset {
  my ($self) = @_;

  my $type = $self->get ('Content-Type');
  $type ||= $self->get ('Content-type');

  my @locales = split (' ', $self->{conf}->{ok_locales});
  push (@locales, $ENV{'LANG'});

  $type = get_charset_from_ct_line ($type);
  if (defined $type &&
    !Mail::SpamAssassin::Locales::is_charset_ok_for_locales
		    ($type, @locales))
  {
    return 1;
  }

  0;
}

sub check_for_faraway_charset_in_body {
  my ($self, $fulltext) = @_;

  if ($$fulltext =~ /\n\n.*\n
  		Content-Type:\s(.{0,100}charset=[^\n]+)\n
		/isx)
  {
    my $type = $1;
    my @locales = split (' ', $self->{conf}->{ok_locales});
    push (@locales, $ENV{'LANG'});

    $type = get_charset_from_ct_line ($type);
    if (defined $type &&
      !Mail::SpamAssassin::Locales::is_charset_ok_for_locales
		      ($type, @locales))
    {
      return 1;
    }
  }

  0;
}

sub get_charset_from_ct_line {
  my $type = shift;
  if ($type =~ /charset="([^"]+)"/i) { return $1; }
  if ($type =~ /charset=(\S+)/i) { return $1; }
  return undef;
}

###########################################################################

sub check_for_round_the_world_received {
  my ($self) = @_;
  my ($relayer, $relayerip, $relay);

  my $rcvd = $self->get ('Received');

  # trad sendmail/postfix fmt:
  # Received: from hitower.parkgroup.ru (unknown [212.107.207.26]) by
  #     mail.netnoteinc.com (Postfix) with ESMTP id B8CAC11410E for
  #     <me@netnoteinc.com>; Fri, 30 Nov 2001 02:42:05 +0000 (Eire)
  # Received: from fmx1.freemail.hu ([212.46.197.200]) by hitower.parkgroup.ru
  #     (Lotus Domino Release 5.0.8) with ESMTP id 2001113008574773:260 ;
  #     Fri, 30 Nov 2001 08:57:47 +1000
  if ($rcvd =~ /
  	\nfrom.{0,20}\b(\S+\.${CCTLDS_WITH_LOTS_OF_OPEN_RELAYS})\s\(.{0,200}
  	\nfrom.{0,20}\b(\S+\.\S+\.\S+)\b.{0,30}\[(\d+\.\d+\.\d+\.\d+)\]
  /osix) { $relay = $1; $relayer = $2; $relayerip = $3; goto gotone; }

  return 0;

gotone:
  my $revdns = $self->lookup_ptr ($relayerip);

  dbg ("round-the-world: mail relayed through $relay by ".	
  	"$relayerip (HELO $relayer, rev DNS says $revdns");

  if ($revdns =~ /\.${ROUND_THE_WORLD_RELAYERS}$/oi) {
    dbg ("round-the-world: yep, I think so");
    return 1;
  }

  dbg ("round-the-world: probably not");
  return 0;
}

###########################################################################
# BODY TESTS:
###########################################################################

sub check_for_very_long_text {
  my ($self, $body) = @_;

  my $count = 0;
  foreach my $line (@{$body}) {
    if (length($line) > 40) { $count++; }
  }
  if ($count > 500) { return 1; }
  return 0;
}

###########################################################################
# FULL-MESSAGE TESTS:
###########################################################################

sub check_razor {
  my ($self, $fulltext) = @_;

  return 0 unless ($self->is_razor_available());
  return 0 if ($self->{already_checked_razor});

  $self->{already_checked_razor} = 1;

  # note: we don't use $fulltext. instead we get the raw message,
  # unfiltered, for razor to check.  ($fulltext removes MIME
  # parts etc.)
  my $full = $self->get_full_message_as_text();
  return $self->razor_lookup (\$full);
}

sub check_for_base64_enc_text {
  my ($self, $fulltext) = @_;

  if ($$fulltext =~ /\n\n.{0,100}(
    	\nContent-Type:\stext\/.{0,200}
	\nContent-Transfer-Encoding:\sbase64.*?
	\n\n)/isx)
  {
    my $otherhdrs = $1;
    if ($otherhdrs =~ /^Content-Disposition: (?:attachment|inline)/im) {
      return 0;		# text attachments are OK
    } else {
      return 1;		# no Content-Disp: header found, it's bad
    }
  }

  return 0;
}

###########################################################################

1;
