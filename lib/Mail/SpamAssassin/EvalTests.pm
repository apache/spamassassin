#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Dns;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::PhraseFreqs;
use Mail::SpamAssassin::AutoWhitelist;
use Time::Local;
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
$CCTLDS_WITH_LOTS_OF_OPEN_RELAYS = qr{(?:kr|cn|cl|ar|hk|il|th|tw|sg|za|tr|ma|ua|in|pe)};
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
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # spammers do not ;)

  #if ($rcvd !~ /from hotmail.com/) { return 0; }

  if ($rcvd =~ /from \S*hotmail.com \(\S+\.hotmail(?:\.msn|)\.com /) { return 0; }
  if ($rcvd =~ /from \S+ by \S+\.hotmail(?:\.msn|)\.com with HTTP\;/) { return 0; }

  return 1;
}

###########################################################################

sub check_for_forged_excite_received_headers {
  my ($self) = @_;

  my $to = $self->get ('To:addr');
  if ($to !~ /excite.com/) { return 0; }

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

  if ($rcvd =~ /from \S*excite.com /) { return 0; }
  
  return 1;
}

###########################################################################

sub check_for_forged_yahoo_received_headers {
  my ($self) = @_;

  my $to = $self->get ('To:addr');
  if ($to !~ /yahoo.com/) { return 0; }

  my $rcvd = $self->get ('Received');
  $rcvd =~ s/\s+/ /gs;		# just spaces, simplify the regexp

  # not sure about this
  #if ($rcvd !~ /from \S*yahoo\.com/) { return 0; }

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
  foreach my $regexp (values %{$list}) {
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
  foreach $_ ($self->{main}->find_all_addrs_in_line
  			($self->get ('To') . $self->get ('Cc')))
  {
    return $self->_check_whitelist ($self->{conf}->{whitelist_to}, $_);
  }
}


###########################################################################
# added by DJ

sub check_to_in_more_spam {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->{main}->find_all_addrs_in_line
  			($self->get ('To') . $self->get ('Cc')))
  {
    return $self->_check_whitelist ($self->{conf}->{more_spam_to}, $_);
  }
}


###########################################################################
# added by DJ

sub check_to_in_all_spam {
  my ($self) = @_;
  local ($_);
  foreach $_ ($self->{main}->find_all_addrs_in_line
  			($self->get ('To') . $self->get ('Cc')))
  {
    return $self->_check_whitelist ($self->{conf}->{all_spam_to}, $_);
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

  my $sword = substr $word, 0, 4;  # Perhaps 5 is better than 4.

  dbg ("checking dictionary for \"$sword\", (was $word)");

  # make a search pattern that will match anywhere in the dict-line.
  # we just want to see if the word is english-like...
  my $wordre = qr/${sword}/i;

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
			\d{4}\s+\d\d:\d\d:\d\d\s+[-+]*\d{4}\n$/xs);

  if (defined ($h1) && defined ($h2) && $h2 !~ /\./) {
    return 1;
  }

  0;
}

###########################################################################

sub check_for_content_type_just_html {
  my ($self) = @_;
  local ($_);

  my $rcv = $self->get ('Received');
  my $ctype = $self->get ('Content-Type');

  # HotMail uses this unfortunately for it's "rich text" control,
  # so we need to exclude that from the test.
  if ($rcv =~ / by hotmail.com /) { return 0; }

  if ($ctype =~ /^text\/html\b/) { return 1; }

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
  	\nfrom\b.{0,20}\s(\S+\.${CCTLDS_WITH_LOTS_OF_OPEN_RELAYS})\s\(.{0,200}
  	\nfrom\b.{0,20}\s([-_A-Za-z0-9.]+)\s.{0,30}\[(\d+\.\d+\.\d+\.\d+)\]
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

sub check_for_forward_date {
  my ($self) = @_;
  local ($_);

  my $date = $self->get ('Date');
  my $rcvd = $self->get ('Received');

  # if we have no Received: headers, chances are we're archived mail
  # with a limited set of hdrs. return 0.
  if (!defined $rcvd || $rcvd eq '') {
    return 0;
  }

  # don't barf here; just return an OK return value, as there's already
  # a good test for this.
  if (!defined $date || $date eq '') { return 0; }
  
  chomp ($date);
  my $time = $self->_parse_rfc822_date ($date);

  my $now;

  if ($rcvd =~ /\s(\S\S\S, .?\d+ \S\S\S \d+ \d+:\d+:\d+ \S+)/) {
    $rcvd = $1;
    dbg ("using Received header date for real time: $rcvd");
    $now = $self->_parse_rfc822_date ($rcvd);
  } else {
    dbg ("failed to find Received header date, using current system time");
    $now = time();
  }

  my $diff = $now - $time; if ($diff < 0) { $diff = -$diff; }
  dbg ("time_t from date=$time, rcvd=$now, diff=$diff");

  if ($diff > (60 * 60 * 24 * 4)) {	# 4 days far enough?
    dbg ("too far from current time, raising flag");
    return 1;
  }

  0;
}

sub _parse_rfc822_date {
  my ($self, $date) = @_;
  local ($_);
  my ($yyyy, $mmm, $dd, $hh, $mm, $ss, $mon, $tzoff);

  # make it a bit easier to match
  $_ = " $date "; s/, */ /gs; s/\s+/ /gs;

  # now match it in parts.  Date part first:
  if (s/ (\d+) ([A-Z][a-z][a-z]) (\d{4}) / /) {
    $dd = $1; $mon = $2; $yyyy = $3;
  } elsif (s/ ([A-Z][a-z][a-z]) +(\d+) \d+:\d+:\d+ (\d{4}) / /) {
    $dd = $2; $mon = $1; $yyyy = $3;
  } elsif (s/ (\d+) ([A-Z][a-z][a-z]) (\d\d) / /) {
    $dd = $1; $mon = $2; $yyyy = $3;
  }

  if (defined $yyyy && $yyyy < 100) {
    # psycho Y2K crap
    $yyyy = $3; if ($yyyy < 70) { $yyyy += 2000; } else { $yyyy += 1900; }
  }

  # hh:mm:ss
  if (s/ ([\d\s]\d):(\d\d):(\d\d) / /) {
    $hh = $1; $mm = $2; $ss = $3;
  }

  # and timezone offset. if we can't parse non-numeric zones, that's OK
  # as long as we don't worry about time diffs < 1 to 1.5 days.
  if (s/ ([-+]\d{4}) / /) {
    $tzoff = $1;
  }
  $tzoff ||= '0000';

  if (!defined $mmm && defined $mon) {
    my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
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
    return 0;
  }

  if ($tzoff =~ /([-+])(\d\d)(\d\d)$/)	# convert to seconds difference
  {
    $tzoff = (($2 * 60) + $3) * 60;
    if ($1 eq '-') {
      $time -= $tzoff;
    } else {
      $time += $tzoff;
    }
  }

  return $time;
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

sub check_for_spam_phrases {
  return Mail::SpamAssassin::PhraseFreqs::check_phrase_freqs (@_);
}
sub check_for_spam_phrases_scoring {
  return Mail::SpamAssassin::PhraseFreqs::extra_score_phrase_freqs (@_);
}

###########################################################################

1;
