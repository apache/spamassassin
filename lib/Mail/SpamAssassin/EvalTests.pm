#

package Mail::SpamAssassin::EvalTests;
1;

package Mail::SpamAssassin::PerMsgStatus;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Dns;
use Mail::SpamAssassin::Locales;
use IO::Socket;
use Carp;
use strict;

use vars qw{
	$KNOWN_BAD_DIALUP_RANGES $IP_IN_RESERVED_RANGE
	$EXISTING_DOMAIN $IS_DNS_AVAILABLE
};

# persistent spam sources. These are not in the RBL though :(
$KNOWN_BAD_DIALUP_RANGES = q(
    .da.uu.net .prod.itd.earthlink.net .pub-ip.psi.net .prserv.net
);

$EXISTING_DOMAIN = 'microsoft.com.';

$IP_IN_RESERVED_RANGE = undef;

$IS_DNS_AVAILABLE = undef;

###########################################################################
# HEAD TESTS:
###########################################################################

sub check_for_from_mx {
  my ($self) = @_;
  local ($_);

  $_ = $self->get ('From');
  return 0 unless (/\@(\S+)/);
  $_ = $1;

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();

  # Try 5 times to protect against temporary outages.  sleep between checks
  # to give the DNS a chance to recover.
  for my $i (1..5) {
    my @mx = Net::DNS::mx ($self->{res}, $_);
    if (scalar @mx >= 0) { return 0; }
    sleep 5;
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
  ($from eq $to);
}

###########################################################################

sub check_for_forged_hotmail_received_headers {
  my ($self) = @_;
  my $rcvd = $self->get ('Received');

  # Hotmail formats its received headers like this:
  # Received: from hotmail.com (f135.law8.hotmail.com [216.33.241.135])
  # spammers do not ;)

  if ($rcvd =~ /from hotmail.com/
  	&& $rcvd !~ /from \S*hotmail.com \(\S+\.hotmail\.com /)
  {
    return 1;
  } else {
    return 0;
  }
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

sub check_from_in_whitelist {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('From:addr');

  foreach my $addr (@{$self->{conf}->{whitelist_from}}) {
    if ($_ eq $addr) {
      return 1;
    }
  }

  return 0;
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
  my ($self, $rbl_domain) = @_;
  local ($_);
  my $rcv = $self->get ('Received');

  my @ips = ($rcv =~ /\[(\d+\.\d+\.\d+\.\d+)\]/g);
  return 0 unless ($#ips >= 0);

  # First check that DNS is available, if not do not perform this check
  return 0 unless $self->is_dns_available();

  if ($#ips > 1) {
    @ips = @ips[$#ips-1 .. $#ips];        # only check the originating 2
  }

  if (!defined $self->{rbl_IN_As_found}) {
    $self->{rbl_IN_As_found} = ' ';
    $self->{rbl_matches_found} = ' ';
  }

  init_rbl_check_reserved_ips();
  my $already_matched_in_other_zones = ' '.$self->{rbl_matches_found}.' ';
  my $found = 0;

  # First check that DNS is available, if not do not perform this check.
  # Stop after the first positive.
  eval q{
    foreach my $ip (@ips) {
      next if ($ip =~ /${IP_IN_RESERVED_RANGE}/o);
      next if ($already_matched_in_other_zones =~ / ${ip} /);
      next unless ($ip =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/);
      $found = $self->do_rbl_lookup ("$4.$3.$2.$1.".$rbl_domain, $ip, $found);
    }
  };

  $found;
}

###########################################################################

sub check_rbl_results_for {
  my ($self, $addr) = @_;

  return 0 unless $self->is_dns_available();
  return 0 unless defined ($self->{rbl_IN_As_found});

  my $inas = ' '.$self->{rbl_IN_As_found}.' ';
  if ($inas =~ / ${addr} /) { return 1; }

  return 0;
}

###########################################################################

sub check_for_unique_subject_id {
  my ($self) = @_;
  local ($_);
  $_ = $self->get ('Subject');

  my $id = undef;
  if (/[-_\.\s]{7,}([-a-z0-9]{4,})$/
	|| /\s+[-:\#\(\[]+([-a-zA-Z0-9]{4,})[\]\)]+$/
	|| /\s+[-:\#]([-a-zA-Z0-9]{4,})$/)
  {
    $id = $1;
  }

  if (!defined($id) || $self->word_is_in_dictionary ($id)) {
    return 0;
  } else {
    return 1;
  }
}

sub word_is_in_dictionary {
  my ($self, $word) = @_;
  local ($_);

  $word =~ tr/A-Z/a-z/;
  $word =~ s/^\s+//;
  $word =~ s/\s+$//;
  return 0 if ($word =~ /[^a-z]/);

  if (!open (DICT, "</usr/dict/words") &&
  	!open (DICT, "</usr/share/dict/words"))
  {
    dbg ("failed to open /usr/dict/words, cannot check dictionary");
    return 1;		# fail safe
  }

  # use DICT as a file, rather than making a hash; keeps memory
  # usage down, and the OS should cache the file contents anyway
  # if the system has enough memory.
  #
  while (<DICT>) {
    chop; if ($word eq $_) { close DICT; return 1; }
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
  my $locale = $ENV{'LANG'};

  if ($type =~ /^.*charset=[\"](.+?)[\"]/i || $type =~ /^.*charset=(\S+?)/i) {
    if (!Mail::SpamAssassin::Locales::is_charset_ok_for_locale ($1, $locale)) {
      return 1;
    }
  }

  0;
}

sub check_for_faraway_charset_in_body {
  my ($self, $fulltext) = @_;

  if ($$fulltext =~ /\n\n.*\n
  		Content-Type:\s.{0,100}charset=([^\n]+?)\n
		/isx)
  {
    my $type = $1;
    my $locale = $ENV{'LANG'};
    if ($type =~ /[\"](.+?)[\"]/i || $type =~ /^(\S+?)/i) {
      if (!Mail::SpamAssassin::Locales::is_charset_ok_for_locale ($1, $locale)) {
	return 1;
      }
    }
  }

  0;
}

###########################################################################
# BODY TESTS:
###########################################################################

sub check_for_very_long_text {
  my ($self, $body) = @_;
  (scalar @{$body} > 500);
}

###########################################################################
# FULL-MESSAGE TESTS:
###########################################################################

sub check_razor {
  my ($self, $fulltext) = @_;

  return 0 unless ($self->is_razor_available());
  return $self->razor_lookup ($fulltext);
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
