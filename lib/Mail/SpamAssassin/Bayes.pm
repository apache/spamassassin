# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Bayes - determine spammishness using a Bayesian classifier

=head1 SYNOPSIS

=head1 DESCRIPTION

This is a Bayesian-like form of probability-analysis classification, using an
algorithm based on the one detailed in Paul Graham's I<A Plan For Spam> paper
at:

  http://www.paulgraham.com/

It also incorporates some other aspects taken from Graham Robinson's webpage
on the subject at:

  http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html

And the chi-square probability combiner as described here:

  http://www.linuxjournal.com/print.php?sid=6467

The results are incorporated into SpamAssassin as the BAYES_* rules.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Bayes;

use strict;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::SHA1 qw(sha1);

use vars qw{
  @ISA
  $IGNORED_HDRS
  $MARK_PRESENCE_ONLY_HDRS
  %HEADER_NAME_COMPRESSION
  $OPPORTUNISTIC_LOCK_VALID
};

@ISA = qw();

# Which headers should we scan for tokens?  Don't use all of them, as it's easy
# to pick up spurious clues from some.  What we now do is use all of them
# *less* these well-known headers; that way we can pick up spammers' tracking
# headers (which are obviously not well-known in advance!).

$IGNORED_HDRS = qr{(?: (?:X-)?Sender    # misc noise
  |Delivered-To |Delivery-Date
  |(?:X-)?Envelope-To
  |X-MIME-Auto[Cc]onverted |X-Converted-To-Plain-Text

  |Received     # handled specially

  |Subject      # not worth a tiny gain vs. to db size increase

  # Date: can provide invalid cues if your spam corpus is
  # older/newer than ham
  |Date

  # List headers: ignore. a spamfiltering mailing list will
  # become a nonspam sign.
  |X-List|(?:X-)?Mailing-List
  |(?:X-)?List-(?:Archive|Help|Id|Owner|Post|Subscribe
    |Unsubscribe|Host|Id|Manager|Admin|Comment
    |Name|Url)
  |X-Unsub(?:scribe)?
  |X-Mailman-Version |X-Been[Tt]here |X-Loop
  |Mail-Followup-To
  |X-eGroups-(?:Return|From)
  |X-MDMailing-List
  |X-XEmacs-List

  # gatewayed through mailing list (thanks to Allen Smith)
  |(?:X-)?Resent-(?:From|To|Date)
  |(?:X-)?Original-(?:From|To|Date)

  # Spamfilter/virus-scanner headers: too easy to chain from
  # these
  |X-MailScanner(?:-SpamCheck)?
  |X-Spam(?:-(?:Status|Level|Flag|Report|Hits|Score|Checker-Version))?
  |X-Antispam |X-RBL-Warning |X-Mailscanner
  |X-MDaemon-Deliver-To |X-Virus-Scanned
  |X-Mass-Check-Id
  |X-Pyzor |X-DCC-\S{2,25}-Metrics
  |X-Filtered-B[Yy] |X-Scanned-By |X-Scanner
  |X-AP-Spam-(?:Score|Status) |X-RIPE-Spam-Status
  |X-SpamCop-[^:]+
  |X-SMTPD |(?:X-)?Spam-Apparently-To
  |SPAM |X-Perlmx-Spam

  # some noisy Outlook headers that add no good clues:
  |Content-Class |Thread-(?:Index|Topic)
  |X-Original[Aa]rrival[Tt]ime

  # Annotations from IMAP, POP, and MH:
  |(?:X-)?Status |X-Flags |Replied |Forwarded
  |Lines |Content-Length
  |X-UIDL?

  # Annotations from Bugzilla
  |X-Bugzilla-[^:]+

  # Annotations from VM: (thanks to Allen Smith)
  |X-VM-(?:Bookmark|(?:POP|IMAP)-Retrieved|Labels|Last-Modified
    |Summary-Format|VHeader|v\d-Data|Message-Order)

  # Annotations from Gnus:
  | X-Gnus-Mail-Source
  | Xref

)}x;

# Note only the presence of these headers, in order to reduce the
# hapaxen they generate.
$MARK_PRESENCE_ONLY_HDRS = qr{(?: X-Face
  |X-(?:Gnu-?PG|PGP|GPG)(?:-Key)?-Fingerprint
)}ix;

# tweaks tested as of Nov 18 2002 by jm: see SpamAssassin-devel list archives
# for results.  The winners are now the default settings.
use constant IGNORE_TITLE_CASE => 1;
use constant TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES => 1;
use constant TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;

# tweaks of May 12 2003, see SpamAssassin-devel archives again.
use constant PRE_CHEW_ADDR_HEADERS => 1;
use constant CHEW_BODY_URIS => 1;
use constant CHEW_BODY_MAILADDRS => 1;
use constant HDRS_TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;
use constant BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;
use constant IGNORE_MSGID_TOKENS => 0;

# tweaks of 12 March 2004, see bug 2129.
use constant DECOMPOSE_BODY_TOKENS => 1;
use constant MAP_HEADERS_MID => 1;
use constant MAP_HEADERS_FROMTOCC => 1;
use constant MAP_HEADERS_USERAGENT => 1;

# We store header-mined tokens in the db with a "HHeaderName:val" format.
# some headers may contain lots of gibberish tokens, so allow a little basic
# compression by mapping the header name at least here.  these are the headers
# which appear with the most frequency in my db.  note: this doesn't have to
# be 2-way (ie. LHSes that map to the same RHS are not a problem), but mixing
# tokens from multiple different headers may impact accuracy, so might as well
# avoid this if possible. These are the top ones from my corpus, BTW (jm).
%HEADER_NAME_COMPRESSION = (
  'Message-Id'		=> '*m',
  'Message-ID'		=> '*M',
  'Received'		=> '*r',
  'User-Agent'		=> '*u',
  'References'		=> '*f',
  'In-Reply-To'		=> '*i',
  'From'		=> '*F',
  'Reply-To'		=> '*R',
  'Return-Path'		=> '*p',
  'X-Mailer'		=> '*x',
  'X-Authentication-Warning' => '*a',
  'Organization'	=> '*o',
  'Organisation'        => '*o',
  'Content-Type'	=> '*c',
  'X-Spam-Relays-Trusted' => '*RT',
  'X-Spam-Relays-Untrusted' => '*RU',
);

# How many seconds should the opportunistic_expire lock be valid?
$OPPORTUNISTIC_LOCK_VALID = 300;

# Should we use the Robinson f(w) equation from
# http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html ?
# It gives better results, in that scores are more likely to distribute
# into the <0.5 range for nonspam and >0.5 for spam.
use constant USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS => 1;

# Value for 'x' in the f(w) equation.
# "Let x = the number used when n [hits] is 0."
use constant CHI_ROBINSON_X_CONSTANT  => 0.538;
use constant GARY_ROBINSON_X_CONSTANT => 0.600;

# Value for 's' in the f(w) equation.  "We can see s as the "strength" (hence
# the use of "s") of an original assumed expectation ... relative to how
# strongly we want to consider our actual collected data."  Low 's' means
# trust collected data more strongly.
use constant CHI_ROBINSON_S_CONSTANT  => 0.100;
use constant GARY_ROBINSON_S_CONSTANT => 0.160;

# Should we ignore tokens with probs very close to the middle ground (.5)?
# tokens need to be outside the [ .5-MPS, .5+MPS ] range to be used.
use constant CHI_ROBINSON_MIN_PROB_STRENGTH  => 0.346;
use constant GARY_ROBINSON_MIN_PROB_STRENGTH => 0.430;

# How many of the most significant tokens should we use for the p(w)
# calculation?
use constant N_SIGNIFICANT_TOKENS => 150;

# How many significant tokens are required for a classifier score to
# be considered usable?
use constant REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE => -1;

# How long a token should we hold onto?  (note: German speakers typically
# will require a longer token than English ones.)
use constant MAX_TOKEN_LENGTH => 15;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    'main'              => $main,
    'conf'		=> $main->{conf},
    'log_raw_counts'	=> 0,
    'use_ignores'       => 1,
    'tz'		=> Mail::SpamAssassin::Util::local_tz(),
  };
  bless ($self, $class);

  if ($self->{conf}->{bayes_store_module}) {
    my $module = $self->{conf}->{bayes_store_module};
    my $store;

    eval '
      require '.$module.';
      $store = '.$module.'->new($self);
    ';
    if ($@) { die $@; }
    $self->{store} = $store;
  }
  else {
    require Mail::SpamAssassin::BayesStore::DBM;
    $self->{store} = Mail::SpamAssassin::BayesStore::DBM->new($self);
  }

  $self;
}

###########################################################################

sub finish {
  my $self = shift;
  #if (!$self->{conf}->{use_bayes}) { return; }

  # if we're untying too much, uncomment this...
  # use Carp qw(cluck); cluck "stack trace at untie";

  $self->{store}->untie_db();
}

###########################################################################

sub sanity_check_is_untied {
  my $self = shift;

  # do a sanity check here.  Wierd things happen if we remain tied
  # after compiling; for example, spamd will never see that the
  # number of messages has reached the bayes-scanning threshold.
  if ($self->{store}->{already_tied} || $self->{store}->{is_locked}) {
    warn "SpamAssassin: oops! still tied/locked to bayes DBs, untie'ing\n";
    $self->{store}->untie_db();
  }
}

###########################################################################

# read configuration items to control bayes behaviour.  Called by
# BayesStore::read_db_configs().
sub read_db_configs {
  my ($self) = @_;

  # use of hapaxes.  Set on bayes object, since it controls prob
  # computation.
  $self->{use_hapaxes} = $self->{conf}->{bayes_use_hapaxes};

  # Use chi-squared combining instead of Gary-combining (Robinson/Graham-style
  # naive-Bayesian)?
  $self->{use_chi_sq_combining} = $self->{conf}->{bayes_use_chi2_combining};

  # Use the appropriate set of constants; the different systems have different
  # optimum settings for these.  (TODO: should these be exposed through Conf?)
  if ($self->{use_chi_sq_combining}) {
    $self->{robinson_x_constant} = CHI_ROBINSON_X_CONSTANT;
    $self->{robinson_s_constant} = CHI_ROBINSON_S_CONSTANT;
    $self->{robinson_min_prob_strength} = CHI_ROBINSON_MIN_PROB_STRENGTH;
  } else {
    $self->{robinson_x_constant} = GARY_ROBINSON_X_CONSTANT;
    $self->{robinson_s_constant} = GARY_ROBINSON_S_CONSTANT;
    $self->{robinson_min_prob_strength} = GARY_ROBINSON_MIN_PROB_STRENGTH;
  }

  $self->{robinson_s_times_x} =
      ($self->{robinson_x_constant} * $self->{robinson_s_constant});
}

###########################################################################

# The calling functions expect a uniq'ed array of tokens ...
sub tokenize {
  my ($self, $msg, $body) = @_;

  # Tokenize the body and put everything together
  my @tokens = map { $self->tokenize_line ($_, '', 1) } @{$body};

  # Tokenize the headers
  my %hdrs = $self->tokenize_headers ($msg);
  while( my($prefix, $value) = each %hdrs ) {
    push(@tokens, $self->tokenize_line ($value, "H$prefix:", 0));
  }

  # Go ahead and uniq the array
  my %tokens = map { $_ => 1 } @tokens;

  # return the keys == tokens ...
  keys %tokens;
}

sub tokenize_line {
  my $self = $_[0];
  my $tokprefix = $_[2];
  my $isbody = $_[3];
  local ($_) = $_[1];

  my @rettokens = ();

  my $in_headers = ($tokprefix ne '');

  # include quotes, .'s and -'s for URIs, and [$,]'s for Nigerian-scam strings,
  # and ISO-8859-15 alphas.  Do not split on @'s; better results keeping it.
  # Some useful tokens: "$31,000,000" "www.clock-speed.net" "f*ck" "Hits!"
  tr/-A-Za-z0-9,\@\*\!_'"\$.\241-\377 / /cs;

  # DO split on "..." or "--" or "---"; common formatting error resulting in
  # hapaxes.  Keep the separator itself as a token, though, as long ones can
  # be good spamsigns.
  s/(\w)(\.{3,6})(\w)/$1 $2 $3/gs;
  s/(\w)(\-{2,6})(\w)/$1 $2 $3/gs;

  if (IGNORE_TITLE_CASE) {
    if ($isbody) {
      # lower-case Title Case at start of a full-stop-delimited line (as would
      # be seen in a Western language).
      s/(?:^|\.\s+)([A-Z])([^A-Z]+)(?:\s|$)/ ' '. (lc $1) . $2 . ' ' /ge;
    }
  }

  # cache the magic token regexp...
  my $magic_re = $self->{store}->get_magic_re();

  foreach my $token (split) {
    $token =~ s/^[-'"\.,]+//;        # trim non-alphanum chars at start or end
    $token =~ s/[-'"\.,]+$//;        # so we don't get loads of '"foo' tokens

    # Skip false magic tokens
    # TVD: we need to do a defined() check since SQL doesn't have magic
    # tokens, so the SQL BayesStore returns undef.  I really want a way
    # of optimizing that out, but I haven't come up with anything yet.
    #
    next if ( defined $magic_re && /$magic_re/ );

    # *do* keep 3-byte tokens; there's some solid signs in there
    my $len = length($token);

    # but extend the stop-list. These are squarely in the gray
    # area, and it just slows us down to record them.
    next if $len < 3 ||
	($token =~ /^(?:a(?:nd|ny|ble|ll|re)|
		m(?:uch|ost|ade|ore|ail|ake|ailing|any|ailto)|
		t(?:his|he|ime|hrough|hat)|
		w(?:hy|here|ork|orld|ith|ithout|eb)|
		f(?:rom|or|ew)| e(?:ach|ven|mail)|
		o(?:ne|ff|nly|wn|ut)| n(?:ow|ot|eed)|
		s(?:uch|ame)| l(?:ook|ike|ong)|
		y(?:ou|our|ou're)|
		The|has|have|into|using|http|see|It's|it's|
		number|just|both|come|years|right|know|already|
		people|place|first|because|
		And|give|year|information|can)$/x);

    # are we in the body?  If so, apply some body-specific breakouts
    if (!$in_headers) {
      if (CHEW_BODY_MAILADDRS && $token =~ /\S\@\S/i) {
	push (@rettokens, $self->tokenize_mail_addrs ($token));
      }
      elsif (CHEW_BODY_URIS && $token =~ /\S\.[a-z]/i) {
	push (@rettokens, "UD:".$token); # the full token
	my $bit = $token; while ($bit =~ s/^[^\.]+\.(.+)$/$1/gs) {
	  push (@rettokens, "UD:".$1); # UD = URL domain
	}
      }

        if (DECOMPOSE_BODY_TOKENS) {
          my $decompd = $token;               # "Foo!"
          $decompd =~ s/[^\w:\*]//gs;
          push (@rettokens, $decompd);        # "Foo"
          $decompd = $token; $decompd = lc $decompd;
          push (@rettokens, $decompd);        # "foo!"
          $decompd =~ s/[^\w:\*]//gs;
          push (@rettokens, $decompd);        # "foo"
        }
    }

    # note: do not trim down overlong tokens if they contain '*'.  This is
    # used as part of split tokens such as "HTo:D*net" indicating that 
    # the domain ".net" appeared in the To header.
    #
    if ($len > MAX_TOKEN_LENGTH && $token !~ /\*/) {
      if (TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES && $token =~ /[\xa0-\xff]{2}/) {
	# Matt sez: "Could be asian? Autrijus suggested doing character ngrams,
	# but I'm doing tuples to keep the dbs small(er)."  Sounds like a plan
	# to me! (jm)
	while ($token =~ s/^(..?)//) {
	  push (@rettokens, "8:$1");
	}
	next;
      }

    if (($in_headers && HDRS_TOKENIZE_LONG_TOKENS_AS_SKIPS)
		|| (!$in_headers && BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS))
    {
	# if (TOKENIZE_LONG_TOKENS_AS_SKIPS) {
	# Spambayes trick via Matt: Just retain 7 chars.  Do not retain
	# the length, it does not help; see my mail to -devel of Nov 20 2002.
	# "sk:" stands for "skip".
	$token = "sk:".substr($token, 0, 7);
      }
    }

    push (@rettokens, $tokprefix.$token);
  }

  return @rettokens;
}

sub tokenize_headers {
  my ($self, $msg) = @_;

  my $hdrs = $msg->get_all_headers() . $msg->get_all_metadata();

  my %parsed = ();

  # we don't care about whitespace; so fix continuation lines to make the next
  # bit easier
  $hdrs =~ s/\n[ \t]+/ /gs;

  # first, keep a copy of Received hdrs, so we can strip down to last 2
  my @rcvdlines = ($hdrs =~ /^Received: [^\n]*$/gim);

  # and now delete lines for headers we don't want (incl all Receiveds)
  $hdrs =~ s/^${IGNORED_HDRS}: [^\n]*$//gim;

  if (IGNORE_MSGID_TOKENS) { $hdrs =~ s/^Message-I[dD]: [^\n]*$//gim;}

  # and re-add the last 2 received lines: usually a good source of
  # spamware tokens and HELO names.
  if ($#rcvdlines >= 0) { $hdrs .= "\n".$rcvdlines[$#rcvdlines]; }
  if ($#rcvdlines >= 1) { $hdrs .= "\n".$rcvdlines[$#rcvdlines-1]; }

  # remove user-specified headers here, after Received, in case they
  # want to ignore that too
  foreach my $conf (@{$self->{main}->{conf}->{bayes_ignore_headers}}) {
    $hdrs =~ s/^\Q${conf}\E: [^\n]*$//gim;
  }

  while ($hdrs =~ /^(\S+): ([^\n]*)$/gim) {
    my $hdr = $1;
    my $val = $2;

    # special tokenization for some headers:
    if ($hdr =~ /^(?:|X-|Resent-)Message-I[dD]$/) {
      $val = $self->pre_chew_message_id ($val);
    }
    elsif (PRE_CHEW_ADDR_HEADERS && $hdr =~ /^(?:|X-|Resent-)
	(?:Return-Path|From|To|Cc|Reply-To|Errors-To|Mail-Followup-To|Sender)$/ix)
    {
      $val = $self->pre_chew_addr_header ($val);
    }
    elsif ($hdr eq 'Received') {
      $val = $self->pre_chew_received ($val);
    }
    elsif ($hdr eq 'Content-Type') {
      $val = $self->pre_chew_content_type ($val);
    }
    elsif ($hdr eq 'MIME-Version') {
      $val =~ s/1\.0//;		# totally innocuous
    }
    elsif ($hdr =~ /^${MARK_PRESENCE_ONLY_HDRS}$/i) {
      $val = "1"; # just mark the presence, they create lots of hapaxen
    }

    if (MAP_HEADERS_MID) {
      if ($hdr eq 'In-Reply-To' || $hdr eq 'References' || $hdr =~ /^Message-Id/i)
      {
        $parsed{"*MI"} = $val;
      }
    }
    if (MAP_HEADERS_FROMTOCC) {
      if ($hdr =~ /^(?:From|To|Cc)$/i) {
        $parsed{"*Ad"} = $val;
      }
    }
    if (MAP_HEADERS_USERAGENT) {
      if ($hdr =~ /^(?:X-Mailer|User-Agent)$/) {
        $parsed{"*UA"} = $val;
      }
    }

    # replace hdr name with "compressed" version if possible
    if (defined $HEADER_NAME_COMPRESSION{$hdr}) {
      $hdr = $HEADER_NAME_COMPRESSION{$hdr};
    }

    if (exists $parsed{$hdr}) {
      $parsed{$hdr} .= " ".$val;
    } else {
      $parsed{$hdr} = $val;
    }
    dbg ("tokenize: header tokens for $hdr = \"$parsed{$hdr}\"");
  }

  return %parsed;
}

sub pre_chew_content_type {
  my ($self, $val) = @_;

  # hopefully this will retain good bits without too many hapaxen
  if ($val =~ s/boundary=[\"\'](.*?)[\"\']/ /ig) {
    my $boundary = $1;
    $boundary =~ s/[a-fA-F0-9]/H/gs;
    # break up blocks of separator chars so they become their own tokens
    $boundary =~ s/([-_\.=]+)/ $1 /gs;
    $val .= $boundary;
  }

  # stop-list words for Content-Type header: these wind up totally gray
  $val =~ s/\b(?:text|charset)\b//;

  $val;
}

sub pre_chew_message_id {
  my ($self, $val) = @_;
  # we can (a) get rid of a lot of hapaxen and (b) increase the token
  # specificity by pre-parsing some common formats.

  # Outlook Express format:
  $val =~ s/<([0-9a-f]{4})[0-9a-f]{4}[0-9a-f]{4}\$
           ([0-9a-f]{4})[0-9a-f]{4}\$
           ([0-9a-f]{8})\@(\S+)>/ OEA$1 OEB$2 OEC$3 $4 /gx;

  # Exim:
  $val =~ s/<[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]\@//;

  # Sendmail:
  $val =~ s/<20\d\d[01]\d[0123]\d[012]\d[012345]\d[012345]\d\.
           [A-F0-9]{10,12}\@//gx;

  # try to split Message-ID segments on probable ID boundaries. Note that
  # Outlook message-ids seem to contain a server identifier ID in the last
  # 8 bytes before the @.  Make sure this becomes its own token, it's a
  # great spam-sign for a learning system!  Be sure to split on ".".
  $val =~ s/[^_A-Za-z0-9]/ /g;
  $val;
}

sub pre_chew_received {
  my ($self, $val) = @_;

  # Thanks to Dan for these.  Trim out "useless" tokens; sendmail-ish IDs
  # and valid-format RFC-822/2822 dates

  $val =~ s/\swith\sSMTP\sid\sg[\dA-Z]{10,12}\s/ /gs;  # Sendmail
  $val =~ s/\swith\sESMTP\sid\s[\dA-F]{10,12}\s/ /gs;  # Sendmail
  $val =~ s/\bid\s[a-zA-Z0-9]{7,20}\b/ /gs;    # Sendmail
  $val =~ s/\bid\s[A-Za-z0-9]{7}-[A-Za-z0-9]{6}-0[A-Za-z0-9]/ /gs; # exim

  $val =~ s/(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?
           [0-3\s]?[0-9]\s
           (?:Jan|Feb|Ma[ry]|Apr|Ju[nl]|Aug|Sep|Oct|Nov|Dec)\s
           (?:19|20)?[0-9]{2}\s
           [0-2][0-9](?:\:[0-5][0-9]){1,2}\s
           (?:\s*\(|\)|\s*(?:[+-][0-9]{4})|\s*(?:UT|[A-Z]{2,3}T))*
           //gx;

  # IPs: break down to nearest /24, to reduce hapaxes -- EXCEPT for
  # IPs in the 10 and 192.168 ranges, they gets lots of significant tokens
  # (on both sides)
  # also make a dup with the full IP, as fodder for
  # bayes_dump_to_trusted_networks: "H*r:ip*aaa.bbb.ccc.ddd"
  $val =~ s{\b(\d{1,3}\.)(\d{1,3}\.)(\d{1,3})(\.\d{1,3})\b}{
           if ($2 eq '10' || ($2 eq '192' && $3 eq '168')) {
             $1.$2.$3.$4.
		" ip*".$1.$2.$3.$4." ";
           } else {
             $1.$2.$3.
		" ip*".$1.$2.$3.$4." ";
           }
         }gex;

  # trim these: they turn out as the most common tokens, but with a
  # prob of about .5.  waste of space!
  $val =~ s/\b(?:with|from|for|SMTP|ESMTP)\b/ /g;

  $val;
}

sub pre_chew_addr_header {
  my ($self, $val) = @_;
  local ($_);

  my @addrs = $self->{main}->find_all_addrs_in_line ($val);
  my @toks = ();
  foreach (@addrs) {
    push (@toks, $self->tokenize_mail_addrs ($_));
  }
  return join (' ', @toks);
}

sub tokenize_mail_addrs {
  my ($self, $addr) = @_;

  ($addr =~ /(.+)\@(.+)$/) or return ();
  my @toks = ();
  push(@toks, "U*".$1, "D*".$2);
  $_ = $2; while (s/^[^\.]+\.(.+)$/$1/gs) { push(@toks, "D*".$1); }
  return @toks;
}

###########################################################################

sub ignore_message {
  my ($Bayes,$PMS) = @_;

  return 0 unless $Bayes->{use_ignores};

  my $ignore = $PMS->check_from_in_list('bayes_ignore_from')
    		|| $PMS->check_to_in_list('bayes_ignore_to');

  dbg("Not using Bayes, bayes_ignore_from or _to rule") if $ignore;

  return $ignore;
}

###########################################################################

sub learn {
  my ($self, $isspam, $msg, $id) = @_;

  if (!$self->{conf}->{use_bayes}) { return; }
  if (!defined $msg) { return; }

  if( $self->{use_ignores} )  # Remove test when PerMsgStatus available.
  {
    # DMK, koppel@ece.lsu.edu:  Hoping that the ultimate fix to bug 2263 will
    # make it unnecessary to construct a PerMsgStatus here.
    my $PMS = new Mail::SpamAssassin::PerMsgStatus $self->{main}, $msg;
    my $ignore = $self->ignore_message($PMS);
    $PMS->finish();
    return if $ignore;
  }

  $msg->extract_message_metadata ($self->{main});
  my $body = $self->get_body_from_msg ($msg);
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    my $ok;
    if ($self->{main}->{learn_to_journal}) {
      # If we're going to learn to journal, we'll try going r/o first...
      # If that fails for some reason, let's try going r/w.  This happens
      # if the DB doesn't exist yet.
      $ok = $self->{store}->tie_db_readonly() || $self->{store}->tie_db_writable();
    } else {
      $ok = $self->{store}->tie_db_writable();
    }

    if ($ok) {
      $ret = $self->learn_trapped ($isspam, $msg, $body, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->{store}->untie_db();
    die $failure;
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub learn_trapped {
  my ($self, $isspam, $msg, $body, $msgid) = @_;
  my @msgid = ( $msgid );

  if (!defined $msgid) {
    @msgid = $self->get_msgid($msg);
  }

  foreach $msgid ( @msgid ) {
    my $seen = $self->{store}->seen_get ($msgid);

    if (defined ($seen)) {
      if (($seen eq 's' && $isspam) || ($seen eq 'h' && !$isspam)) {
        dbg ("$msgid: already learnt correctly, not learning twice");
        return 0;
      } elsif ($seen !~ /^[hs]$/) {
        warn ("db_seen corrupt: value='$seen' for $msgid. ignored");
      } else {
        dbg ("$msgid: already learnt as opposite, forgetting first");

        # kluge so that forget() won't untie the db on us ...
        my $orig = $self->{main}->{learn_caller_will_untie};
        $self->{main}->{learn_caller_will_untie} = 1;

        my $fatal = !defined $self->forget ($msg);

        # reset the value post-forget() ...
        $self->{main}->{learn_caller_will_untie} = $orig;
    
        # forget() gave us a fatal error, so propagate that up
        if ($fatal) {
          dbg("forget() returned a fatal error, so learn() will too");
	  return;
        }
      }

      # we're only going to have seen this once, so stop if it's been
      # seen already
      last;
    }
  }

  # Now that we're sure we haven't seen this message before ...
  $msgid = $msgid[0];

  if ($isspam) {
    $self->{store}->nspam_nham_change (1, 0);
  } else {
    $self->{store}->nspam_nham_change (0, 1);
  }

  my $msgatime = $self->receive_date(scalar $msg->get_all_headers(0,1));

  # If the message atime comes back as being more than 1 day in the
  # future, something's messed up and we should revert to current time as
  # a safety measure.
  #
  $msgatime = time if ( $msgatime - time > 86400 );

  for ($self->tokenize ($msg, $body)) {
    if ($isspam) {
      $self->{store}->tok_count_change (1, 0, $_, $msgatime);
    } else {
      $self->{store}->tok_count_change (0, 1, $_, $msgatime);
    }
  }

  $self->{store}->seen_put ($msgid, ($isspam ? 's' : 'h'));
  $self->{store}->cleanup();
  dbg("bayes: Learned '$msgid', atime: $msgatime");

  1;
}

###########################################################################

sub forget {
  my ($self, $msg, $id) = @_;

  if (!$self->{conf}->{use_bayes}) { return; }
  if (!defined $msg) { return; }

  $msg->extract_message_metadata ($self->{main});
  my $body = $self->get_body_from_msg ($msg);
  my $ret;

  # we still tie for writing here, since we write to the seen db
  # synchronously
  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    my $ok;
    if ($self->{main}->{learn_to_journal}) {
      # If we're going to learn to journal, we'll try going r/o first...
      # If that fails for some reason, let's try going r/w.  This happens
      # if the DB doesn't exist yet.
      $ok = $self->{store}->tie_db_readonly() || $self->{store}->tie_db_writable();
    } else {
      $ok = $self->{store}->tie_db_writable();
    }

    if ($ok) {
      $ret = $self->forget_trapped ($msg, $body, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->{store}->untie_db();
    die $failure;
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub forget_trapped {
  my ($self, $msg, $body, $msgid) = @_;
  my @msgid = ( $msgid );
  my $isspam;

  if (!defined $msgid) {
    @msgid = $self->get_msgid($msg);
  }

  while( $msgid = shift @msgid ) {
    my $seen = $self->{store}->seen_get ($msgid);

    if (defined ($seen)) {
      if ($seen eq 's') {
        $isspam = 1;
      } elsif ($seen eq 'h') {
        $isspam = 0;
      } else {
        dbg ("forget: msgid $msgid seen entry is neither ham nor spam, ignored");
        return 0;
      }

      # messages should only be learned once, so stop if we find a msgid
      # which was seen before
      last;
    }
    else {
      dbg ("forget: msgid $msgid not learnt, ignored");
    }
  }

  # This message wasn't learnt before, so return
  if (!defined $isspam) {
    dbg("forget: no msgid from this message has been learnt, skipping message");
    return 0;
  }
  elsif ($isspam) {
    $self->{store}->nspam_nham_change (-1, 0);
  }
  else {
    $self->{store}->nspam_nham_change (0, -1);
  }

  for ($self->tokenize ($msg, $body)) {
    if ($isspam) {
      $self->{store}->tok_count_change (-1, 0, $_);
    } else {
      $self->{store}->tok_count_change (0, -1, $_);
    }
  }

  $self->{store}->seen_delete ($msgid);
  $self->{store}->cleanup();
  1;
}

###########################################################################

sub get_msgid {
  my ($self, $msg) = @_;

  my @msgid = ();

  my $msgid = $msg->get_header("Message-Id");
  if (defined $msgid && $msgid ne '' && $msgid !~ /^\s*<\s*(?:\@sa_generated)?>.*$/) {
    # remove \r and < and > prefix/suffixes
    chomp $msgid;
    $msgid =~ s/^<//; $msgid =~ s/>.*$//g;
    push(@msgid, $msgid);
  }

  # Use sha1(Date:, last received: and top N bytes of body)
  # where N is MIN(1024 bytes, 1/2 of body length)
  #
  my $date = $msg->get_header("Date");
  $date = "None" if (!defined $date || $date eq ''); # No Date?

  my @rcvd = $msg->get_header("Received");
  my $rcvd = $rcvd[$#rcvd];
  $rcvd = "None" if (!defined $rcvd || $rcvd eq ''); # No Received?

  # Make a copy since pristine_body is a reference ...
  my $body = join('', $msg->get_pristine_body());
  if (length($body) > 64) { # Small Body?
    my $keep = ( length $body > 2048 ? 1024 : int(length($body) / 2) );
    substr($body, $keep) = '';
  }

  unshift(@msgid, sha1($date."\000".$rcvd."\000".$body).'@sa_generated');

  return wantarray ? @msgid : $msgid[0];
}

sub add_uris_for_permsgstatus {
  my ($self, $permsgstatus) = @_;
  return $permsgstatus->get_uri_list();
}

sub get_body_from_msg {
  my ($self, $msg) = @_;

  if (!ref $msg) {
    # I have no idea why this seems to happen. TODO
    warn "msg not a ref: '$msg'";
    return [ ];
  }
  $msg->extract_message_metadata ($self->{main});
  my $permsgstatus =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);

  my $body = $msg->get_rendered_body_text_array();
  # TODO! also add URI extraction to {metadata}
  push (@{$body}, $self->add_uris_for_permsgstatus($permsgstatus));
  $permsgstatus->finish();

  if (!defined $body) {
    # why?!
    warn "failed to get body for ".scalar($self->get_msgid($self->{msg}))."\n";
    return [ ];
  }

  return $body;
}

###########################################################################

sub sync {
  my ($self, $sync, $expire, $opts) = @_;
  if (!$self->{conf}->{use_bayes}) { return 0; }

  dbg("Syncing Bayes and expiring old tokens...");
  $self->{store}->sync($opts) if ( $sync );
  $self->{store}->expire_old_tokens($opts) if ( $expire );
  dbg("Syncing complete.");

  return 0;
}

###########################################################################

# compute the probability that that token is spammish
sub compute_prob_for_token {
  my ($self, $token, $ns, $nn, $s, $n, $atime) = @_;

  # we allow the caller to give us the token information, just
  # to save a potentially expensive lookup
  if (!defined($s) || !defined($n) || !defined($atime)) {
    ($s, $n, $atime) = $self->{store}->tok_get ($token);
  }
  return if ($s == 0 && $n == 0);

  if (!USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    return if ($s + $n < 10);      # ignore low-freq tokens
  }

  if (!$self->{use_hapaxes}) {
    return if ($s + $n < 2);
  }

  return if ( $ns == 0 || $nn == 0 );

  my $ratios = ($s / $ns);
  my $ration = ($n / $nn);

  my $prob;

  if ($ratios == 0 && $ration == 0) {
    warn "oops? ratios == ration == 0";
    return;
  } else {
    $prob = ($ratios) / ($ration + $ratios);
  }

  if (USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    # use Robinson's f(x) equation for low-n tokens, instead of just
    # ignoring them
    my $robn = $s+$n;
    $prob = ($self->{robinson_s_times_x} + ($robn * $prob))
                             /
		  ($self->{robinson_s_constant} + $robn);
  }

  if ($self->{log_raw_counts}) {
    $self->{raw_counts} .= " s=$s,n=$n ";
  }

  return $prob;
}

# Check to make sure we can tie() the DB, and we have enough entries to do a scan
sub is_scan_available {
  my $self = shift;

  return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  if ($ns < $self->{conf}->{bayes_min_spam_num}) {
    dbg("bayes: Not available for scanning, only $ns spam(s) in Bayes DB < ".$self->{conf}->{bayes_min_spam_num});
    $self->{store}->untie_db();
    return 0;
  }
  if ($nn < $self->{conf}->{bayes_min_ham_num}) {
    dbg("bayes: Not available for scanning, only $nn ham(s) in Bayes DB < ".$self->{conf}->{bayes_min_ham_num});
    $self->{store}->untie_db();
    return 0;
  }

  return 1;
}

###########################################################################
# Finally, the scoring function for testing mail.

sub scan {
  my ($self, $permsgstatus, $msg, $body) = @_;
  my $score;

  if( $self->ignore_message($permsgstatus) ) {
    goto skip;
  }

  goto skip unless $self->is_scan_available();

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  if ($self->{log_raw_counts}) {
    $self->{raw_counts} = " ns=$ns nn=$nn ";
  }

  dbg ("bayes corpus size: nspam = $ns, nham = $nn");

  # Add URIs to the body ...
  push (@{$body}, $self->add_uris_for_permsgstatus ($permsgstatus));

  # Figure out our probabilities for the message tokens
  my %pw = map {
      my $pw = $self->compute_prob_for_token ($_, $ns, $nn);
      if (!defined $pw) {
	();		# exit map()
      } else {
	($_ => $pw);
      }
  } $self->tokenize ($msg, $body);

  # If none of the tokens were found in the DB, we're going to skip
  # this message...
  if (!keys %pw) {
    dbg ("cannot use bayes on this message; none of the tokens were found in the database");
    goto skip;
  }

  # Figure out the message receive time (used as atime below)
  # If the message atime comes back as being in the future, something's
  # messed up and we should revert to current time as a safety measure.
  #
  my $msgatime = $self->receive_date(scalar $msg->get_all_headers(0,1));
  $msgatime = time if ( $msgatime > time );

  # now take the $count most significant tokens and calculate probs using
  # Robinson's formula.
  my $count = N_SIGNIFICANT_TOKENS;
  my @sorted = ();

  for (sort {
              abs($pw{$b} - 0.5) <=> abs($pw{$a} - 0.5)
            } keys %pw)
  {
    if ($count-- < 0) { last; }
    my $pw = $pw{$_};
    next if (abs($pw - 0.5) < $self->{robinson_min_prob_strength});
    push (@sorted, $pw);

    # update the atime on this token, it proved useful
    $self->{store}->tok_touch ($_, $msgatime);

    dbg ("bayes token '$_' => $pw");
  }

  if (!@sorted || (REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE > 0 && 
	$#sorted <= REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE))
  {
    dbg ("cannot use bayes on this message; not enough usable tokens found");
    goto skip;
  }

  if ($self->{use_chi_sq_combining}) {
    $score = chi_squared_probs_combine ($ns, $nn, @sorted);
  } else {
    $score = robinson_naive_bayes_probs_combine (@sorted);
  }

  # Couldn't come up with a probability?
  goto skip unless defined $score;

  dbg ("bayes: score = $score");

  if ($self->{log_raw_counts}) {
    print "#Bayes-Raw-Counts: $self->{raw_counts}\n";
  }

skip:
  if (!defined $score) {
    dbg ("bayes: not scoring message, returning undef");
  }

  $self->{store}->cleanup();
  $self->opportunistic_calls();
  $self->{store}->untie_db();

  return $score;
}

sub opportunistic_calls {
  my($self) = @_;

  # Is an expire or sync running?
  my $running_expire = $self->{store}->get_running_expire_tok();
  if ( defined $running_expire && $running_expire+$OPPORTUNISTIC_LOCK_VALID > time() ) { return; }

  # handle expiry and syncing
  if ($self->{store}->expiry_due()) {
    $self->{store}->set_running_expire_tok();
    $self->sync(1,1);
    # don't need to unlock since the expire will have done that. ;)
  }
  elsif ( $self->{store}->sync_due() ) {
    $self->{store}->set_running_expire_tok();
    $self->sync(1,0);
    $self->{store}->remove_running_expire_tok();
  }
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

sub robinson_naive_bayes_probs_combine {
  my (@sorted) = @_;

  my $wc = scalar @sorted;
  return unless $wc;

  my $P = 1;
  my $Q = 1;

  foreach my $pw (@sorted) {
    $P *= (1-$pw);
    $Q *= $pw;
  }
  $P = 1 - ($P ** (1 / $wc));
  $Q = 1 - ($Q ** (1 / $wc));
  return (1 + ($P - $Q) / ($P + $Q)) / 2.0;
}

###########################################################################

# Chi-squared function
sub chi2q {
  my ($x2, $v) = @_;

  die "v must be even in chi2q(x2, v)" if $v & 1;
  my $m = $x2 / 2.0;
  my ($sum, $term);
  $sum = $term = exp(0 - $m);
  for my $i (1 .. (($v/2)-1)) {
    $term *= $m / $i;
    $sum += $term;
  }
  return $sum < 1.0 ? $sum : 1.0;
}

# Chi-Squared method. Produces mostly boolean $result,
# but with a grey area.
sub chi_squared_probs_combine  {
  my ($ns, $nn, @sorted) = @_;
  # @sorted contains an array of the probabilities
  my $wc = scalar @sorted;
  return unless $wc;

  my ($H, $S);
  my ($Hexp, $Sexp);
  $Hexp = $Sexp = 0;

  # see bug 3118
  my $totmsgs = ($ns + $nn);
  if ($totmsgs == 0) { return; }
  $S = ($ns / $totmsgs);
  $H = ($nn / $totmsgs);

  use POSIX qw(frexp);

  foreach my $prob (@sorted) {
    $S *= 1.0 - $prob;
    $H *= $prob;
    if ($S < 1e-200) {
      my $e;
      ($S, $e) = frexp($S);
      $Sexp += $e;
    }
    if ($H < 1e-200) {
      my $e;
      ($H, $e) = frexp($H);
      $Hexp += $e;
    }
  }

  use constant LN2 => log(2);

  $S = log($S) + $Sexp * LN2;
  $H = log($H) + $Hexp * LN2;

  $S = 1.0 - chi2q(-2.0 * $S, 2 * $wc);
  $H = 1.0 - chi2q(-2.0 * $H, 2 * $wc);
  return (($S - $H) + 1.0) / 2.0;
}

###########################################################################

sub dump_bayes_db {
  my($self, $magic, $toks, $regex) = @_;

  # allow dump to occur even if use_bayes disables everything else ...
  #return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();
  
  my @vars = $self->{store}->get_storage_variables();

  my($sb,$ns,$nh,$nt,$le,$oa,$bv,$js,$ad,$er,$na) = @vars;

  my $template = '%3.3f %10d %10d %10d  %s'."\n";

  if ( $magic ) {
    printf ($template, 0.0, 0, $bv, 0, 'non-token data: bayes db version');
    printf ($template, 0.0, 0, $ns, 0, 'non-token data: nspam');
    printf ($template, 0.0, 0, $nh, 0, 'non-token data: nham');
    printf ($template, 0.0, 0, $nt, 0, 'non-token data: ntokens');
    printf ($template, 0.0, 0, $oa, 0, 'non-token data: oldest atime');
    printf ($template, 0.0, 0, $na, 0, 'non-token data: newest atime') if ( $bv >= 2 );
    printf ($template, 0.0, 0, $sb, 0, 'non-token data: current scan-count') if ( $bv < 2 );
    printf ($template, 0.0, 0, $js, 0, 'non-token data: last journal sync atime') if ( $bv >= 2 );
    printf ($template, 0.0, 0, $le, 0, 'non-token data: last expiry atime');
    if ( $bv >= 2 ) {
      printf ($template, 0.0, 0, $ad, 0, 'non-token data: last expire atime delta');
      printf ($template, 0.0, 0, $er, 0, 'non-token data: last expire reduction count');
    }
  }

  if ( $toks ) {
    # let the store sort out the db_toks
    $self->{store}->dump_db_toks($template, $regex, @vars);
  }

  if (!$self->{main}->{learn_caller_will_untie}) {
    $self->{store}->untie_db();
  }
}

# Stolen from Archive Iteraator ...  Should probably end up in M::SA::Util
# Modified to call first_date via $self->first_date()
sub receive_date {
  my ($self, $header) = @_;

  $header ||= '';
  $header =~ s/\n[ \t]+/ /gs;	# fix continuation lines

  my @rcvd = ($header =~ /^Received:(.*)/img);
  my @local;
  my $time;

  if (@rcvd) {
    if ($rcvd[0] =~ /qmail \d+ invoked by uid \d+/ ||
	$rcvd[0] =~ /\bfrom (?:localhost\s|(?:\S+ ){1,2}\S*\b127\.0\.0\.1\b)/)
    {
      push @local, (shift @rcvd);
    }
    if (@rcvd && ($rcvd[0] =~ m/\bby localhost with \w+ \(fetchmail-[\d.]+/)) {
      push @local, (shift @rcvd);
    }
    elsif (@local) {
      unshift @rcvd, (shift @local);
    }
  }

  if (@rcvd) {
    $time = $self->first_date(shift @rcvd);
    return $time if defined($time);
  }
  if (@local) {
    $time = $self->first_date(@local);
    return $time if defined($time);
  }
  if ($header =~ /^(?:From|X-From-Line:)\s+(.+)$/im) {
    my $string = $1;
    $string .= " ".$self->{tz} unless $string =~ /(?:[-+]\d{4}|\b[A-Z]{2,4}\b)/;
    $time = $self->first_date($string);
    return $time if defined($time);
  }
  if (@rcvd) {
    $time = $self->first_date(@rcvd);
    return $time if defined($time);
  }
  if ($header =~ /^Resent-Date:\s*(.+)$/im) {
    $time = $self->first_date($1);
    return $time if defined($time);
  }
  if ($header =~ /^Date:\s*(.+)$/im) {
    $time = $self->first_date($1);
    return $time if defined($time);
  }

  return time;
}

sub first_date {
  my ($self, @strings) = @_;

  foreach my $string (@strings) {
    my $time = Mail::SpamAssassin::Util::parse_rfc822_date($string);
    return $time if defined($time) && $time;
  }
  return undef;
}

1;
