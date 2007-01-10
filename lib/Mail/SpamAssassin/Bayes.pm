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

=head1 NAME

Mail::SpamAssassin::Bayes - determine spammishness using a Bayesian classifier

=head1 DESCRIPTION

This is a Bayesian-like form of probability-analysis classification, using an
algorithm based on the one detailed in Paul Graham's I<A Plan For Spam> paper
at:

  http://www.paulgraham.com/spam.html

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
use warnings;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Logger;

# pick ONLY ONE of these combining implementations.
use Mail::SpamAssassin::Bayes::CombineChi;
# use Mail::SpamAssassin::Bayes::CombineNaiveBayes;

use Digest::SHA1 qw(sha1 sha1_hex);

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

# Received is handled specially
$IGNORED_HDRS = qr{(?: (?:X-)?Sender    # misc noise
  |Delivered-To |Delivery-Date
  |(?:X-)?Envelope-To
  |X-MIME-Auto[Cc]onverted |X-Converted-To-Plain-Text

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
  |X-Bogosity

  # some noisy Outlook headers that add no good clues:
  |Content-Class |Thread-(?:Index|Topic)
  |X-Original[Aa]rrival[Tt]ime

  # Annotations from IMAP, POP, and MH:
  |(?:X-)?Status |X-Flags |Replied |Forwarded
  |Lines |Content-Length
  |X-UIDL? |X-IMAPbase

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
use constant URIS_TOKENIZE_LONG_TOKENS_AS_SKIPS => 0;
use constant IGNORE_MSGID_TOKENS => 0;

# tweaks of 12 March 2004, see bug 2129.
use constant DECOMPOSE_BODY_TOKENS => 1;
use constant MAP_HEADERS_MID => 1;
use constant MAP_HEADERS_FROMTOCC => 1;
use constant MAP_HEADERS_USERAGENT => 1;

# tweaks, see http://issues.apache.org/SpamAssassin/show_bug.cgi?id=3173#c26
use constant ADD_INVIZ_TOKENS_I_PREFIX => 1;
use constant ADD_INVIZ_TOKENS_NO_PREFIX => 0;

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
  'Return-path'		=> '*rp',
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
    ## 'log_raw_counts'	=> 0, # see compute_prob_for_token()
    'use_ignores'       => 1,
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

sub finish {
  my $self = shift;
  #if (!$self->{conf}->{use_bayes}) { return; }

  # if we're untying too much, uncomment this...
  # use Carp qw(cluck); cluck "stack trace at untie";

  $self->{store}->untie_db();
  %{$self} = ();
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

sub sanity_check_is_untied {
  my $self = shift;
  my $quiet = shift;

  # do a sanity check here.  Wierd things happen if we remain tied
  # after compiling; for example, spamd will never see that the
  # number of messages has reached the bayes-scanning threshold.
  if ($self->{store}->db_readable()) {
    warn "bayes: oops! still tied to bayes DBs, untying\n" unless $quiet;
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
}

###########################################################################

# The calling functions expect a uniq'ed array of tokens ...
sub tokenize {
  my ($self, $msg, $msgdata) = @_;

  # the body
  my @tokens = map { $self->tokenize_line ($_, '', 1) }
                                    @{$msgdata->{bayes_token_body}};

  # the URI list
  push (@tokens, map { $self->tokenize_line ($_, '', 2) }
                                    @{$msgdata->{bayes_token_uris}});

  # add invisible tokens
  if (ADD_INVIZ_TOKENS_I_PREFIX) {
    push (@tokens, map { $self->tokenize_line ($_, "I*:", 1) }
                                    @{$msgdata->{bayes_token_inviz}});
  }
  if (ADD_INVIZ_TOKENS_NO_PREFIX) {
    push (@tokens, map { $self->tokenize_line ($_, "", 1) }
                                    @{$msgdata->{bayes_token_inviz}});
  }

  # Tokenize the headers
  my %hdrs = $self->tokenize_headers ($msg);
  while( my($prefix, $value) = each %hdrs ) {
    push(@tokens, $self->tokenize_line ($value, "H$prefix:", 0));
  }

  # Go ahead and uniq the array, skip null tokens (can happen sometimes)
  # generate an SHA1 hash and take the lower 40 bits as our token
  my %tokens;
  foreach my $token (@tokens) {
    next unless length($token); # skip 0 length tokens
    $tokens{substr(sha1($token), -5)} = $token;
  }

  # return the keys == tokens ...
  return \%tokens;
}

sub tokenize_line {
  my $self = $_[0];
  my $tokprefix = $_[2];
  my $region = $_[3];
  local ($_) = $_[1];

  my @rettokens = ();

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
    if ($region == 1 || $region == 2) {
      # lower-case Title Case at start of a full-stop-delimited line (as would
      # be seen in a Western language).
      s/(?:^|\.\s+)([A-Z])([^A-Z]+)(?:\s|$)/ ' '. (lc $1) . $2 . ' ' /ge;
    }
  }

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
    # See http://wiki.apache.org/spamassassin/BayesStopList for more info.
    #
    next if $len < 3 ||
	($token =~ /^(?:a(?:ble|l(?:ready|l)|n[dy]|re)|b(?:ecause|oth)|c(?:an|ome)|e(?:ach|mail|ven)|f(?:ew|irst|or|rom)|give|h(?:a(?:ve|s)|ttp)|i(?:n(?:formation|to)|t\'s)|just|know|l(?:ike|o(?:ng|ok))|m(?:a(?:de|il(?:(?:ing|to))?|ke|ny)|o(?:re|st)|uch)|n(?:eed|o[tw]|umber)|o(?:ff|n(?:ly|e)|ut|wn)|p(?:eople|lace)|right|s(?:ame|ee|uch)|t(?:h(?:at|is|rough|e)|ime)|using|w(?:eb|h(?:ere|y)|ith(?:out)?|or(?:ld|k))|y(?:ears?|ou(?:(?:\'re|r))?))$/i);

    # are we in the body?  If so, apply some body-specific breakouts
    if ($region == 1 || $region == 2) {
      if (CHEW_BODY_MAILADDRS && $token =~ /\S\@\S/i) {
	push (@rettokens, $self->tokenize_mail_addrs ($token));
      }
      elsif (CHEW_BODY_URIS && $token =~ /\S\.[a-z]/i) {
	push (@rettokens, "UD:".$token); # the full token
	my $bit = $token; while ($bit =~ s/^[^\.]+\.(.+)$/$1/gs) {
	  push (@rettokens, "UD:".$1); # UD = URL domain
	}
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

      if (($region == 0 && HDRS_TOKENIZE_LONG_TOKENS_AS_SKIPS)
            || ($region == 1 && BODY_TOKENIZE_LONG_TOKENS_AS_SKIPS)
            || ($region == 2 && URIS_TOKENIZE_LONG_TOKENS_AS_SKIPS))
      {
	# if (TOKENIZE_LONG_TOKENS_AS_SKIPS)
	# Spambayes trick via Matt: Just retain 7 chars.  Do not retain
	# the length, it does not help; see my mail to -devel of Nov 20 2002.
	# "sk:" stands for "skip".
	$token = "sk:".substr($token, 0, 7);
      }
    }

    # decompose tokens?  do this after shortening long tokens
    if ($region == 1 || $region == 2) {
      if (DECOMPOSE_BODY_TOKENS) {
        if ($token =~ /[^\w:\*]/) {
          my $decompd = $token;                        # "Foo!"
          $decompd =~ s/[^\w:\*]//gs;
          push (@rettokens, $tokprefix.$decompd);      # "Foo"
        }

        if ($token =~ /[A-Z]/) {
          my $decompd = $token; $decompd = lc $decompd;
          push (@rettokens, $tokprefix.$decompd);      # "foo!"

          if ($token =~ /[^\w:\*]/) {
            $decompd =~ s/[^\w:\*]//gs;
            push (@rettokens, $tokprefix.$decompd);    # "foo"
          }
        }
      }
    }

    push (@rettokens, $tokprefix.$token);
  }

  return @rettokens;
}

sub tokenize_headers {
  my ($self, $msg) = @_;

  my %parsed = ();

  my %user_ignore;
  $user_ignore{lc $_} = 1 for @{$self->{main}->{conf}->{bayes_ignore_headers}};

  # get headers in array context
  my @hdrs;
  my @rcvdlines;
  for ($msg->get_all_headers()) {
    # first, keep a copy of Received headers, so we can strip down to last 2
    if (/^Received:/i) {
      push(@rcvdlines, $_);
      next;
    }
    # and now skip lines for headers we don't want (including all Received)
    next if /^${IGNORED_HDRS}:/i;
    next if IGNORE_MSGID_TOKENS && /^Message-ID:/i;
    push(@hdrs, $_);
  }
  push(@hdrs, $msg->get_all_metadata());

  # and re-add the last 2 received lines: usually a good source of
  # spamware tokens and HELO names.
  if ($#rcvdlines >= 0) { push(@hdrs, $rcvdlines[$#rcvdlines]); }
  if ($#rcvdlines >= 1) { push(@hdrs, $rcvdlines[$#rcvdlines-1]); }

  for (@hdrs) {
    next unless /\S/;
    my ($hdr, $val) = split(/:/, $_, 2);

    # remove user-specified headers here, after Received, in case they
    # want to ignore that too
    next if exists $user_ignore{lc $hdr};

    # Prep the header value
    $val ||= '';
    chomp($val);

    # special tokenization for some headers:
    if ($hdr =~ /^(?:|X-|Resent-)Message-Id$/i) {
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
      if ($hdr =~ /^(?:In-Reply-To|References|Message-ID)$/i) {
        $parsed{"*MI"} = $val;
      }
    }
    if (MAP_HEADERS_FROMTOCC) {
      if ($hdr =~ /^(?:From|To|Cc)$/i) {
        $parsed{"*Ad"} = $val;
      }
    }
    if (MAP_HEADERS_USERAGENT) {
      if ($hdr =~ /^(?:X-Mailer|User-Agent)$/i) {
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
    if (would_log('dbg', 'bayes') > 1) {
      dbg("bayes: header tokens for $hdr = \"$parsed{$hdr}\"");
    }
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
  my ($self,$PMS) = @_;

  return 0 unless $self->{use_ignores};

  my $ig_from = $self->{main}->call_plugins ("check_wb_list", { permsgstatus => $PMS, type => 'from', list => 'bayes_ignore_from' });
  my $ig_to = $self->{main}->call_plugins ("check_wb_list", { permsgstatus => $PMS, type => 'to', list => 'bayes_ignore_to' });

  my $ignore = $ig_from || $ig_to;

  dbg("bayes: not using bayes, bayes_ignore_from or _to rule") if $ignore;

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
    return 0 if $ignore;
  }

  my $msgdata = $self->get_body_from_msg ($msg);
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
      $ret = $self->learn_trapped ($isspam, $msg, $msgdata, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->{store}->untie_db();
    die "bayes: $failure";
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub learn_trapped {
  my ($self, $isspam, $msg, $msgdata, $msgid) = @_;
  my @msgid = ( $msgid );

  if (!defined $msgid) {
    @msgid = $self->get_msgid($msg);
  }

  foreach $msgid ( @msgid ) {
    my $seen = $self->{store}->seen_get ($msgid);

    if (defined ($seen)) {
      if (($seen eq 's' && $isspam) || ($seen eq 'h' && !$isspam)) {
        dbg("bayes: $msgid already learnt correctly, not learning twice");
        return 0;
      } elsif ($seen !~ /^[hs]$/) {
        warn("bayes: db_seen corrupt: value='$seen' for $msgid, ignored");
      } else {
        # bug 3704: If the message was already learned, don't try learning it again.
        # this prevents, for instance, manually learning as spam, then autolearning
        # as ham, or visa versa.
        if ($self->{main}->{learn_no_relearn}) {
	  dbg("bayes: $msgid already learnt as opposite, not re-learning");
	  return 0;
	}

        dbg("bayes: $msgid already learnt as opposite, forgetting first");

        # kluge so that forget() won't untie the db on us ...
        my $orig = $self->{main}->{learn_caller_will_untie};
        $self->{main}->{learn_caller_will_untie} = 1;

        my $fatal = !defined $self->forget ($msg);

        # reset the value post-forget() ...
        $self->{main}->{learn_caller_will_untie} = $orig;
    
        # forget() gave us a fatal error, so propagate that up
        if ($fatal) {
          dbg("bayes: forget() returned a fatal error, so learn() will too");
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

  my $msgatime = $msg->receive_date();

  # If the message atime comes back as being more than 1 day in the
  # future, something's messed up and we should revert to current time as
  # a safety measure.
  #
  $msgatime = time if ( $msgatime - time > 86400 );

  my $tokens = $self->tokenize($msg, $msgdata);

  if ($isspam) {
    $self->{store}->multi_tok_count_change(1, 0, $tokens, $msgatime);
  } else {
    $self->{store}->multi_tok_count_change(0, 1, $tokens, $msgatime);
  }

  $self->{store}->seen_put ($msgid, ($isspam ? 's' : 'h'));
  $self->{store}->cleanup();

  $self->{main}->call_plugins("bayes_learn", { toksref => $tokens,
					       isspam => $isspam,
					       msgid => $msgid,
					       msgatime => $msgatime,
					     });

  dbg("bayes: learned '$msgid', atime: $msgatime");

  1;
}

###########################################################################

sub forget {
  my ($self, $msg, $id) = @_;

  if (!$self->{conf}->{use_bayes}) { return; }
  if (!defined $msg) { return; }

  my $msgdata = $self->get_body_from_msg ($msg);
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
      $ret = $self->forget_trapped ($msg, $msgdata, $id);

      if (!$self->{main}->{learn_caller_will_untie}) {
        $self->{store}->untie_db();
      }
    }
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->{store}->untie_db();
    die "bayes: $failure";
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub forget_trapped {
  my ($self, $msg, $msgdata, $msgid) = @_;
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
        dbg("bayes: forget: msgid $msgid seen entry is neither ham nor spam, ignored");
        return 0;
      }

      # messages should only be learned once, so stop if we find a msgid
      # which was seen before
      last;
    }
    else {
      dbg("bayes: forget: msgid $msgid not learnt, ignored");
    }
  }

  # This message wasn't learnt before, so return
  if (!defined $isspam) {
    dbg("bayes: forget: no msgid from this message has been learnt, skipping message");
    return 0;
  }
  elsif ($isspam) {
    $self->{store}->nspam_nham_change (-1, 0);
  }
  else {
    $self->{store}->nspam_nham_change (0, -1);
  }

  my $tokens = $self->tokenize($msg, $msgdata);

  if ($isspam) {
    $self->{store}->multi_tok_count_change (-1, 0, $tokens);
  } else {
    $self->{store}->multi_tok_count_change (0, -1, $tokens);
  }

  $self->{store}->seen_delete ($msgid);
  $self->{store}->cleanup();

  $self->{main}->call_plugins("bayes_forget", { toksref => $tokens,
						isspam => $isspam,
						msgid => $msgid,
					      });

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

  # Use sha1_hex(Date:, last received: and top N bytes of body)
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

  unshift(@msgid, sha1_hex($date."\000".$rcvd."\000".$body).'@sa_generated');

  return wantarray ? @msgid : $msgid[0];
}

sub get_body_from_msg {
  my ($self, $msg) = @_;

  if (!ref $msg) {
    # I have no idea why this seems to happen. TODO
    warn "bayes: msg not a ref: '$msg'";
    return { };
  }

  my $permsgstatus =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);
  $msg->extract_message_metadata ($permsgstatus);
  my $msgdata = $self->get_msgdata_from_permsgstatus ($permsgstatus);
  $permsgstatus->finish();

  if (!defined $msgdata) {
    # why?!
    warn "bayes: failed to get body for ".scalar($self->get_msgid($self->{msg}))."\n";
    return { };
  }

  return $msgdata;
}

sub get_msgdata_from_permsgstatus {
  my ($self, $msg) = @_;

  my $msgdata = { };
  $msgdata->{bayes_token_body} = $msg->{msg}->get_visible_rendered_body_text_array();
  $msgdata->{bayes_token_inviz} = $msg->{msg}->get_invisible_rendered_body_text_array();
  @{$msgdata->{bayes_token_uris}} = $msg->get_uri_list();
  return $msgdata;
}

###########################################################################

sub sync {
  my ($self, $sync, $expire, $opts) = @_;
  if (!$self->{conf}->{use_bayes}) { return 0; }

  if ($sync) {
    dbg("bayes: bayes journal sync starting");
    $self->{store}->sync($opts);
    dbg("bayes: bayes journal sync completed");
  }
  if ($expire) {
    dbg("bayes: expiry starting");
    $self->{store}->expire_old_tokens($opts);
    dbg("bayes: expiry completed");
  }

  return 0;
}

###########################################################################

# compute the probability that that token is spammish
sub compute_prob_for_token {
  my ($self, $token, $ns, $nn, $s, $n) = @_;

  # we allow the caller to give us the token information, just
  # to save a potentially expensive lookup
  if (!defined($s) || !defined($n)) {
    ($s, $n, undef) = $self->{store}->tok_get ($token);
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
    warn "bayes: oops? ratios == ration == 0";
    return;
  } else {
    $prob = ($ratios) / ($ration + $ratios);
  }

  if (USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    # use Robinson's f(x) equation for low-n tokens, instead of just
    # ignoring them
    my $robn = $s+$n;
    $prob = ($Mail::SpamAssassin::Bayes::Combine::FW_S_DOT_X + ($robn * $prob))
                             /
            ($Mail::SpamAssassin::Bayes::Combine::FW_S_CONSTANT + $robn);
  }

  # 'log_raw_counts' is used to log the raw data for the Bayes equations during
  # a mass-check, allowing the S and X constants to be optimized quickly
  # without requiring re-tokenization of the messages for each attempt. There's
  # really no need for this code to be uncommented in normal use, however.   It
  # has never been publicly documented, so commenting it out is fine. ;)

  ## if ($self->{log_raw_counts}) {
  ## $self->{raw_counts} .= " s=$s,n=$n ";
  ## }

  return $prob;
}

###########################################################################
# If a token is neither hammy nor spammy, return 0.
# For a spammy token, return the minimum number of additional ham messages
# it would have had to appear in to no longer be spammy.  Hammy tokens
# are handled similarly.  That's what the function does (at the time
# of this writing, 31 July 2003, 16:02:55 CDT).  It would be slightly
# more useful if it returned the number of /additional/ ham messages
# a spammy token would have to appear in to no longer be spammy but I
# fear that might require the solution to a cubic equation, and I
# just don't have the time for that now.

sub compute_declassification_distance {
  my ($self, $Ns, $Nn, $ns, $nn, $prob) = @_;

  return 0 if $ns == 0 && $nn == 0;

  if (!USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {return 0 if ($ns + $nn < 10);}
  if (!$self->{use_hapaxes}) {return 0 if ($ns + $nn < 2);}

  return 0 if $Ns == 0 || $Nn == 0;
  return 0 if abs( $prob - 0.5 ) <
                $Mail::SpamAssassin::Bayes::Combine::MIN_PROB_STRENGTH;

  my ($Na,$na,$Nb,$nb) = $prob > 0.5 ? ($Nn,$nn,$Ns,$ns) : ($Ns,$ns,$Nn,$nn);
  my $p = 0.5 - $Mail::SpamAssassin::Bayes::Combine::MIN_PROB_STRENGTH;

  return int( 1.0 - 1e-6 + $nb * $Na * $p / ($Nb * ( 1 - $p )) ) - $na
    unless USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS;

  my $s = $Mail::SpamAssassin::Bayes::Combine::FW_S_CONSTANT;
  my $sx = $Mail::SpamAssassin::Bayes::Combine::FW_S_DOT_X;
  my $a = $Nb * ( 1 - $p );
  my $b = $Nb * ( $sx + $nb * ( 1 - $p ) - $p * $s ) - $p * $Na * $nb;
  my $c = $Na * $nb * ( $sx - $p * ( $s + $nb ) );
  my $discrim = $b * $b - 4 * $a * $c;
  my $disc_max_0 = $discrim < 0 ? 0 : $discrim;
  my $dd_exact = ( 1.0 - 1e-6 + ( -$b + sqrt( $disc_max_0 ) ) / ( 2*$a ) ) - $na;

  # This shouldn't be necessary.  Should not be < 1
  return $dd_exact < 1 ? 1 : int($dd_exact);
}


# Check to make sure we can tie() the DB, and we have enough entries to do a scan
# if we're told the caller will untie(), go ahead and leave the db tied.
sub is_scan_available {
  my $self = shift;

  return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();

  # We need the DB to stay tied, so if the journal sync occurs, don't untie!
  my $caller_untie = $self->{main}->{learn_caller_will_untie};
  $self->{main}->{learn_caller_will_untie} = 1;

  # Do a journal sync if necessary.  Do this before the nspam_nham_get()
  # call since the sync may cause an update in the number of messages
  # learnt.
  $self->opportunistic_calls(1);

  # Reset the variable appropriately
  $self->{main}->{learn_caller_will_untie} = $caller_untie;

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  if ($ns < $self->{conf}->{bayes_min_spam_num}) {
    dbg("bayes: not available for scanning, only $ns spam(s) in bayes DB < ".$self->{conf}->{bayes_min_spam_num});
    if (!$self->{main}->{learn_caller_will_untie}) {
      $self->{store}->untie_db();
    }
    return 0;
  }
  if ($nn < $self->{conf}->{bayes_min_ham_num}) {
    dbg("bayes: not available for scanning, only $nn ham(s) in bayes DB < ".$self->{conf}->{bayes_min_ham_num});
    if (!$self->{main}->{learn_caller_will_untie}) {
      $self->{store}->untie_db();
    }
    return 0;
  }

  return 1;
}

###########################################################################
# Finally, the scoring function for testing mail.

sub scan {
  my ($self, $permsgstatus, $msg) = @_;
  my $score;

  # When we're doing a scan, we'll guarantee that we'll do the untie,
  # so override the global setting until we're done.
  my $caller_untie = $self->{main}->{learn_caller_will_untie};
  $self->{main}->{learn_caller_will_untie} = 1;

  goto skip if ($self->ignore_message($permsgstatus));

  goto skip unless $self->is_scan_available();

  my ($ns, $nn) = $self->{store}->nspam_nham_get();

  ## if ($self->{log_raw_counts}) { # see compute_prob_for_token()
  ## $self->{raw_counts} = " ns=$ns nn=$nn ";
  ## }

  dbg("bayes: corpus size: nspam = $ns, nham = $nn");

  my $msgdata = $self->get_msgdata_from_permsgstatus ($permsgstatus);

  my $msgtokens = $self->tokenize($msg, $msgdata);

  my $tokensdata = $self->{store}->tok_get_all(keys %{$msgtokens});

  my %pw = ();

  foreach my $tokendata (@{$tokensdata}) {
    my ($token, $tok_spam, $tok_ham, $atime) = @{$tokendata};
    my $prob = $self->compute_prob_for_token($token, $ns, $nn, $tok_spam, $tok_ham);
    next unless defined $prob;

    $pw{$token} = {
      prob => $prob,
      spam_count => $tok_spam,
      ham_count => $tok_ham,
      atime => $atime
    };
  }

  # If none of the tokens were found in the DB, we're going to skip
  # this message...
  if (!keys %pw) {
    dbg("bayes: cannot use bayes on this message; none of the tokens were found in the database");
    goto skip;
  }

  my $tcount_total = keys %{$msgtokens};
  my $tcount_learned = keys %pw;

  # Figure out the message receive time (used as atime below)
  # If the message atime comes back as being in the future, something's
  # messed up and we should revert to current time as a safety measure.
  #
  my $msgatime = $msg->receive_date();
  my $now = time;
  $msgatime = $now if ( $msgatime > $now );

  # now take the $count most significant tokens and calculate probs using
  # Robinson's formula.
  my $count = N_SIGNIFICANT_TOKENS;
  my @sorted = ();

  my @touch_tokens;
  my $tinfo_spammy = $permsgstatus->{bayes_token_info_spammy} = [];
  my $tinfo_hammy = $permsgstatus->{bayes_token_info_hammy} = [];

  my %tok_strength = map { $_ => (abs($pw{$_}->{prob} - 0.5)) } keys %pw;
  my $log_each_token = (would_log('dbg', 'bayes') > 1);

  foreach my $tok (sort {
              $tok_strength{$b} <=> $tok_strength{$a}
            } keys %pw)
  {
    if ($count-- < 0) { last; }
    next if ($tok_strength{$tok} <
                $Mail::SpamAssassin::Bayes::Combine::MIN_PROB_STRENGTH);

    my $pw = $pw{$tok}->{prob};

    # What's more expensive, scanning headers for HAMMYTOKENS and
    # SPAMMYTOKENS tags that aren't there or collecting data that
    # won't be used?  Just collecting the data is certainly simpler.
    #
    my $raw_token = $msgtokens->{$tok} || "(unknown)";
    my $s = $pw{$tok}->{spam_count};
    my $n = $pw{$tok}->{ham_count};
    my $a = $pw{$tok}->{atime};

    if ($pw < 0.5) {
      push @$tinfo_hammy,  [$raw_token,$pw,$s,$n,$a];
    } else {
      push @$tinfo_spammy, [$raw_token,$pw,$s,$n,$a];
    }

    push (@sorted, $pw);

    # update the atime on this token, it proved useful
    push(@touch_tokens, $tok);

    if ($log_each_token) {
      dbg("bayes: token '$raw_token' => $pw");
    }
  }

  if (!@sorted || (REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE > 0 && 
	$#sorted <= REQUIRE_SIGNIFICANT_TOKENS_TO_SCORE))
  {
    dbg("bayes: cannot use bayes on this message; not enough usable tokens found");
    goto skip;
  }

  $score = Mail::SpamAssassin::Bayes::Combine::combine($ns, $nn, \@sorted);

  # Couldn't come up with a probability?
  goto skip unless defined $score;

  dbg("bayes: score = $score");

  # no need to call tok_touch_all unless there were significant
  # tokens and a score was returned
  # we don't really care about the return value here
  $self->{store}->tok_touch_all(\@touch_tokens, $msgatime);

  $permsgstatus->{bayes_nspam} = $ns;
  $permsgstatus->{bayes_nham} = $nn;

  ## if ($self->{log_raw_counts}) { # see compute_prob_for_token()
  ## print "#Bayes-Raw-Counts: $self->{raw_counts}\n";
  ## }

  $self->{main}->call_plugins("bayes_scan", { toksref => $msgtokens,
					      probsref => \%pw,
					      score => $score,
					      msgatime => $msgatime,
					      significant_tokens => \@touch_tokens,
					    });

skip:
  if (!defined $score) {
    dbg("bayes: not scoring message, returning undef");
  }

  # Take any opportunistic actions we can take
  if ($self->{main}->{opportunistic_expire_check_only}) {
    # we're supposed to report on expiry only -- so do the
    # opportunistic_calls() run for the journal only.
    $self->opportunistic_calls(1);
    $permsgstatus->{bayes_expiry_due} = $self->{store}->expiry_due();
  }
  else {
    $self->opportunistic_calls();
  }

  # Do any cleanup we need to do
  $self->{store}->cleanup();

  # Reset the value accordingly
  $self->{main}->{learn_caller_will_untie} = $caller_untie;

  # If our caller won't untie the db, we need to do it.
  if (!$caller_untie) {
    $self->{store}->untie_db();
  }

  $permsgstatus->{tag_data}{BAYESTCHAMMY} = 
                        ($tinfo_hammy ? scalar @{$tinfo_hammy} : 0);
  $permsgstatus->{tag_data}{BAYESTCSPAMMY} = 
                        ($tinfo_spammy ? scalar @{$tinfo_spammy} : 0);
  $permsgstatus->{tag_data}{BAYESTCLEARNED} = $tcount_learned;
  $permsgstatus->{tag_data}{BAYESTC} = $tcount_total;

  return $score;
}

sub opportunistic_calls {
  my($self, $journal_only) = @_;

  # If we're not already tied, abort.
  if (!$self->{store}->db_readable()) {
    dbg("bayes: opportunistic call attempt failed, DB not readable");
    return;
  }

  # Is an expire or sync running?
  my $running_expire = $self->{store}->get_running_expire_tok();
  if ( defined $running_expire && $running_expire+$OPPORTUNISTIC_LOCK_VALID > time() ) {
    dbg("bayes: opportunistic call attempt skipped, found fresh running expire magic token");
    return;
  }

  # handle expiry and syncing
  if (!$journal_only && $self->{store}->expiry_due()) {
    dbg("bayes: opportunistic call found expiry due");

    # sync will bring the DB R/W as necessary, and the expire will remove
    # the running_expire token, may untie as well.
    $self->sync(1,1);
  }
  elsif ( $self->{store}->sync_due() ) {
    dbg("bayes: opportunistic call found journal sync due");

    # sync will bring the DB R/W as necessary, may untie as well
    $self->sync(1,0);

    # We can only remove the running_expire token if we're doing R/W
    if ($self->{store}->db_writable()) {
      $self->{store}->remove_running_expire_tok();
    }
  }

  return;
}

###########################################################################

sub dump_bayes_db {
  my($self, $magic, $toks, $regex) = @_;

  # allow dump to occur even if use_bayes disables everything else ...
  #return 0 unless $self->{conf}->{use_bayes};
  return 0 unless $self->{store}->tie_db_readonly();
  
  my @vars = $self->{store}->get_storage_variables();

  my($sb,$ns,$nh,$nt,$le,$oa,$bv,$js,$ad,$er,$na) = @vars;

  my $template = '%3.3f %10u %10u %10u  %s'."\n";

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
  return 1;
}

1;

=back

=cut
