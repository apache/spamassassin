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

The results are incorporated into SpamAssassin as the BAYES_* rules.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Bayes;

use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;
use Fcntl ':DEFAULT',':flock';
use Sys::Hostname;

BEGIN { @AnyDBM_File::ISA = qw(DB_File GDBM_File NDBM_File SDBM_File); }
use AnyDBM_File;

use vars qw{ @ISA @DBNAMES
  $IGNORED_HDRS
  @FLAG_PRESENCE_HDRS
  $MIN_SPAM_CORPUS_SIZE_FOR_BAYES
  $MIN_HAM_CORPUS_SIZE_FOR_BAYES
  %HEADER_NAME_COMPRESSION
  $NSPAM_MAGIC_TOKEN $NHAM_MAGIC_TOKEN 
};

@ISA = qw();

# Which headers should we scan for tokens?  Don't use all of them, as it's easy
# to pick up spurious clues from some.  What we now do is use all of them
# *less* these well-known headers; that way we can pick up spammers' tracking
# headers (which are obviously not well-known in advance!).

$IGNORED_HDRS = qr{(?: Sender			# misc noise
		  |Delivered-To |Delivery-Date
		  |X-MIME-Autoconverted

		  |Received	# handled specially

		  # Date: can provide invalid cues if your spam corpus is
		  # older/newer than nonspam
		  |Date	

		  # List headers: ignore. a spamfiltering mailing list will
		  # become a nonspam sign.
		  |List-Unsubscribe |List-Subscribe |List-Owner |X-List-Host
		  |X-Mailman-Version |X-Beenthere |List-Post |List-Help
		  |X-Original-Date |List-Archive |List-Id |Mail-Followup-To

		  # Spamfilter/virus-scanner headers: too easy to chain from
		  # these
		  |X-MailScanner |X-MailScanner-SpamCheck |X-Spam-Status
		  |X-Spam-Level |X-Antispam |X-Spam-Checker-Version
		  |X-Spam-Report |X-Spam-Flag |X-RBL-Warning
		  |X-MDaemon-Deliver-To |X-Virus-Scanned |X-Spam-hits |X-Spam
		  |X-Spam-Score |X-Mass-Check-Id |X-Pyzor

		  # some noisy Outlook headers that add no good clues:
		  |Content-Class |Thread-Index
		  |X-OriginalArrivalTime

		  # Annotations from IMAP, POP, and MH:
		  |Status |Content-Length
		  |Lines |X-UID	|X-UIDL
		  |Replied |Forwarded
		)}x;

# Note the presence or absence of some headers.  by default the PRESENT/ABSENT
# token this generates will exist alongside the tokens in the header; if you
# don't want to see tokens from these headers *at all* except for the
# PRESENT/ABSENT token, add them to IGNORED_HDRS too.  This is off by default.
#
# to replace In-Reply-To et al with a header presence/absence token, add
# this to IGNORED_HDRS above: "|In-Reply-To |References" and turn on
# TRY_NOTE_HEADER_PRESENCE_ABSENCE.  But it does not seem to be a win.

use constant TRY_NOTE_HEADER_PRESENCE_ABSENCE => 0;
@FLAG_PRESENCE_HDRS = qw{
		  From To Cc CC MIME-Version Content-Transfer-Encoding Date
		  Subject Sender Reply-To Errors-To Return-Receipt-To
		  Return-Path Content-Class Thread-Index X-OriginalArrivalTime
		  X-Mailer User-Agent Content-Type X-Priority X-Msmail-Priority
		  Importance X-Mimeole In-Reply-To References 
		};

# tweaks tested as of Nov 18 2002 by jm: see SpamAssassin-devel list archives
# for results.  The winners are now the default settings.
use constant TRY_IGNORE_TITLE_CASE_AT_START_OF_SENTENCE => 1;
use constant TRY_IGNORE_TITLE_CASE_EVERYWHERE => 0;
use constant TRY_DUP_TOKENS_AS_LOWERCASE => 0;
use constant TRY_DUP_TOKENS_WITH_CASEI_PREFIX => 0;
use constant TRY_KEEP_AT_SIGNS => 1;
use constant TRY_KEEP_THIRD_RECEIVED => 0;
use constant TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES => 0;
use constant TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES_2 => 0;
use constant TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES_3 => 1;
use constant TOKENIZE_LONG_TOKENS_AS_SKIPS => 1;

# We store header-mined tokens in the db with a "HHeaderName:val" format.
# some headers may contain lots of gibberish tokens, so allow a little basic
# compression by mapping the header name at least here.  these are the headers
# which appear with the most frequency in my db.  note: this doesn't have to
# be 2-way (ie. LHSes that map to the same RHS are not a problem), but mixing
# tokens from multiple different headers may impact accuracy, so might as well
# avoid this if possible.
%HEADER_NAME_COMPRESSION = (
  'Message-Id' => '*m',
  'Message-ID' => '*M',
  'Received' => '*r',
  'Subject' => '*s',
  'User-Agent' => '*u',
  'References' => '*f',
  'In-Reply-To' => '*i',
);

# How big should the corpora be before we allow scoring using Bayesian tests?
# Do not use constants here. Also these may be better as conf items. TODO
$MIN_SPAM_CORPUS_SIZE_FOR_BAYES = 200;
$MIN_HAM_CORPUS_SIZE_FOR_BAYES = 200;

# Should we use the Robinson f(w) equation from 
# http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html ?
# It gives better results, in that scores are more likely to distribute
# into the <0.5 range for nonspam and >0.5 for spam.
use constant USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS => 1;

# This (apparently) works well as a value for 's' in the f(w) equation.
use constant ROBINSON_S_CONSTANT => 0.30;

# How many of the most significant tokens should we use for the p(w)
# calculation?
use constant N_SIGNIFICANT_TOKENS => 150;

# Should we ignore tokens with probs very close to the middle ground (.5)?
# tokens need to be outside the [ .5-MPS, .5+MPS ] range to be used.
use constant ROBINSON_MIN_PROB_STRENGTH => 0.27;

# How long a token should we hold onto?  (note: German speakers typically
# will require a longer token than English ones.)
use constant MAX_TOKEN_LENGTH => 15;

# lower and upper bounds for probabilities; we lock probs into these
# so one high-strength token can't overwhelm a set of slightly lower-strength
# tokens.
use constant PROB_BOUND_LOWER => 0.001;
use constant PROB_BOUND_UPPER => 0.999;

# we have 5 databases for efficiency.  To quote Matt:
# > need five db files though to make it real fast:
# [probs] 1. ngood and nbad (two entries, so could be a flat file rather 
# than a db file).	(now 2 entries in db_probs)
# [toks]  2. good token -> number seen
# [toks]  3. bad token -> number seen (both are packed into 1 entry in 1 db)
# [probs]  4. Consolidated good token -> probability
# [probs]  5. Consolidated bad token -> probability
# > As you add new mails, you update the entry in 2 or 3, then regenerate
# > the entry for that token in 4 or 5.
# > Then as you test a new mail, you just need to pull the probability
# > direct from 4 and 5, and generate the overall probability. A simple and
# > very fast operation. 
# jm: we use probs as overall probability. <0.5 = ham, >0.5 = spam
# also, added a new one to support forgetting, auto-learning, and
# auto-forgetting for refiled mails:
# [seen]  6. a list of Message-IDs of messages already learnt from. values
# are 's' for learnt-as-spam, 'h' for learnt-as-ham.

@DBNAMES = qw(toks probs seen);

$NSPAM_MAGIC_TOKEN = '**NSPAM';
$NHAM_MAGIC_TOKEN = '**NHAM';

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main) = @_;
  my $self = {
    'main'              => $main,
    'hostname'          => hostname,
    'already_tied'      => 0,
    'is_locked'         => 0,
  };
  bless ($self, $class);

  $self->precompute_robinson_constants();
  $self;
}

###########################################################################

sub tie_db_readonly {
  my ($self) = @_;
  my $main = $self->{main};

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return 1 if ($self->{already_tied} && $self->{is_locked} == 0);
  $self->{already_tied} = 1;

  if (!defined($main->{conf}->{bayes_path})) {
    dbg ("bayes_path not defined");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{bayes_path});
  if (!-f $path.'_probs') {
    dbg ("bayes: no dbs present, cannot scan");
    return 0;
  }

  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/O $name");
    # untie %{$self->{$db_var}} if (tied %{$self->{$db_var}});
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDONLY,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  return 1;

failed_to_tie:
  warn "Cannot open bayes_path $path R/O: $!\n";
  return 0;
}

# tie() to the databases, read-write and locked.  Any callers of
# this should ensure they call untie_db() afterwards!
#
sub tie_db_writable {
  my ($self) = @_;
  my $main = $self->{main};

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return 1 if ($self->{already_tied} && $self->{is_locked} == 1);
  $self->{already_tied} = 1;

  if (!defined($main->{conf}->{bayes_path})) {
    dbg ("bayes_path not defined");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{bayes_path});

  #NFS Safe Lockng (I hope!)
  #Attempt to lock the dbfile, using NFS safe locking 
  #Locking code adapted from code by Alexis Rosen <alexis@panix.com>
  #Kelsey Cummings <kgc@sonic.net>
  my $lock_file = $self->{lock_file} = $path.'.lock';
  my $lock_tmp = $lock_file . '.' . $self->{hostname} . '.'. $$;
  my $max_lock_age = 300; #seconds 
  my $lock_tries = 30;

  open(LTMP, ">$lock_tmp") || die "Cannot create tmp lockfile $lock_file : $!\n";
  my $old_fh = select(LTMP);
  $|=1;
  select($old_fh);

  for (my $i = 0; $i < $lock_tries; $i++) {
    dbg("bayes: $$ trying to get lock on $path pass $i");
    print LTMP $self->{hostname}.".$$\n";
    if ( link ($lock_tmp,$lock_file) ) {
      $self->{is_locked} = 1;
      last;

    } else {
      #link _may_ return false even if the link _is_ created
      if ( (stat($lock_tmp))[3] > 1 ) {
	$self->{is_locked} = 1;
	last;
      }

      #check to see how old the lockfile is
      my $lock_age = (stat($lock_file))[10];
      my $now = (stat($lock_tmp))[10];
      if (!defined($lock_age) || $lock_age < $now - $max_lock_age) {
	#we got a stale lock, break it
	dbg("bayes: $$ breaking stale lockfile!");
	unlink "$lock_file";
      }
      sleep(1);
    }
  }
  close(LTMP);
  unlink($lock_tmp);

  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/W $name");
    # not convinced this is needed, or is efficient!
    # untie %{$self->{$db_var}} if (tied %{$self->{$db_var}});
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDWR|O_CREAT,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  return 1;

failed_to_tie:
  unlink($self->{lock_file}) ||
     dbg ("bayes: couldn't unlink " . $self->{lock_file} . ": $!\n");

  warn "Cannot open bayes_path $path R/W: $!\n";
  return 0;
}

###########################################################################

sub untie_db {
  my $self = shift;
  dbg("bayes: untie-ing");

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;
    dbg ("bayes: untie-ing $db_var");
    untie %{$self->{$db_var}};
  }

  if ($self->{is_locked}) {
    dbg ("bayes: files locked, breaking lock.");
    unlink($self->{lock_file}) ||
        dbg ("bayes: couldn't unlink " . $self->{lock_file} . ": $!\n");
    $self->{is_locked} = 0;
  }

  $self->{already_tied} = 0;
}

sub finish {
  $_[0]->untie_db();
}

###########################################################################

sub tokenize {
  my ($self, $msg, $body) = @_;

  my $wc = 0;
  $self->{tokens} = [ ];

  for (@{$body}) {
    $wc += $self->tokenize_line ($_, '', 1);
  }

  my %hdrs = $self->tokenize_headers ($msg);
  foreach my $prefix (keys %hdrs) {
    $wc += $self->tokenize_line ($hdrs{$prefix}, "H$prefix:", 0);
  }

  my @toks = @{$self->{tokens}}; delete $self->{tokens};
  ($wc, @toks);
}

sub tokenize_line {
  my $self = $_[0];
  local ($_) = $_[1];
  my $tokprefix = $_[2];
  my $isbody = $_[3];

  # include quotes, .'s and -'s for URIs, and [$,]'s for Nigerian-scam strings,
  # and ISO-8859-15 alphas.  DO split on @'s, so username and domains in
  # mail addrs are separate tokens.
  # Some useful tokens: "$31,000,000" "www.clock-speed.net"
  if (TRY_KEEP_AT_SIGNS) {
    tr/-A-Za-z0-9,\@_'"\$.\241-\377 / /cs;
  } else {
    tr/-A-Za-z0-9,_'"\$.\241-\377 / /cs;
  }

  if (TRY_IGNORE_TITLE_CASE_AT_START_OF_SENTENCE) {
    if ($isbody) {
      # lower-case Title Case at start of a full-stop-delimited line (as would
      # be seen in a Western language).
      s/(?:^|\.\s+)([A-Z])([^A-Z]+)(?:\s|$)/ ' '. (lc $1) . $2 . ' ' /ge;
    }
  }

  my $wc = 0;

  foreach my $token (split) {
    $token =~ s/^[-'"\.,]+//;        # trim non-alphanum chars at start or end
    $token =~ s/[-'"\.,]+$//;        # so we don't get loads of '"foo' tokens

    # *do* keep 3-byte tokens; there's some solid signs in there
    my $len = length($token);
    next if $len < 3 ||
	$token =~ /^(?:and|the|not|any|for|from|one|The|has|have)$/;

    my $replacedigits = 1;

    if ($len > MAX_TOKEN_LENGTH) {
      if (TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES) {
	if ($token =~ /[\xa0-\xff]/) {
	  # Matt sez: "Could be asian? Autrijus suggested doing character ngrams,
	  # but I'm doing tuples to keep the dbs small(er)."  Sounds like a plan
	  # to me! (jm)
	  while ($token =~ s/^(..?)//) {
	    push (@{$self->{tokens}}, "8bit:$1"); $wc++;
	  }
	  next;
	}
      }
      if (TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES_2) {
	if ($token =~ /[\xa0-\xff]{2}/) {
	  # Matt sez: "Could be asian? Autrijus suggested doing character ngrams,
	  # but I'm doing tuples to keep the dbs small(er)."  Sounds like a plan
	  # to me! (jm)
	  while ($token =~ s/^(..?)//) {
	    push (@{$self->{tokens}}, "8bit:$1"); $wc++;
	  }
	  next;
	}
      }
      if (TOKENIZE_LONG_8BIT_SEQS_AS_TUPLES_3) {
	if ($token =~ /^[\xa0-\xff]{2}/) {
	  # Matt sez: "Could be asian? Autrijus suggested doing character ngrams,
	  # but I'm doing tuples to keep the dbs small(er)."  Sounds like a plan
	  # to me! (jm)
	  while ($token =~ s/^(..?)//) {
	    push (@{$self->{tokens}}, "8bit:$1"); $wc++;
	  }
	  next;
	}
      }

      if (TOKENIZE_LONG_TOKENS_AS_SKIPS) {
	# Spambayes trick via Matt: Just retain 7 chars and the length
	# sk: stands for "skip".
	$token = "sk:".substr($token, 0, 7)." ".$len;
	$replacedigits = 0;
      }
    }

    $wc++;

    if (TRY_IGNORE_TITLE_CASE_EVERYWHERE) {
      if ($isbody) { # lowercase Title Case words anyway
	$token =~ s/^([A-Z])([^A-Z]+)$/ (lc $1) . $2 /ge;
      }
    }
    push (@{$self->{tokens}}, $tokprefix.$token);

    # now do some token abstraction; in other words, make them act like
    # patterns instead of text copies.

    # case...
    if (TRY_DUP_TOKENS_AS_LOWERCASE) {
      $token =~ tr/A-Z/a-z/;
      push (@{$self->{tokens}}, $tokprefix.$token);
    }

    if (TRY_DUP_TOKENS_WITH_CASEI_PREFIX) {
      if ($token =~ /[A-Z]/) {
	$token =~ tr/A-Z/a-z/;
	push (@{$self->{tokens}}, 'C:'.$tokprefix.$token);
      } else {
	push (@{$self->{tokens}}, 'C:'.$tokprefix.$token);
      }
    }

    # replace digits with 'N'...
    if ($replacedigits && $token =~ /\d/) {
      $token =~ s/\d/N/gs; push (@{$self->{tokens}}, 'N:'.$tokprefix.$token);
    }
  }

  return $wc;
}

sub tokenize_headers {
  my ($self, $msg) = @_;

  my $hdrs = $msg->get_all_headers();
  my %parsed = ();

  # we don't care about whitespace; so fix continuation lines to make the next
  # bit easier
  $hdrs =~ s/\n[ \t]+/ /gs;

  # first, keep a copy of Received hdrs, so we can strip down to last 2
  my @rcvdlines = ($hdrs =~ /^Received: [^\n]*$/gim);

  # and now delete lines for headers we don't want (incl all Receiveds)
  $hdrs =~ s/^From \S+[^\n]+$//gim;

  if (TRY_NOTE_HEADER_PRESENCE_ABSENCE) {
    my @newhdrs = ();

    foreach my $hdr (@FLAG_PRESENCE_HDRS) {
      if ($hdrs =~ /^${hdr}: /m) {
	push (@newhdrs, "\n", $hdr, ": PRESENT");
      } else {
	push (@newhdrs, "\n", $hdr, ": ABSENT");
      }
    }

    $hdrs =~ s/^${IGNORED_HDRS}: [^\n]*$//gim;
    $hdrs .= join ('', @newhdrs);

  } else {
    $hdrs =~ s/^${IGNORED_HDRS}: [^\n]*$//gim;
  }

  # and re-add the last 2 received lines: usually a good source of
  # spamware tokens and HELO names.
  if ($#rcvdlines >= 0) { $hdrs .= "\n".$rcvdlines[$#rcvdlines]; }
  if ($#rcvdlines >= 1) { $hdrs .= "\n".$rcvdlines[$#rcvdlines-1]; }

  if (TRY_KEEP_THIRD_RECEIVED) {
    if ($#rcvdlines >= 2) { $hdrs .= "\n".$rcvdlines[$#rcvdlines-2]; }
  }

  while ($hdrs =~ /^(\S+): ([^\n]*)$/gim) {
    my $hdr = $1;
    my $val = $2;

    # special tokenization for some headers:
    if ($hdr =~ /^(?:|X-|Resent-)Message-I[dD]$/) {
      # try to split Message-ID segments on probable ID boundaries. Note that
      # Outlook message-ids seem to contain a server identifier ID in the last
      # 8 bytes before the @.  Make sure this becomes its own token, it's a
      # great spam-sign for a learning system!  Be sure to split on ".".
      $val =~ s/[^_A-Za-z0-9]/ /g;
    }
    elsif ($hdr eq 'Received') {
      # Thanks to Dan for these.  Trim out "useless" tokens; sendmail-ish IDs
      # and valid-format RFC-822/2822 dates
      $val =~ s/\bid [a-zA-Z0-9]{7,20}\b//g;
      $val =~ s/(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s)?
		[0-3\s]?[0-9]\s
		(?:Jan|Feb|Ma[ry]|Apr|Ju[nl]|Aug|Sep|Oct|Nov|Dec)\s
		(?:19|20)?[0-9]{2}\s
		[0-2][0-9](?:\:[0-5][0-9]){1,2}\s
		(?:\s*\(|\)|\s*(?:[+-][0-9]{4})|\s*(?:UT|[A-Z]{2,3}T))*
		//gx;

      # also these: they turn out as the most common tokens, but with a
      # prob of about .5.  waste of space!
      $val =~ s/\s(?:with|from|for|SMTP|ESMTP)\s/ /g;
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

###########################################################################

sub learn {
  my ($self, $isspam, $msg) = @_;

  if (!defined $msg) { return; }
  my $body = $self->get_body_from_msg ($msg);
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    $self->tie_db_writable();
    $ret = $self->learn_trapped ($isspam, $msg, $body);
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->untie_db();
    die $failure;
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub learn_trapped {
  my ($self, $isspam, $msg, $body) = @_;

  my $msgid = $self->get_msgid ($msg);
  my $seen = $self->{db_seen}->{$msgid};
  if (defined ($seen)) {
    if (($seen eq 's' && $isspam) || ($seen eq 'h' && !$isspam)) {
      dbg ("$msgid: already learnt correctly, not learning twice");
      return;
    } elsif ($seen !~ /^[hs]$/) {
      warn ("db_seen corrupt: value='$seen' for $msgid. ignored");
    } else {
      dbg ("$msgid: already learnt as opposite, forgetting first");
      $self->forget ($msg);
    }
  }

  if ($isspam) {
    $self->{db_probs}->{$NSPAM_MAGIC_TOKEN}++;
  } else {
    $self->{db_probs}->{$NHAM_MAGIC_TOKEN}++;
  }
  my $ns = $self->{db_probs}->{$NSPAM_MAGIC_TOKEN};
  my $nn = $self->{db_probs}->{$NHAM_MAGIC_TOKEN};
  $ns ||= 0;
  $nn ||= 0;

  my ($wc, @tokens) = $self->tokenize ($msg, $body);
  my %seen = ();

  for (@tokens) {
    if ($seen{$_}) { next; } else { $seen{$_} = 1; }

    my ($ts, $th) = tok_unpack ($self->{db_toks}->{$_});
    if ($isspam) { $ts++; } else { $th++; }
    $self->{db_toks}->{$_} = tok_pack ($ts, $th);

    # if we don't have both corpora, skip generating probabilities.
    # we can't get useful results without both.
    next if ($nn == 0 || $ns == 0);
    if ($self->{main}->{bayes_on_the_fly_recalc}) {
      $self->compute_prob_for_token ($_, $ns, $nn);
    }
  }

  $self->{db_seen}->{$msgid} = ($isspam ? 's' : 'h');

  # do this costly operation once every 500 mails
  # TODO: come up with a time-based recalc operation instead
  if ($ns != 0 && $nn != 0 && (($ns+$nn) % 500) == 0) {
    $self->recompute_all_probs();

    # next, dump all dbs to disk. they will be reloaded on next operation.
    # this should help keep memory down
    $self->untie_db();
  }
}

###########################################################################

sub forget {
  my ($self, $msg) = @_;

  if (!defined $msg) { return; }
  my $body = $self->get_body_from_msg ($msg);
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    $self->tie_db_writable();
    $ret = $self->forget_trapped ($msg, $body);
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->untie_db();
    die $failure;
  }

  return $ret;
}

# this function is trapped by the wrapper above
sub forget_trapped {
  my ($self, $msg, $body) = @_;

  my $msgid = $self->get_msgid ($msg);
  my $seen = $self->{db_seen}->{$msgid};
  my $isspam;
  if (defined ($seen)) {
    if ($seen eq 's') {
      $isspam = 1;
    } elsif ($seen eq 'h') {
      $isspam = 0;
    } else {
      dbg ("forget: message $msgid not learnt, ignored");
      return;
    }
  }

  my $ns = $self->{db_probs}->{$NSPAM_MAGIC_TOKEN};
  my $nn = $self->{db_probs}->{$NHAM_MAGIC_TOKEN};
  $ns ||= 0;
  $nn ||= 0;

  # protect against going negative
  if ($isspam) {
    $ns--; if ($ns < 0) { $ns = 0; }
    $self->{db_probs}->{$NSPAM_MAGIC_TOKEN} = $ns;
  } else {
    $nn--; if ($nn < 0) { $nn = 0; }
    $self->{db_probs}->{$NHAM_MAGIC_TOKEN} = $nn;
  }

  my ($wc, @tokens) = $self->tokenize ($msg, $body);
  my %seen = ();
  for (@tokens) {
    if ($seen{$_}) { next; } else { $seen{$_} = 1; }
    my ($ts, $th) = tok_unpack ($self->{db_toks}->{$_});

    if ($isspam) {
      $ts = ($ts <= 1 ? 0 : $ts-1);
    } else {
      $th = ($th <= 1 ? 0 : $th-1);
    }

    if ($ts == 0 && $th == 0) {
      delete $self->{db_toks}->{$_};
      delete $self->{db_probs}->{$_};
    } else {
      $self->{db_toks}->{$_} = tok_pack ($ts, $th);
    }

    # if we don't have both corpora, skip generating probabilities.
    # we can't get useful results without both.
    next if ($nn == 0 || $ns == 0);
    if ($self->{main}->{bayes_on_the_fly_recalc}) {
      $self->compute_prob_for_token ($_, $ns, $nn);
    }
  }

  delete $self->{db_seen}->{$msgid};

  # do this costly operation once every 500 mails, or if we've forgotten
  # the last ham/spam
  if ($ns != 0 && $nn != 0 && (($ns+$nn) % 500) == 0) {
    $self->recompute_all_probs();

    # next, dump all dbs to disk. they will be reloaded on next operation.
    # this should help keep memory down
    $self->untie_db();
  }
}

###########################################################################

sub get_msgid {
  my ($self, $msg) = @_;

  my $msgid = $msg->get("Message-Id");
  if (!defined $msgid) { $msgid = time.".$$\@sa_generated"; }

  # remove \r and < and > prefix/suffixes
  chomp $msgid;
  $msgid =~ s/^<//; $msgid =~ s/>.*$//g;

  $msgid;
}

sub get_body_from_msg {
  my ($self, $msg) = @_;

  if (!ref $msg) {
    # I have no idea why this seems to happen. TODO
    warn "msg not a ref: '$msg'";
    return [ ];
  }
  my $permsgstatus =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);
  my $body = $permsgstatus->get_decoded_stripped_body_text_array();
  $permsgstatus->finish();

  if (!defined $body) {
    # why?!
    warn "failed to get body for ".$self->{msg}->get("Message-Id")."\n";
    return [ ];
  }

  return $body;
}

###########################################################################

# now and again, this can be run to rebuild the probabilities cache.
# This cache will be unusable if one of the corpora has not been scanned yet.
# This operation can take a while...

sub recompute_all_probs {
  my ($self) = @_;
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    $self->tie_db_writable();
    $ret = $self->recompute_all_probs_trapped ();
  };

  if ($@) {		# if we died, untie the dbs.
    my $failure = $@;
    $self->untie_db();
    die $failure;
  }

  return $ret;
}

# this function is trapped by the wrapper above.
#
# TODO: BTW, this would be faster if we create a totally-new DB file instead of
# using the existing one, since we will typically visit 99.99% of the entries
# in the DB anyway.  However we cannot simply unlink() at the start of the fn,
# as any reader processes will then not have Bayes scoring until we've completed.
# Instead we should create a "new" db in parallel, then rename() it in once
# we've finished.

sub recompute_all_probs_trapped {
  my ($self) = @_;

  my $start = time;

  my $ns = $self->{db_probs}->{$NSPAM_MAGIC_TOKEN};
  my $nn = $self->{db_probs}->{$NHAM_MAGIC_TOKEN};
  $ns ||= 0;
  $nn ||= 0;
  if ($nn == 0 || $ns == 0) {
    dbg("bayes: 0 messages in spam ($ns) or ham ($nn) corpus, not recomputing");
    goto done;
  }

  my $probstotal = 0;
  my $count = 0;

  dbg("bayes: recomputing all probabilities for $ns spam msgs and $nn ham msgs...");

  my %done = ();
  foreach my $token (keys %{$self->{db_toks}}) {
    next if (exists $done{$token}); $done{$token}=1;
    my $prob = $self->compute_prob_for_token ($token, $ns, $nn);
    if (defined $prob) { $probstotal += $prob; }
    $count++;
  }

  # for debugging, let's see this figure
  dbg ("bayes: computed Robinson x = ".($count ? ($probstotal / $count) : 0));

done:
  my $now = time;
  dbg ("bayes: recomputed all probabilities for ".(scalar keys %done).
        " tokens in ".($now - $start)." seconds");
  $self->untie_db();
  1;
}

sub compute_prob_for_token {
  my ($self, $token, $ns, $nn) = @_;

  # precompute the probability that that token is spammish
  my ($s, $n) = tok_unpack ($self->{db_toks}->{$token});

  if (!USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    return if ($s + $n < 10);      # ignore low-freq tokens
  }

  # to *not* use hapaxes: return if ($s + $n < 2);
  # but this does not seem to be a win at all.

  my $ratios = ($s / $ns);
  my $ration = ($n / $nn);
  my $prob;

  if ($ratios == 0 && $ration == 0) {
    warn "oops? ratios == ration == 0";
    $prob = 0.5;
  } else {
    $prob = ($ratios) / ($ration + $ratios);
  }

  if (USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    # use Robinson's f(x) equation for low-n tokens, instead of just
    # ignoring them
    my $robn = $s+$n;
    $prob = ($self->{robinson_s_dot_x} + ($robn * $prob)) /
		  (ROBINSON_S_CONSTANT + $robn);
  }

  $self->{db_probs}->{$token} = pack ('f', $prob);
  return $prob;
}

sub precompute_robinson_constants {
  my $self = shift;

  my $robinson_x = 0.5;		#TODO - use computed one?
  # precompute this here for speed
  $self->{robinson_s_dot_x} = ($robinson_x * ROBINSON_S_CONSTANT);
}

###########################################################################
# Finally, the scoring function for testing mail.

sub scan {
  my ($self, $msg, $body) = @_;

  if (!$self->tie_db_readonly()) { goto skip; }

  my $ns = $self->{db_probs}->{$NSPAM_MAGIC_TOKEN};
  my $nn = $self->{db_probs}->{$NHAM_MAGIC_TOKEN};
  $ns ||= 0;
  $nn ||= 0;

  if ($ns < $MIN_SPAM_CORPUS_SIZE_FOR_BAYES) {
    dbg ("corpus too small ($ns < $MIN_SPAM_CORPUS_SIZE_FOR_BAYES), skipping");
    goto skip;
  }
  if ($nn < $MIN_HAM_CORPUS_SIZE_FOR_BAYES) {
    dbg ("corpus too small ($nn < $MIN_HAM_CORPUS_SIZE_FOR_BAYES), skipping");
    goto skip;
  }

  dbg ("bayes corpus size: nspam = $ns, nham = $nn");

  my ($wc, @tokens) = $self->tokenize ($msg, $body);
  my %seen = ();
  my $pw;

  my %pw = map {
    if ($seen{$_}) { (); }	# exit map()
    
    else {
      $seen{$_} = 1;

      $pw = $self->{db_probs}->{$_};
      if (!defined $pw) { (); }	# exit map()
      
      else {
	$pw = unpack ('f', $pw);

	# enforce (max PROB_BOUND_LOWER (min PROB_BOUND_UPPER (score))) as per
	# Graham; it allows a majority of spam clues to override 1 or 2
	# very-strong nonspam clues.
	#
	if ($pw < PROB_BOUND_LOWER) {
	  ($_ => PROB_BOUND_LOWER);
	} elsif ($pw > PROB_BOUND_UPPER) {
	  ($_ => PROB_BOUND_UPPER);
	} else {
	  ($_ => $pw);
	}
      }
    }
  } @tokens;

  if ($wc <= 0) {
    dbg ("cannot use bayes on this message; no tokens found");
    goto skip;
  }

  # now take the $count most significant tokens and calculate probs using
  # Robinson's formula.
  my $count = N_SIGNIFICANT_TOKENS;
  my $P = 1;
  my $Q = 1;
  for (sort {
              abs($pw{$b} - 0.5) <=> abs($pw{$a} - 0.5)
            } keys %pw)
  {
    if ($count-- < 0) { last; }
    my $pw = $pw{$_};
    next if (abs($pw - 0.5) < ROBINSON_MIN_PROB_STRENGTH);
    $P *= (1-$pw);
    $Q *= $pw;

    dbg ("bayes token '$_' => $pw");
  }

  $P = 1 - ($P ** (1 / $wc));
  $Q = 1 - ($Q ** (1 / $wc));

  if ($P + $Q == 0) {
    dbg ("cannot use bayes on this message; db not initialised yet");
    goto skip;
  }

  my $S = (1 + ($P - $Q) / ($P + $Q)) / 2.0;
  dbg ("bayes: score = $S");
  $self->untie_db();

  return $S;

skip:
  dbg ("bayes: not scoring message, returning 0.5");
  return 0.5;           # nice and neutral
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

# token marshalling format for db_toks.

# Since we may have many entries with few hits, especially thousands of hapaxes
# (1-occurrence entries), use a flexible entry format, instead of simply "2
# packed ints", to keep the memory and disk space usage down.  In my
# 18k-message test corpus, only 8.9% have >= 8 hits in either counter, so we
# can use a 1-byte representation for the other 91% of low-hitting entries
# and save masses of space.

# This looks like: XXSSSHHH (XX = format bits, SSS = 3 spam-count bits, HHH = 3
# ham-count bits).  If XX in the first byte is 11, it's packed as this 1-byte
# representation; otherwise, if XX in the first byte is 00, it's packed as
# "CLL", ie. 1 byte and 2 32-bit "longs" in perl pack format.

# Savings: roughly halves size of toks db, at the cost of a ~10% slowdown.

use constant FORMAT_FLAG	=> 0xc0;	# 11000000
  use constant ONE_BYTE_FORMAT	=> 0xc0;	# 11000000
  use constant TWO_LONGS_FORMAT	=> 0x00;	# 00000000

use constant ONE_BYTE_SSS_BITS	=> 0x38;	# 00111000
use constant ONE_BYTE_HHH_BITS	=> 0x07;	# 00000111

sub tok_unpack {
  my ($packed, $ts, $th) = unpack("CLL", $_[0] || 0);

  if (($packed & FORMAT_FLAG) == ONE_BYTE_FORMAT) {
    return (($packed & ONE_BYTE_SSS_BITS) >> 3, $packed & ONE_BYTE_HHH_BITS);
  }
  elsif (($packed & FORMAT_FLAG) == TWO_LONGS_FORMAT) {
    # use $ts and $th we just unpacked
    return ($ts || 0, $th || 0);
  }
  # other formats would go here...
  else {
    warn "unknown packing format for Bayes db, please re-learn: $packed";
    return (0, 0);
  }
}

sub tok_pack {
  my ($ts, $th) = @_;
  $ts ||= 0;
  $th ||= 0;
  if ($ts < 8 && $th < 8) {
    return pack ("C", ONE_BYTE_FORMAT | ($ts << 3) | $th);
  } else {
    return pack ("CLL", TWO_LONGS_FORMAT, $ts, $th);
  }
}

###########################################################################

1;
