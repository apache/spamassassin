=head1 NAME

Mail::SpamAssassin::Bayes - determine spammishness using a Bayesian classifier

=head1 SYNOPSIS

=head1 DESCRIPTION

This is a form of Bayesian classification, using an algorithm based on the one
detailed in Paul Graham's "A Plan For Spam" paper at:

  http://www.paulgraham.com/

It also incorporates some other aspects taken from Graham Robinson's webpage on
the subject at:

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
  $MIN_SPAM_CORPUS_SIZE_FOR_BAYES
  $MIN_HAM_CORPUS_SIZE_FOR_BAYES
  $USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS
  $ROBINSON_S_CONSTANT
  $ROBINSON_MIN_PROB_STRENGTH
  $N_SIGNIFICANT_TOKENS
};

@ISA = qw();

# How big should the corpora be before we allow scoring using Bayesian
# tests?
$MIN_SPAM_CORPUS_SIZE_FOR_BAYES = 200;
$MIN_HAM_CORPUS_SIZE_FOR_BAYES = 200;

# Should we use the Robinson f(w) equation from 
# http://radio.weblogs.com/0101454/stories/2002/09/16/spamDetection.html ?
# It gives better results, in that scores are more likely to distribute
# into the <0.5 range for nonspam and >0.5 for spam.
$USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS = 1;

# This (apparently) works well as a value for 's' in the f(w) equation.
$ROBINSON_S_CONSTANT = 0.45;

# How many of the most significant tokens should we use for the p(w)
# calculation?
$N_SIGNIFICANT_TOKENS = 100;

# Should we ignore tokens very close to the middle ground?  This value
# is anecdotally effective.
$ROBINSON_MIN_PROB_STRENGTH = 0.1;

# we have 5 databases for efficiency.  To quote Matt:
# > need five db files though to make it real fast:
# [count] 1. ngood and nbad (two entries, so could be a flat file rather 
# than a db file).
# [toks_ham] 2. good token -> number seen
# [toks_spam]  3. bad token -> number seen
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

@DBNAMES = qw(count toks_ham toks_spam probs seen);

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
  return if ($self->{already_tied} && $self->{is_locked} == 0);
  $self->{already_tied} = 1;

  if (!defined($main->{conf}->{bayes_path})) {
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{bayes_path});
  if (!-f $path.'_count') {
    dbg ("No bayes dbs present, cannot scan");
    return 0;
  }

  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("Tie-ing to DB file R/O $name");
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDONLY,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  return 1;

failed_to_tie:
  warn "Cannot open bayes_path $path R/O: $!\n";
  return 0;
}

sub tie_db_writable {
  my ($self) = @_;
  my $main = $self->{main};

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return if ($self->{already_tied} && $self->{is_locked} == 1);
  $self->{already_tied} = 1;

  if (!defined($main->{conf}->{bayes_path})) {
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
    dbg("$$ Trying to get lock on $path pass $i");
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
      if ($lock_age < $now - $max_lock_age) {
	#we got a stale lock, break it
	dbg("$$ Breaking Stale Lockfile!");
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
    dbg("Tie-ing to DB file R/W $name");
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDWR|O_CREAT,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  return 1;

failed_to_tie:
  unlink($self->{lock_file}) ||
     dbg ("Couldn't unlink " . $self->{lock_file} . ": $!\n");

  warn "Cannot open bayes_path $path R/W: $!\n";
  return 0;
}

###########################################################################

sub untie_db {
  my $self = shift;
  dbg("Bayes: untie-ing and destroying lockfile.");

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;
    dbg ("untie-ing $db_var");
    untie %{$self->{$db_var}};
  }

  if ($self->{is_locked}) {
    dbg ("Bayes: files locked, breaking lock.");
    unlink($self->{lock_file}) ||
        dbg ("Couldn't unlink " . $self->{lock_file} . ": $!\n");
    $self->{is_locked} = 0;
  }

  $self->{already_tied} = 0;
}

sub finish {
  $_[0]->untie_db();
}

###########################################################################

# TODO: should we try to get some header data in here too?  possible good
# sources are:
#
# Message-ID (contains spamtool patterns)
# Content-Type (mime boundaries ditto)
# X-Mailer, User-Agent (spamtool signatures)
# Received (should only take last 2 or 3 Received entries)
#
# others can provide spurious clues.  The spambayes folks note that even
# Date headers can subvert testing, if you've got a corpus of spam from
# one date period and nonspam from another!

sub tokenize {
  my ($self, $body) = @_;
  my $wc = 0;
  my @tokens = ();

  for (@{$body}) {
    tr/A-Z/a-z/;

    # include quotes, .'s and -'s for URIs, and [$,]'s for Nigerian-scam strings,
    # and ISO-8859-15 alphas.
    # Some useful tokens: "$31,000,000" "www.clock-speed.net"
    tr/-a-z0-9,_'"\$.\250\270\300-\377 / /cs;

    foreach my $token (split) {
      $token =~ s/^[-'"\.,]+//;        # trim non-alphanum chars at start or end
      $token =~ s/[-'"\.,]+$//;        # so we don't get loads of '"foo' tokens

      next if length($token) < 3 || $token eq "and" || $token eq "the";
      next if length($token) > 25; #TODO
      $wc++;
      push (@tokens, $token);
    }
  }

  ($wc, @tokens);
}

###########################################################################

sub learn {
  my ($self, $isspam, $msgid, $body) = @_;

  if (!defined $body) { return; }
  $self->tie_db_writable();

  $msgid = canonicalize_msgid ($msgid);
  my $seen = $self->{db_seen}->{$msgid};
  if (defined ($seen)) {
    if (($seen eq 's' && $isspam) || ($seen eq 'h' && !$isspam)) {
      dbg ("$msgid: already learnt correctly, not learning twice");
      return;
    } elsif ($seen !~ /^[hs]$/) {
      warn ("db_seen corrupt: value='$seen' for $msgid. ignored");
    } else {
      dbg ("$msgid: already learnt as opposite, forgetting first");
      $self->forget ($msgid, $body);
    }
  }

  if ($isspam) {
    $self->{db_count}->{'nspam'}++;
  } else {
    $self->{db_count}->{'nham'}++;
  }
  my $ns = $self->{db_count}->{'nspam'};
  my $nn = $self->{db_count}->{'nham'};
  $ns ||= 0;
  $nn ||= 0;

  my ($wc, @tokens) = $self->tokenize ($body);
  for (@tokens) {
    if ($isspam) {
      $self->{db_toks_spam}->{$_}++;
    } else {
      $self->{db_toks_ham}->{$_}++;
    }

    # if we don't have both corpora, skip generating probabilities.
    # we can't get useful results without both.
    next if ($nn == 0 || $ns == 0);
    $self->compute_prob_for_token ($_, $ns, $nn);
  }

  $self->{db_seen}->{$msgid} = ($isspam ? 's' : 'h');

  # do this costly operation once every 500 mails
  if ($ns != 0 && $nn != 0 && (($ns+$nn) % 500) == 0) {
    $self->recompute_all_probs();

    # next, dump all dbs to disk. they will be reloaded on next operation.
    # this should help keep memory down
    $self->untie_db();
  }
}

###########################################################################

sub forget {
  my ($self, $msgid, $body) = @_;

  if (!defined $body) { return; }
  $self->tie_db_writable();

  $msgid = canonicalize_msgid ($msgid);
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

  my $ns = $self->{db_count}->{'nspam'};
  my $nn = $self->{db_count}->{'nham'};
  $ns ||= 0;
  $nn ||= 0;

  # protect against going negative
  if ($isspam) {
    $ns--; if ($ns < 0) { $ns = 0; }
    $self->{db_count}->{'nspam'} = $ns;
  } else {
    $nn--; if ($nn < 0) { $nn = 0; }
    $self->{db_count}->{'nham'} = $nn;
  }

  my ($wc, @tokens) = $self->tokenize ($body);
  for (@tokens) {
    if ($isspam) {
      my $count = $self->{db_toks_spam}->{$_} - 1;
      $self->{db_toks_spam}->{$_} = ($count < 0 ? 0 : $count);
    } else {
      my $count = $self->{db_toks_ham}->{$_} - 1;
      $self->{db_toks_ham}->{$_} = ($count < 0 ? 0 : $count);
    }

    # if we don't have both corpora, skip generating probabilities.
    # we can't get useful results without both.
    next if ($nn == 0 || $ns == 0);
    $self->compute_prob_for_token ($_, $ns, $nn);
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

sub canonicalize_msgid {
  my $msgid = shift;
  if (!defined $msgid) { $msgid = time.".$$\@sa_generated"; }

  # remove \r and < and > prefix/suffixes
  chomp $msgid;
  $msgid =~ s/^<//; $msgid =~ s/>.*$//g;

  $msgid;
}

###########################################################################

# now and again, this can be run to rebuild the probabilities cache.
# This cache will be unusable if one of the corpora has not been scanned yet.
# This operation can take a while...
sub recompute_all_probs {
  my ($self) = @_;

  dbg ("bayes: recomputing all probabilities");
  my $start = time;

  $self->tie_db_writable();
  my $ns = $self->{db_count}->{'nspam'};
  my $nn = $self->{db_count}->{'nham'};
  $ns ||= 0;
  $nn ||= 0;
  if ($nn == 0 || $ns == 0) { goto done; }

  my $probstotal = 0;
  my $count = 0;

  my %done = ();
  foreach my $token (keys %{$self->{db_toks_spam}}, keys %{$self->{db_toks_ham}})
  {
    next if (exists $done{$token}); $done{$token}=1;
    my $prob = $self->compute_prob_for_token ($token, $ns, $nn);
    if (defined $prob) { $probstotal += $prob; }
    $count++;
  }

  # for debugging, let's see this figure
  $self->{db_count}->{'robinson_x'} = ($count ? ($probstotal / $count) : 0);
  dbg ("bayes: Robinson x = ".$self->{db_count}->{'robinson_x'});

done:
  my $now = time;
  dbg ("bayes: recomputed all probabilities for ".(scalar keys %done).
        " tokens in ".($now - $start)." seconds");
}

sub compute_prob_for_token {
  my ($self, $token, $ns, $nn) = @_;

  # precompute the probability that that token is spammish
  my $s = $self->{db_toks_spam}->{$token};
  my $n = $self->{db_toks_ham}->{$token};
  $s ||= 0;
  $n ||= 0;

  if (!$USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    return if ($s + $n < 10);      # ignore low-freq tokens
  } else {
    return if ($s + $n < 2);       # ignore hapaxes (1-occurence only)
  }

  my $ratios = ($s / $ns);
  my $ration = ($n / $nn);
  my $prob = ($ratios) / ($ration + $ratios);

  if ($USE_ROBINSON_FX_EQUATION_FOR_LOW_FREQS) {
    # use Robinson's f(x) equation for low-n tokens, instead of just
    # ignoring them
    my $robx = $self->{robinson_x};
    my $robn = $s+$n;
    $prob = ($self->{robinson_s_dot_x} + ($robn * $prob)) /
		  ($ROBINSON_S_CONSTANT + $robn);
  }

  $self->{db_probs}->{$token} = pack ('f', $prob);
  #dbg ("learnt '$token' $s $n  p(s) = $prob");

  return $prob;
}

sub precompute_robinson_constants {
  my $self = shift;

  $self->{robinson_x} = 0.5;	#TODO
  # precompute this here for speed
  $self->{robinson_s_dot_x} = ($self->{robinson_x} * $ROBINSON_S_CONSTANT);
}

###########################################################################
# Finally, the scoring function for testing mail.

sub scan {
  my ($self, $body) = @_;

  if (!$self->tie_db_readonly()) { goto skip; }

  my $ns = $self->{db_count}->{'nspam'};
  my $nn = $self->{db_count}->{'nham'};
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

  my ($wc, @tokens) = $self->tokenize ($body);
  my %pw = map {
    my $pw = $self->{db_probs}->{$_};

    if (!defined $pw) {
      $wc--; ();

    } else {
      $pw = unpack ('f', $pw);

      # enforce (max .01 (min .99 (score))) as per Graham; it allows
      # a majority of spam clues to override 1 or 2 very-strong nonspam clues.
      #
      if ($pw < 0.01) {
	($_ => 0.01);
      } elsif ($pw > 0.99) {
	($_ => 0.99);
      } else {
	($_ => $pw);
      }
    }
  } @tokens;

  if ($wc <= 0) {
    dbg ("cannot use bayes on this message; no tokens found");
    goto skip;
  }

  # now take the $count most significant tokens and calculate probs using
  # Robinson's formula.
  my $count = $N_SIGNIFICANT_TOKENS;
  my $P = 1;
  my $Q = 1;
  for (sort {
              abs($pw{$b} - 0.5) <=> abs($pw{$a} - 0.5)
            } keys %pw)
  {
    if ($count-- < 0) { last; }
    my $pw = $pw{$_};
    next if (abs($pw - 0.5) < $ROBINSON_MIN_PROB_STRENGTH);
    $P *= (1-$pw);
    $Q *= $pw;

    dbg ("bayes token '$_' => $pw (P=$P Q=$Q)");

    # dump token counts as well: requires 2 more db lookups. off by default.
    #my $s = $self->{db_toks_spam}->{$_};
    #my $n = $self->{db_toks_ham}->{$_};
    #dbg ("bayes token '$_' => $pw (spamhits=$s hamhits=$n) (P=$P Q=$Q)");
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

1;
