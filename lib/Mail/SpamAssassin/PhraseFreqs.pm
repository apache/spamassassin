package Mail::SpamAssassin::PhraseFreqs;

use strict;

###########################################################################

sub _check_phrase_freqs {
  my ($self, $body) = @_;

  $self->{phrase_score} = 0;
  $self->{phrase_hits_hash} = { };
  $self->{conf}->{spamphrase_highest_score} ||= 1;

  my $text = join ("\n", @{$body});

  # remove "Subject:"
  $text =~ s/^Subject://i;

  # remove signature
  my $maxsig = scalar(grep(/\S\s+\S/, @{$body})) / 3 + 1;
  $maxsig = 15 if $maxsig > 15;
  $text =~ s/(\S)\s*\n-- \n((.*\n){1,$maxsig}?)\s*\Z/$1/m;

  # just the words
  $text =~ s/[^A-Za-z]+/ /gs;
  $text =~ s/\s+/ /gs;
  $text =~ tr/A-Z/a-z/;

  # kill ignored stopwords -- too small for us to match
  $text =~ s/ (?:to|of|in|a|an|and|the|on|if|or) / /gs;

  # print "words found: $text\n";

  my $word;
  my $wc = 0;
  my $lastword = "000";		# avoid defined() test in loop
  my $phrase;
  my $freq;

  # don't forget to increase the maximum match length if longer words
  # appear in 40_spam_phrases.cf
  while ($text =~ /\b([a-z]{3,15})\b/g) {
    $word = $1;
    $wc++;
    $phrase = "$lastword $word";
    $freq = $self->{conf}->{spamphrase}->{$phrase};
    if (defined $freq) {
      $self->{phrase_score} += $freq;
      $self->{phrase_hits_hash}->{$phrase} = $freq;
    }
    $lastword = $word;
  }

  # bring the score down to an absolute value (not based on the size
  # of the corpus used to generate them)
  $self->{phrase_score} /= ($self->{conf}->{spamphrase_highest_score} / 10);

  # a message of 400 words will score 1/2 as much to compensate for
  # having more phrases
  if ($wc > 200) {
      $self->{phrase_score} /= ($wc / 200);
  }

  my $hit = '';
  foreach my $k (sort keys %{$self->{phrase_hits_hash}}) {
    #next unless ($self->{phrase_hits_hash}->{$k} >
			 #($self->{conf}->{spamphrase_highest_score} / 10));
    $hit .= ', '.$k;
  }
  $hit =~ s/^, //;

  delete $self->{phrase_hits_hash};
  $self->{phrase_hits} = $hit;

  dbg ("spam-phrase score: ".$self->{phrase_score}.
  			": hits: ".$self->{phrase_hits});
}

sub check_phrase_freqs {
  my ($self, $body, $min, $max) = @_;

  if (!defined($self->{phrase_score})) {
    _check_phrase_freqs($self, $body);
    $self->test_log(sprintf ("phrase: %3d, hits: %s",
			     $self->{phrase_score}, $self->{phrase_hits}));
  }
  return (($min == 0 || $self->{phrase_score} > $min) &&
	  ($max eq "undef" || $self->{phrase_score} <= $max));
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
