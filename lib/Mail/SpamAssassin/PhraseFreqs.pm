package Mail::SpamAssassin::PhraseFreqs;

use strict;

###########################################################################

sub _check_phrase_freqs {
  my ($self, $body) = @_;

  $self->{phrase_score} = 0;
  $self->{phrase_hits_hash} = { };
  $self->{conf}->{spamphrase_highest_score} ||= 1;

  my @local = @{$body};
  $local[0] =~ s/^Subject://i;

  my $last;
  my $word;
  my $wc = 0;
  my $phrase;
  my $freq;

  for (@local) {
      $last = "";		# avoid defined() test in loop
      tr/A-Za-z/ /cs;
      tr/A-Z/a-z/;
      foreach my $word (split) {
	  # kill ignored stopwords -- too small for us to match
	  next if length($word) < 3 || $word eq "and" || $word eq "the";
	  $wc++;
	  $phrase = "$last $word";
	  $freq = $self->{conf}->{spamphrase}->{$phrase};
	  if (defined $freq) {
	      $self->{phrase_score} += $freq;
	      $self->{phrase_hits_hash}->{$phrase} = $freq;
	  }
	  $last = $word;
      }
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
  }
  if (($min == 0 || $self->{phrase_score} > $min) &&
      ($max eq "undef" || $self->{phrase_score} <= $max))
  {
      if ($self->{phrase_score}) {
	  if ($self->{conf}->{detailed_phrase_score}) {
	      $self->test_log(sprintf ("score: %d, hits: %s",
				       $self->{phrase_score},
				       $self->{phrase_hits}));
	  }
	  else {
	      $self->test_log(sprintf ("score: %d", $self->{phrase_score}));
	  }
      }
      return 1;
  }
  return 0;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
