package Mail::SpamAssassin::PhraseFreqs;

use strict;

###########################################################################

sub check_phrase_freqs {
  my ($self, $fulltext, $threshold) = @_;

  $self->{phrase_score} = 0;
  $self->{phrase_hits_hash} = { };

  $self->{conf}->{spamphrase_highest_score} ||= 1;

  my $text = $$fulltext;

  # remove headers, but leave the subject line
  $text =~ s/^.*?Subject: (.*?)\n[A-Z].*?\n\n/$1 /gs;

  $text =~ s/^SPAM: .*$//gm;
  $text =~ s/^Content-.*: .*$//gm;
  $text =~ s/^--.*$//gm;
  $text =~ s/\=\n//gis;

  # strip markup and QP
  $text =~ s/=20/ /gis;
  $text =~ s/=3E/>/gis;         # spam trick, disguise HTML
  $text =~ s/=[0-9a-f][0-9a-f]//gis;
  $text =~ s/\&[-_a-zA-Z0-9]+;/ /gs;
  $text =~ s/<[a-z0-9]+\b[^>]*>//gis;
  $text =~ s/<\/[a-z0-9]+>//gis;

  $text =~ s/[^A-Za-z!]/ /gs;
  $text =~ s/\s+/ /gs;

  # kill ignored stopwords -- too small for us to match
  $text =~ s/ (?:to|of|in|a|an|and|the|on|if|or) / /gs;

  # msg_len_factor: 1000 = 200 words of 5 chars avg.  so a message of 
  # 2000 chars will score 1/2 as much to compensate for having more phrases
  #
  my $msg_len_factor;
  if(length($text) > 500) { $msg_len_factor = 1000 / length($text); }
  # avoid division by zero
  else { $msg_len_factor = 500; }

  # print "words found: $text\n";

  my $lastword;
  while ($text =~ /([a-z]{3,20})\b/ig) {
    if (defined $lastword) { test_word_pair ($self, $lastword, $1); }
    $lastword = $1;
  }

  while ($text =~ /!/g) {
    $self->{phrase_score} += 1;              # add for each excl mark
  }

  # bring the score down to an absolute value (not based on the size
  # of the corpus used to generate them)
  $self->{phrase_score} /= $self->{conf}->{spamphrase_highest_score};

  # and then compensate for message length
  $self->{phrase_score} *= $msg_len_factor;

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

  if ($self->{phrase_score} > $threshold) {
    $self->test_log (sprintf ("score: %3d, hits: %s",
    			$self->{phrase_score}, $self->{phrase_hits}));
    return 1;
  }

  return 0;
}

sub extra_score_phrase_freqs {
  my ($self, $fulltext, $threshold) = @_;
  if ($self->{phrase_score} > $threshold) { return 1; }
  return 0;
}

###########################################################################

sub test_word_pair {
  my ($self, $word1, $word2) = @_;

  my $w = lc $word1." ".$word2;
  my $freq = $self->{conf}->{spamphrase}->{$w};
  return if (!defined $freq);

  $self->{phrase_score} += $freq*10;
  $self->{phrase_hits_hash}->{$w} = $freq;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
