#!/usr/bin/perl

use strict;

my $FRAG_LEN = 3;

my %fragments = ();
my $word_num = 0;

if (@ARGV == 0) {
    print STDERR "Usage: triplets.pl dict_file > triplets.txt\n";
    exit(1);
}

while(<>) {
  chomp;

  $word_num++;

  my $word_len = length($_);

  # Ignore proper names
  next if ($_ =~ /[^a-z]/);

  next if ($word_len < $FRAG_LEN);

  if ($word_len == $FRAG_LEN) {
    $fragments{$_} = 1;
    next;
  }

  my $i;

  for ($i = 0; $i < ($word_len - $FRAG_LEN); $i++) {
    my $frag = substr $_, $i, $FRAG_LEN;
    $fragments{$frag} = 1;
  }

  if ($word_num % 1000 == 0) {
    print STDERR ".";
  }
}

print STDER "\n\n$word_num words processed\n";


print join("\n", keys(%fragments)), "\n";
