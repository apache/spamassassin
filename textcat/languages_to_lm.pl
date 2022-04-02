#!/usr/bin/perl

#
# Usage: languages_to_lm.pl <languages> <outdir>
#
# Unpacks contents of SA "languages" file as .lm files into <outdir>
#

die "Outdir not given" unless $ARGV[1];
die "Languages file not found" unless -f $ARGV[0];
unless (-d $ARGV[1]) {
  mkdir $ARGV[1] or die $@;
}

dump_models($ARGV[0]);

sub dump_models {
  my ($languages_filename) = @_;

  local *LM;
  if (!open(LM, $languages_filename)) {
    die "textcat: cannot open languages file $languages_filename: $!\n";
  }

  { my($inbuf,$nread,$text); $text = '';
    while ( $nread=read(LM,$inbuf,16384) ) { $text .= $inbuf }
    defined $nread  or die "error reading $languages_filename: $!";
    @lm = split(/\n/, $text, -1);
  }

  close(LM)  or die "error closing $languages_filename: $!";

  my @ngram;
  # create language ngram maps once
  for (@lm) {
    # look for end delimiter
    if (/^0 (.+)/) {
      my $lang = $1;
      open(OUT, ">$ARGV[1]/$lang.lm");
      binmode OUT or die;
      foreach my $n (@ngram) {
        print OUT $n."\n";
      }
      close OUT or die;
      print "Wrote $ARGV[1]/$lang.lm\n";
      # reset for next language
      @ngram = ();
    }
    else {
      push @ngram, $_;
    }
  }
}

