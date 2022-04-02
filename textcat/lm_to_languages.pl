#!/usr/bin/perl

#
# Usage: lm_to_languages.pl <indir> <languages>
#
# Packs directory of .lm files into SA "languages" file
#

die "Invalid languages" unless $ARGV[1];
die "Invalid indir" unless -d $ARGV[0];

load_models($ARGV[0]);

sub load_models {
  my ($indir) = @_;

  opendir(IN, $indir) or die;
  my @files = grep { /\.lm$/ } readdir(IN);
  closedir(IN) or die;
  die unless @files;

  open(LANGUAGES, ">$ARGV[1]") or die;
  binmode LANGUAGES or die;

  foreach my $f (sort @files) {
    my $outl = $f;
    $outl =~ s/\.lm$//;
    $outl =~ s!.*/!!;
    open(IN, "$indir/$f") or die;
    binmode IN or die;
    my $cnt = 0;
    while (<IN>) {
      s/\r?\n$//;
      /^([^0-9\s]+)/ or die;
      print LANGUAGES "$1\n" or die;
      $cnt++;
    }
    close IN or die;
    print LANGUAGES "0 $outl\n" or die;
    print STDERR "Read $outl ($cnt)\n";
  }

  close LANGUAGES or die;
  print STDERR "Wrote $ARGV[1]\n";
}

