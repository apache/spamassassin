#!/usr/bin/perl

my %defines = ();
my $target;
my $infile;
while ($#ARGV >= 2) {
  $_ = shift @ARGV;
  if (/^-D([^\s\=]+)\=(.*)$/) { $defines{$1} = $2; next; }

  last;
}

$infile = $ARGV[0];
$target = $ARGV[1];

use Config;
my $perl = $Config{'perlpath'};

open (IN, "<$infile") or die "cannot read $infile\n";
open (OUT, ">$target") or die "cannot write to $target\n";

# If we're using a CVS build, add the -w switch to turn on warnings
my $minusw = '';
if (-f 'CVS/Entries') {
  $minusw = ' -w';
}

while (<IN>) {
  s,^\#!/usr/bin/perl[-Tw\s]*$,\#!${perl}${minusw}\n,g;
  s,^.*REMOVEFORINST.*$,,g;
  s,\@\@([A-Z]\w+)\@\@,$defines{$1},gs;
  print OUT;
}

close IN;
close OUT or die "cannot write to $target\n";
