#!/usr/bin/perl

use Config;
my $perl = $Config{'perlpath'};
my $target = pop @ARGV;

open (OUT, ">$target") or die "cannot write to $target\n";

while (<>) {
  s,^\#!/usr/bin/perl,\#!${perl},g;
  s,^.*REMOVEFORINST.*$,,g;
  print OUT;
}

close OUT or die "cannot write to $target\n";
