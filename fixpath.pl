#!/usr/bin/perl

use Config;
my $perl = $Config{'perlpath'};
my $target = pop @ARGV;

open (OUT, ">$target") or die "cannot write to $target\n";

# If we're using a CVS build, add the -w switch to turn on warnings
my $minusw = '';
if (-f 'CVS/Entries') {
  $minusw = ' -w';
}

while (<>) {
  s,^\#!/usr/bin/perl(?:| -w),\#!${perl}${minusw},g;
  s,^.*REMOVEFORINST.*$,,g;
  print OUT;
}

close OUT or die "cannot write to $target\n";
