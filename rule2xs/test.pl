#!/usr/bin/perl
use warnings;
use lib '.';
use lib 'blib/arch/auto/TST';
use TST;
my $matches = TST::scan(join ' ', @ARGV);
print "JMD ".join(' ',@$matches)."\n";
