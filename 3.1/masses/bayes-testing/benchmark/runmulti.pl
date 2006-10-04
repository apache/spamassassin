#!/usr/bin/perl -w

use strict;

use Proc::Background;

my $hamfoldername = shift;
my $spamfoldername = shift;

my $command = "./runmbox.pl";

my $proc1 = Proc::Background->new($command, $hamfoldername);
my $proc2 = Proc::Background->new($command, $spamfoldername);

while ($proc1->alive() || $proc2->alive()) {
    sleep 1;
}
my $time1 = $proc1->start_time;
my $time2 = $proc1->end_time;
my $time3 = $proc2->start_time;
my $time4 = $proc2->end_time;
print STDERR "Proc1: $time1 -- $time2\n";
print STDERR "Proc2: $time3 -- $time4\n";
