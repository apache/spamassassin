#!/usr/bin/perl -w

use strict;
use Proc::Background;

my %procs;

for my $folder (@ARGV) {
    $procs{$folder} = Proc::Background->new("./runmbox.pl", $folder);
}

sleep 1 while (grep {$procs{$_}->alive} keys %procs);

for my $folder (keys %procs) {
    my $time = $procs{$folder}->end_time - $procs{$folder}->start_time;
    print STDERR "$folder: $time\n";
}
