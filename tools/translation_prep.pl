#!/usr/bin/perl

if ($#ARGV!=0) {
    print stderr "Usage: $0 <lang> where <lang> is the two letter suffix for the language\n";
    exit;
}

$lang=$ARGV[0];

link "30_text_$lang.cf", "orig_30_text_$lang.cf";

open IN, "30_text_$lang.cf";
while (<IN>) {
    next unless /^lang $lang describe\s([^\s]+)\s/;
    $rule{$1}=1;
}
close IN;

open IN, "cat *|grep '^describe'|";
open OUT, ">>30_text_$lang.cf";
while (<IN>) {
    next unless /^describe\s([^\s]+)\s/;
    next if $rule{$1};
    print OUT "lang $lang $_";
}