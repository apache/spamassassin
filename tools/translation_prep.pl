#!/usr/bin/perl

if ($#ARGV!=0) {
    print stderr "Usage: $0 <lang>
where <lang> is the two letters suffix for the language
";
    exit;
}

$lang=$ARGV[0];

unlink "orig_30_text_$lang.cf" if -f "orig_30_text_$lang.cf";
system "cp 30_text_$lang.cf orig_30_text_$lang.cf";

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
    $r=$1;
    next if $rule{$r};
    $rule{$r}=1;
    $expr=`cat * |grep $r|grep -v describe|grep -v score|grep -v -e '^test'|grep -v '\#'`;
    $expr=~s/^.*$r\s+//;
    chomp;
    # print "$_+++$expr";
    print OUT "lang $lang $_ $expr";
}
