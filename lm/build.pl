#!/usr/bin/perl -w

# Copyright (C) 2002  Daniel Quinlan
#
# *.lm = old format, uses '_' as separator
# *.ln = new format, uses NULL as separator
#
# @LICENSE

@files = <*.l[mn]>;
open(STDOUT, "> ../rules/languages");
foreach $file (sort @files) {
	$lang = $file;
	$lang =~ s@(.*/)?(.*)\.l[mn]$@$2@;
	open(L, $file);
	while(<L>) {
		s/^([^0-9\s]+).*/$1/;
		if ($file =~ /\.lm$/) {
		    s/^_/\000/;
		    s/_$/\000/;
		}
		print;
	}
	close(L);
	print "0 $lang\n";
}
