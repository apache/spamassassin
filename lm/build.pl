#!/usr/bin/perl -w

# Copyright (C) 2002  Daniel Quinlan
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of either the Artistic License or the GNU General
# Public License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.

# *.lm = old format, uses '_' as separator
# *.ln = new format, uses NULL as separator

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
