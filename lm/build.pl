#!/usr/bin/perl -w

# Copyright (C) 2002  Daniel Quinlan
#
# *.lm = old format, uses '_' as separator
# *.ln = new format, uses NULL as separator
#
# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

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
