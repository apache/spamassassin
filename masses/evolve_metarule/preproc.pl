#!/usr/bin/perl -w
# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#
# Produces an output file containing a sparse matrix to be loaded into
# evolve_metarules.  This particular configuration looks for the __FRAUD_AAA
# rules, but you can change the regex to be whatever you want.
#
# Usage: preproc.pl {ham.log} {spam.log} {rules.dat} {hits.dat}
#
# Output file format for rules.dat:
# rule_name
# ...
#
# Output file format (unsigned ascii integers) for hits.dat:
# num_rules
# max_hits
# num_patterns
# is_spam pattern_count pattern_size (rule_no){pattern_size}
# ...

use strict;

# Search for matching rules in the SpamAssassin rules directory.
my %rules;
open (RULE_OUT, ">", $ARGV[2] || "rules.dat") || die $!;
foreach my $file (<../../rules/*.cf>) {
	open (CONFIG, "<", $file) || die $!;
	while (<CONFIG>) {
		if (/^(?:header|body|uri|rawbody|full|meta)\s+(__FRAUD_[A-Z]{3})\s/) {
			$rules{$1} = (scalar keys %rules);
			printf RULE_OUT "%s\n", $1;
		}
	}
	close (CONFIG) || die $!;
}
close (RULE_OUT) || die $!;

# This is to find the pattern hitting the most rules.
my $largest_pattern = 0;

# ham_patterns: Hash containing all of the unique ham patterns that we have
# 	seen so far and how many of each we have seen.
# ham_pattern_len: How many entries are in each pattern.   This is really only
# 	here so that I can be lazy later.
my (%ham_patterns, %ham_pattern_len);
open (HAM, "<", $ARGV[0] || "ham.log" ) || die $!;
while (<HAM>) {
	# Ignore comments.
	next if /^#/;

	# Rule hits are in the fourth field.
	my (undef,undef,undef, $test_str, undef) = split /\s/;

	# Extract the relevant rule hits and sort them by column number.
	my @tests;
	foreach my $r (split(/,/, $test_str)) {
          my $hits = 1;
          # Support compacted RULE(hitcount) format
          if ($r =~ s/\((\d+)\)$//) {
            $hits = $1;
          }
          next unless exists $rules{$r};
          push @tests, $r for (1 .. $hits);
        }
	my @hits = sort map { $rules{$_} } @tests;

	# Count the number of occurrences and size of this pattern.
	$ham_patterns{join (' ', @hits)}++;
	$ham_pattern_len{join (' ', @hits)} = scalar(@hits);

	# Keep track of the largest pattern that we have seen thus far.
	if ( scalar(@hits) > $largest_pattern) {
		$largest_pattern = scalar(@hits);
	}
}
close (HAM);
delete $ham_patterns{''};

# spam_patterns: Hash containing all of the unique spam patterns that we have
# 	seen so far and how many of each we have seen.
# spam_pattern_len: How many entries are in each pattern.   This is really only
# 	here so that I can be lazy later.
my (%spam_patterns, %spam_pattern_len);
open (SPAM, "<", $ARGV[1] || "spam.log") || die $!;
while (<SPAM>) {
	# Ignore comments.
	next if /^#/;

	# Rule hits are in the fourth field.
	my (undef,undef,undef, $test_str, undef) = split /\s/;

	# Extract the relevant rule hits and sort them by column number.
	my @tests;
	foreach my $r (split(/,/, $test_str)) {
          my $hits = 1;
          # Support compacted RULE(hitcount) format
          if ($r =~ s/\((\d+)\)$//) {
            $hits = $1;
          }
          next unless exists $rules{$r};
          push @tests, $r for (1 .. $hits);
        }
	my @hits = sort map { $rules{$_} } @tests;

	# Count the number of occurrences and size of this pattern.
	$spam_patterns{join (' ', @hits)}++;
	$spam_pattern_len{join (' ', @hits)} = scalar(@hits);

	# Keep track of the largest pattern that we have seen thus far.
	if ( scalar(@hits) > $largest_pattern) {
		$largest_pattern = scalar(@hits);
	}
}
close (SPAM);
delete $spam_patterns{''};

# Write things out to the data file in the format mentioned above.
open (DAT, ">", $ARGV[3] || "hits.dat") || die $!;

printf DAT "%d\n", scalar(keys %rules);
printf DAT "%d\n", $largest_pattern;
printf DAT "%d\n", scalar(keys %ham_patterns) + scalar(keys %spam_patterns);

foreach my $pattern (keys %ham_patterns) {
	printf DAT "0 %d %d %s\n", $ham_patterns{$pattern}, $ham_pattern_len{$pattern}, $pattern;
}

foreach my $pattern (keys %spam_patterns) {
	printf DAT "1 %d %d %s\n", $spam_patterns{$pattern}, $spam_pattern_len{$pattern}, $pattern;
}

close  (DAT);
