#!/usr/bin/perl -w
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

use strict;
use warnings;
use vars qw(%scores);

my $threshold = 5;
my %is_spam = ();
my %id_spam = ();
my %lines = ();
my $cffile = "craig-evolve.scores";

print "Reading scores...";
readscores();
print "Reading logs...";
readlogs();
print "Sorting messages...";
sortmessages();

sub sortmessages {
    my ($yy,$nn,$yn,$ny) = (0,0,0,0);

    open(YY,">truepos.log");
    open(NN,">trueneg.log");
    open(YN,">falseneg.log");
    open(NY,">falsepos.log");

    for my $count (0..scalar(keys %lines)-1) {
	
	if($is_spam{$count})
	{
	    if($id_spam{$count})
	    {
		print YY $lines{$count};
		$yy++;
	    }
	    else
	    {
		print YN $lines{$count};
		$yn++;
	    }
	}
	else
	{
	    if($id_spam{$count})
	    {
		print NY $lines{$count};
		$ny++;
	    }
	    else
	    {
		print NN $lines{$count};
		$nn++;
	    }
	}
    }

    print "$yy,$nn,$yn,$ny\n";

    close YY;
    close NY;
    close YN;
    close NN;
}

sub readlogs {
    my $count = 0;

    foreach my $file ("spam.log", "nonspam.log") {
	open (IN, "<$file");

	while (<IN>) {
            next if /^#/;
	    my $this_line = $_;
	    /^.\s+(\d+)\s+\S+\s*/ or next;
	    my $hits = $1;

	    $_ = $'; #'closing quote for emacs coloring
	    s/,,+/,/g; s/^\s+//; s/\s+$//;
	    my $msg_score = 0;
	    foreach my $tst (split (/,/, $_)) {
		next if ($tst eq '');
		if (!defined $scores{$tst}) {
		    warn "unknown test in $file, ignored: $tst\n";
		    next;
		}
		$msg_score += $scores{$tst};
	    }

	    $lines{$count} = $this_line;
	    
	    if ($msg_score >= $threshold) {
		$id_spam{$count} = 1;
	    } else {
		$id_spam{$count} = 0;
	    }

	    if ($file eq "spam.log") {
		$is_spam{$count} = 1;
	    } else {
		$is_spam{$count} = 0;
	    }
	    $count++;
	} 
	close IN;
    }
    print "$count\n";
}

sub readscores {
    system ("./parse-rules-for-masses -d ../rules -d \"$cffile\"") and die;
    require "./tmp/rules.pl";
    print scalar(keys %scores),"\n";
}

