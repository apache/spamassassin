#!/usr/bin/perl -w
#
# <@LICENSE>
# ====================================================================
# The Apache Software License, Version 1.1
# 
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
# 
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
# 
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
# 
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
# 
# Portions of this software are based upon public domain software
# originally written at the National Center for Supercomputing Applications,
# University of Illinois, Urbana-Champaign.
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

