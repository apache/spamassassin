#!/usr/bin/perl -w

my %falsepos;
my %falseneg;
my $nfp=0;
my $nfn=0;
my %scores;
my %rulehit;

open(SPAM, "<spam.log");
open(NONSPAM, "<nonspam.log");
open(SCORES, "<newscores");

while(<SCORES>)
{
    next unless /^score\s+([^\s]*)\s+([-0-9.]*)/;
    $scores{$1} = $2;
    $falsepos{$1} = 0;
    $falseneg{$1} = 0;
    $rulehit{$1} = 1;
}

close(SCORES);

while(<SPAM>)
{
    next if /^#/;
    /.\s+[-0-9]*\s+[^\s]+\s+([^\s]*)(\s+?:bayes=\S+)\s*?$/;
    my @rules=split /,/,$1;
    my $score = 0.0;
    foreach $rule (@rules)
    {
        next unless (defined ($scores{$rule}));
	$score += $scores{$rule};
	$rulehit{$rule}++;
    }

    if($score < 5)
    {
	foreach $rule (@rules)
	{
            next unless (defined ($scores{$rule}));
	    $falseneg{$rule}++;
	}
	$nfn++;
    }
}

close(SPAM);

while(<NONSPAM>)
{
    next if /^#/;
    /.\s+[-0-9]*\s+[^\s]+\s+([^\s]*)\s*$/;
    next unless defined($1);

    my @rules=split /,/,$1;
    my $score = 0.0;
    foreach $rule (@rules)
    {
        next unless (defined ($scores{$rule}));
	$score += $scores{$rule};
	$rulehit{$rule}++;
    }

    if($score >= 5)
    {
	foreach $rule (@rules)
	{
            next unless (defined ($scores{$rule}));
	    $falsepos{$rule}++;
	}
	$nfp++;
    }
}

@fpk = sort { $falsepos{$b}/($rulehit{$b}||0.0001) <=> $falsepos{$a}/($rulehit{$a}||0.00001) } keys %falsepos;

print "COMMON FALSE POSITIVES: ($nfp total)\n-----------------------\n\n";
foreach $key (@fpk)
{
    print sprintf("%0.3f %5d % 0.4f %s\n",$falsepos{$key}/($rulehit{$key}-1),$falsepos{$key},$scores{$key},$key) if $falsepos{$key}>0;
}

@fnk = sort { $falseneg{$b}/($rulehit{$b}||0.0001) <=> $falseneg{$a}/($rulehit{$a}||0.00001) } keys %falseneg;

print "\n\n\nCOMMON FALSE NEGATIVES: ($nfn total)\n-----------------------\n\n";
foreach $key (@fnk)
{
    print sprintf("%0.3f %5d % 0.4f %s\n",$falseneg{$key}/($rulehit{$key}-1),$falseneg{$key},$scores{$key},$key) if $falseneg{$key}>0;
}
