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
    /.\s+[-0-9]*\s+[^\s]+\s+([^\s]*)\s*$/;
    my @rules=split /,/,$1;
    my $score = 0.0;
    foreach $rule (@rules)
    {
	$score += $scores{$rule};
	$rulehit{$rule}++;
    }

    if($score < 5)
    {
	foreach $rule (@rules)
	{
	    $falseneg{$rule}++;
	}
	$nfn++;
    }
}

close(SPAM);

while(<NONSPAM>)
{
    /.\s+[-0-9]*\s+[^\s]+\s+([^\s]*)\s*$/;
    my @rules=split /,/,$1;
    my $score = 0.0;
    foreach $rule (@rules)
    {
	$score += $scores{$rule};
	$rulehit{$rule}++;
    }

    if($score >= 5)
    {
	foreach $rule (@rules)
	{
	    $falsepos{$rule}++;
	}
	$nfp++;
    }
}

@fpk = sort { $falsepos{$b}/$rulehit{$b} <=> $falsepos{$a}/$rulehit{$a} } keys %falsepos;

print "COMMON FALSE POSITIVES: ($nfp total)\n-----------------------\n\n";
foreach $key (@fpk)
{
    print sprintf("%0.3f %5d % 0.4f %s\n",$falsepos{$key}/($rulehit{$key}-1),$falsepos{$key},$scores{$key},$key) if $falsepos{$key}>0;
}

@fnk = sort { $falseneg{$b}/$rulehit{$b} <=> $falseneg{$a}/$rulehit{$a} } keys %falseneg;

print "\n\n\nCOMMON FALSE NEGATIVES: ($nfn total)\n-----------------------\n\n";
foreach $key (@fnk)
{
    print sprintf("%0.3f %5d % 0.4f %s\n",$falseneg{$key}/($rulehit{$key}-1),$falseneg{$key},$scores{$key},$key) if $falseneg{$key}>0;
}
