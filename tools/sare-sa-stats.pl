#!/usr/bin/perl

# @hourly /usr/local/bin/sa-stats.pl  --web --n=25 > /var/www/html/spamstat/index.html


# -------------------------------------------------------------
# file:    sa-stats.pl (SARE release)
# created: 2005-01-31
# updated: 2007-01-30
# version: 1.03
# author:  Dallas <dallase@uribl.com>
# desc:    Generates Top Spam/Ham Rules fired for SA 3.1.x installations.
#
#          IMPORTANT NOTES
#
#          SA 3.0.x log files do not have user=<user> in
#          the report: log entries, so this does not work with 3.0.
#          See http://www.rulesemporium.com/programs/sa-stats.txt for
#          a SA 3.0.x version ( no per-domain / per-user support )
#
#          If your top 5 does not contain URIBL_BLACK, see
#          http://www.uribl.com/usage.shtml
# -------------------------------------------------------------

# Per User and Per Domain Statistics...
# -------------------------------------------------------------
#
# ./sa-stats -r postmaster
#    - this would give all stats for postmaster users,
#      regardless of which domain it was for.  handy if you
#      have alot of domain aliases
#
# ./sa-stats -r @domain
#    - this would give all stats for the domain specified.
#      make sure you include the '@' sign before the
#      domain or the script will assume you wanted a user
#      name instead.
#
# ./sa-stats -r user@domain.com
#    - this would give all stats for a specific email address.
#      this assumes you pass 'spamc -u <fullemail>' vs.
#      'spamc -u <userpart>'.  If you do the latter, you simply
#      want to call -r <userpart> instead.
#
# -------------------------------------------------------------

use Getopt::Long;
use Pod::Usage;

my ($LOG_DIR,$FILE,$TOPRULES,$PRINT_TO_WEB,$HELP,$RECIP);

GetOptions (
 'logdir|l=s' => \$LOG_DIR,
 'filename|f=s' => \$FILE,
 'recip|r=s' => \$RECIP,
 'num|n=i' => \$TOPRULES,
 'web|w' => \$PRINT_TO_WEB,
 'help|h' => \$HELP
);

if ($HELP) {
  print "usage: $0 [-l <dir>] [-f <file>] [-n <num>] [-w]\n";
  print "\t--logdir|-l <dir>\tDirectory containing spamd logs\n";
  print "\t--filename|-f <file>\tFile names or regex to look for in the logdir\n";
  print "\t--num|-n <num>\tNumber of top rules to display\n";
  print "\t--web|-w\tMake it web friendly output\n";
  print "\t--help|-h\tPrints this help\n";
  exit;
}

if (!defined $TOPRULES) { $TOPRULES=20 }
if (!defined $LOG_DIR) { $LOG_DIR="/var/log" }
if (!defined $FILE) { $FILE='^maillog$' }  # regex

# LEAVE THE REST ALONE UNLESS YOU KNOW WHAT YOU ARE DOING...
################################################################

my $NUM_EMAIL=0; my $NUM_SPAM=0; my $NUM_HAM=0;
my $EMAIL_HITS=0; my $SPAM_HITS=0; my $HAM_HITS=0;
my %SPAM_RULES=(); my %HAM_RULES=();
my $TOTAL_SPAM_RULES=0; my $TOTAL_HAM_RULES=0;
my $ALSPAM=0; my $ALHAM=0; my $ALNO=0;
my $HAM_SEC=0; my $SPAM_SEC=0; my $EMAIL_SEC=0;

my $footer  = '</div><div id="footer"><p> CGI by Dallas Engelken </p></div>';

opendir (DIR,"$LOG_DIR");
my @logs = grep /$FILE/i, readdir DIR;
closedir DIR;

foreach my $log (@logs) {
  &calcstats($LOG_DIR."/".$log);
}

&summarize();
exit;

#############################

sub calcstats {

 my $log=shift;

 if (!-e $log || -d $log) {
    print "$log not found..\n";
    return;
 }

 open(F,"$log");
 while(<F>) {

  my ($result,$score,$rules,$time,$size,$learn,$recip);
  my $spam=0;
  # for user=, it may be %domain or $GLOBAL or @GLOBAL or user@domain..


  if (/.*result:\s+(\w|\.)\s+(\-?\d+)\s+\-\s+(.*)\s+scantime\=([\d\.]+)\,size\=(\d+).*user=([^\,]+).*autolearn=(\w+)/) {
    $result=$1;
    $score=$2;
    $rules=$3;
    $time=$4;
    $size=$5;
    $recip=$6;
    $learn=$7;
  }
  else {
    next;
  }

  my ($user,$domain);

  if ($recip =~ m/^[\%\@](.+)/) {
    $user   = undef;
    $domain = '@'.$1;
  }
  if ($recip =~ m/(.+)\@(.+)/) {
    $user=$1;
    $domain='@'.$2;
  }
  else {
    $user=$recip;
    $domain='@localhost';
  }

  my $email = $user.$domain;


  next if ($RECIP && $RECIP !~ m/\@/ && $RECIP ne $user);
  next if ($RECIP =~ m/^[\%\@](.+)/ && $RECIP ne $domain);
  next if ($RECIP =~ m/(.+)\@(.+)/ && $RECIP ne $email);

  if ($result eq "Y") {
    $SPAM_SEC+=$time;
  }
  else {
    $HAM_SEC+=$time;
  }
  $EMAIL_SEC+=$time;

  $spam=1 if ($result =~ m/Y/);
  if ($learn =~ /ham/) {
   $ALHAM++;
  }
  elsif ($learn =~ /spam/) {
    $ALSPAM++;
  }
  else {
    $ALNO++;
  }

  my @tmprules=split(/\,/,$rules);
  foreach my $r (@tmprules) {
    if ($spam) {
       $TOTAL_SPAM_RULES++;
       if (defined $SPAM_RULES{$r}) {
            $SPAM_RULES{$r}++;
       }
       else {
            $SPAM_RULES{$r}=1;
       }
    }
    else {
       $TOTAL_HAM_RULES++;
       if (defined $HAM_RULES{$r}) {
            $HAM_RULES{$r}++;
       }
       else {
            $HAM_RULES{$r}=1;
       }
    }
  }

  if ($spam) {
        $NUM_SPAM++;
        $SPAM_HITS += $score;
  }
  else {
        $NUM_HAM++;
        $HAM_HITS += $score;
  }
  $NUM_EMAIL++;
  $EMAIL_HITS += $score;
}
close(F);

}


sub summarize {

  my ($avgspamhits,$avghamhits,$avgemailhits);

  print "Content-type: text/html\n\n" if ($PRINT_TO_WEB);
  print "<pre>" if ($PRINT_TO_WEB);

  if ($NUM_SPAM > 0) {
     $avgspamhits= sprintf("%.2f",$SPAM_HITS/$NUM_SPAM);
     $avgspamtime= sprintf("%.2f",$SPAM_SEC/$NUM_SPAM);
  }
  else {
     $avgspamhits=0;
     $avgspamtime=0;
  }

  if ($NUM_HAM > 0) {
     $avghamhits= sprintf("%.2f",$HAM_HITS/$NUM_HAM);
     $avghamtime= sprintf("%.2f",$HAM_SEC/$NUM_HAM);
  }
  else {
     $avghamhits=0;
     $avghamtime=0;
  }

  if ($NUM_EMAIL > 0) {
     $avgemailhits= sprintf("%.2f",$EMAIL_HITS/$NUM_EMAIL);
     $avgemailtime= sprintf("%.2f",$EMAIL_SEC/$NUM_EMAIL);
  }
  else {
     $avgemailhits=0;
     $avgemailtime=0;
  }


  print "\n\n";

  if ($RECIP) {
    print "SPAM STATS FOR $RECIP\n";
    print "-" x 60 . "\n";
  }

  my $ALTOT=$ALSPAM+$ALHAM;
  printf("Email: %8s  Autolearn: %5s  AvgScore: %6.2f  AvgScanTime: %5.2f sec\n",$NUM_EMAIL,$ALTOT,$avgemailhits,$avgemailtime);
  printf("Spam:  %8s  Autolearn: %5s  AvgScore: %6.2f  AvgScanTime: %5.2f sec\n",$NUM_SPAM,$ALSPAM,$avgspamhits,$avgspamtime);
  printf("Ham:   %8s  Autolearn: %5s  AvgScore: %6.2f  AvgScanTime: %5.2f sec\n",$NUM_HAM,$ALHAM,$avghamhits,$avghamtime);

  &br;
  printf "Time Spent Running SA:      %7.2f hours\n",$EMAIL_SEC/60/60;
  printf "Time Spent Processing Spam: %7.2f hours\n",$SPAM_SEC/60/60;
  printf "Time Spent Processing Ham:  %7.2f hours\n",$HAM_SEC/60/60;

  &br;

  my $count=0;
  print "TOP SPAM RULES FIRED";
  print " FOR $RECIP" if ($RECIP);
  print "\n";

  &hr;
  printf("%4s\t%-24s\t%5s %8s %7s %7s %7s\n","RANK","RULE NAME","COUNT","\%OFMAIL","\%OFSPAM","\%OFHAM");
  &hr;
  foreach my $key (sort { $SPAM_RULES{$b} <=> $SPAM_RULES{$a} } keys %SPAM_RULES) {
    #my $perc1=sprintf("%.2f",($SPAM_RULES{$key}/$NUM_EMAIL)*100);
    my $perc1=sprintf("%.2f",(($SPAM_RULES{$key}+$HAM_RULES{$key})/$NUM_EMAIL)*100);
    my $perc2=sprintf("%.2f",($SPAM_RULES{$key}/$NUM_SPAM)*100);
    my $perc3=sprintf("%.2f",($HAM_RULES{$key}/$NUM_HAM)*100);
    printf("%4d\t%-24s\t%5s\t%6.2f\t%6.2f\t%6.2f\n",$count+1,$key,$SPAM_RULES{$key},$perc1,$perc2,$perc3);
    $count++;
    if ($count >= $TOPRULES && $TOPRULES > 0) {
       last;
    }
  }
  &hr;
  &br;

  $count=0;  # thanks mike.
  print "TOP HAM RULES FIRED";
  print " FOR $RECIP" if ($RECIP);
  print "\n";
  &hr;
  printf("%4s\t%-24s\t%5s %8s %7s %7s %7s\n","RANK","RULE NAME","COUNT","\%OFMAIL","\%OFSPAM","\%OFHAM");
  &hr;
  foreach my $key (sort { $HAM_RULES{$b} <=> $HAM_RULES{$a} } keys %HAM_RULES) {
    #my $perc1=sprintf("%.2f",($HAM_RULES{$key}/$NUM_EMAIL)*100);
    my $perc1=sprintf("%.2f",(($SPAM_RULES{$key}+$HAM_RULES{$key})/$NUM_EMAIL)*100);
    my $perc2=sprintf("%.2f",($SPAM_RULES{$key}/$NUM_SPAM)*100);
    my $perc3=sprintf("%.2f",($HAM_RULES{$key}/$NUM_HAM)*100);
    printf("%4d\t%-24s\t%5s\t%6.2f\t%6.2f\t%6.2f\n",$count+1,$key,$HAM_RULES{$key},$perc1,$perc2,$perc3);
    $count++;
    if ($count >= $TOPRULES && $TOPRULES > 0) {
       last;
    }
  }
  &hr;
  &br;
  print "</pre>\n" if ($PRINT_TO_WEB);
  print $footer if ($PRINT_TO_WEB && $footer ne "");
  print "\n";
}

#######################
sub hr {
 if ($PRINT_TO_WEB) {
   print "<hr size=1 width=50% align=left>";
 }
 else {
   print "-" x 70 ."\n";
 }
}
#######################
sub br {
 if ($PRINT_TO_WEB) {
   print "<br>";
 }
 else {
   print "\n";
 }
}






