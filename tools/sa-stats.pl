#!/usr/bin/perl -w
#Purpose      : Produce stats for SpamAssassin package
#Authors      : Brad Rathbun <brad@computechnv.com> http://www.computechnv.com/
#             : Bob Apthorpe <apthorpe+sa@cynistar.net> http://www.cynistar.net/~apthorpe/
#             : Duncan Findlay <duncf@debian.org>

# Licensed under the terms of the SpamAssassin distribution (GPL/PAL).


use strict;

#Configuration section
my %opt = ();
$opt{'logfile'} = '/var/log/maillog';		# Log file 
$opt{'sendmail'} = '/usr/sbin/sendmail';	# Path to sendmail stub
$opt{'from'} = 'SpamAssassin System Admin';	# Who is the mail from
$opt{'end'} = "";
$opt{'start'} = "today";

##########################################################
############# Nothing to edit below here #################
##########################################################

my $VERSION = '$Id: sa-stats.pl,v 1.1 2003/04/28 06:47:51 duncf Exp $';

# internal modules (part of core perl distribution)
use Getopt::Long;
use Pod::Usage;
use POSIX qw/strftime floor/;
use Time::Local;
use Date::Manip;

my $tstart = time;

Getopt::Long::Configure("bundling");
GetOptions('logfile|l=s'  => \$opt{'logfile'},
	   'mail=s'       => \$opt{'mail'},
           'sendmail=s'   => \$opt{'sendmail'},
           'from=s'       => \$opt{'from'},
	   'debug|D'      => \$opt{'debug'},
	   'verbose|v'    => \$opt{'verbose'},
	   'help|h'       => \$opt{'help'},
	   'version|V'    => \$opt{'version'},
	   'start|s=s'    => \$opt{'start'},
	   'end|e=s'      => \$opt{'end'})
  or pod2usage({-verbose => 0, -message => "Unknown options.", -exitval => 2});

if ($opt{'help'}) {
  pod2usage({-verbose => 1, -message => "For more information, try perldoc sa-stats.pl"});
}
if ($opt{'version'}) {
  print "sa-stats.pl version ", $VERSION, "\n";
  exit 0;
}

# efficiency; don't rebuild the (constant) hash every loop iteration
my %month_list = ('Jan' => 0,
		  'Feb' => 1,
		  'Mar' => 2,
		  'Apr' => 3,
		  'May' => 4,
		  'Jun' => 5,
		  'Jul' => 6,
		  'Aug' => 7,
		  'Sep' => 8,
		  'Oct' => 9,
		  'Nov' => 10,
		  'Dec' => 11);

#Local variables
my $YEAR = (localtime(time))[5]; # this is years since 1900

my $total = 0;
my $spamcount = 0;
my $spamavg = 0;
my $hamcount = 0;
my $hamavg = 0;
my $threshtotal = 0;

my %spambyhour = ();
my %hambyhour = ();

my ($start, $end) = parse_arg($opt{'start'}, $opt{'end'});

#Open log file
open(LOG, "< $opt{'logfile'}") or die "Can't open $opt{'logfile'}: $!\n";

LINE: while (<LOG>) {

# Agh... this is ugly.
  if (m/
^(\w{3})\s+             # Month
(\d+)\s+                # Day
(\d\d):(\d\d):(\d\d)\s+ # HH:MM:SS
\w+\s+                  # Hostname?
spamd\[\d+\]:\s+        # spamd[PID]
(clean\smessage|identified\sspam)\s  # Status
\(([-0-9.]+)\/([-0-9.]+)\)\s # Score, Threshold
for\s
\w+:\d+\s             # for daf:1000
in\s
[0-9.]+\sseconds,\s+
[0-9]+\sbytes\./x) {  # There's an extra space at the end for some reason.


    #Split line into components
    my $mon = $1;
    my $day = $2;
    my $hour = $3;
    my $min = $4;
    my $sec = $5;
    my $status = $6;
    my $score = $7;
    my $threshold = $8;

    # Convert to absolute time
    my $abstime = timelocal($sec, $min, $hour, $day, $month_list{$mon}, $YEAR);
    my $abshour = floor ($abstime / 3600); # Hours since the epoch

    #If date specified, only process lines matching date
    next LINE if ($abstime < $start);
    # We can assume that logs are chronological
    last if ($abstime > $end);

    #Total score
    $total++;

    if ($status eq "identified spam") {
      #Spam scores
      $spamcount++;
      $spamavg += $score;
      $spambyhour{$abshour}++;

    } elsif ($status eq "clean message") {
      #Nonspam scores
      $hamcount++;
      $hamavg += $score;
      $hambyhour{$abshour}++;
    } else {
      die "Strange error in regexp";
    }

    $threshtotal += $threshold;

  }

}
#Done reading file
close(LOG);

#Calculate some numbers
$spamavg=$spamavg/$spamcount if $spamcount;
$hamavg=$hamavg/$hamcount if $hamcount;
my $threshavg=$threshtotal/$total if $total;
my $spampercent=(($spamcount/$total) * 100) if $total;
my $hampercent=(($hamcount/$total) * 100) if $total;
my $hrsinperiod=(($end-$start) / 3600);
my $emailperhour=($total/$hrsinperiod) if $total;


my $oldfh;
#Open Sendmail if we are mailing it
if ($opt{'mail'}) {
  open (SENDMAIL, "|$opt{'sendmail'} -oi -t -odq") or die "Can't open sendmail: $!\n";
  print SENDMAIL "From: $opt{'from'}\n";
  print SENDMAIL "To: $opt{'mail'}\n";
  print SENDMAIL "Subject: SpamAssassin statistics\n\n";
  $oldfh = select SENDMAIL;
}

my $telapsed = time - $tstart;

#Output results
print  "Report Title     : SpamAssassin - Spam Statistics\n";
print  "Report Date      : ", strftime("%F", localtime), "\n";
print  "Period Beginning : ", strftime("%c", localtime($start)), "\n";
print  "Period Ending    : ", strftime("%c", localtime($end)), "\n";
print  "\n";
printf "Reporting Period : %.2f hrs\n", $hrsinperiod;
print  "--------------------------------------------------\n";
print  "\n";
print  "Note: 'ham' = 'nonspam'\n";
print  "\n";
printf "Total spam rejected   : %8d (%7.2f%%)\n", $spamcount, $spampercent || 0;
printf "Total ham accepted    : %8d (%7.2f%%)\n", $hamcount, $hampercent || 0;
print  "                        -------------------\n";
printf "Total emails processed: %8d (%5.f/hr)\n", $total, $emailperhour || 0;
print  "\n";
printf "Average spam threshold : %11.2f\n", $threshavg || 0;
printf "Average spam score     : %11.2f\n", $spamavg || 0;
printf "Average ham score      : %11.2f\n", $hamavg || 0;
print "\n\n";
print "Statistics by Hour\n";
print "-------------------------------------\n";
print "Hour                 Spam         Ham\n";
print "-------------    --------    --------\n";

my $hour = floor($start/3600);
while ($hour < $end/3600) {
  printf("%s      %8d    %8d\n",
	 strftime("%F, %H", localtime($hour*3600)),
	 $spambyhour{$hour} || 0, $hambyhour{$hour} || 0);
  $hour++;
}
print "\n";
print "Done. Report generated in $telapsed sec.\n";

#Close Senmdmail if it was opened
if ($opt{'mail'}) {
  select $oldfh;
  close (SENDMAIL);
}

#All done
exit 0;

#############################################################################
# Subroutines ###############################################################
#############################################################################

########################################
# Process parms                        #
########################################
sub parse_arg {
  my $startdate = shift;
  my $enddate = shift;

  my $secsinday = 86400;
  my $time = 0;

  my $start = UnixDate($startdate,"%s");
  my $end = UnixDate($enddate, "%s");

  if(!$start && !$end) {
    $end = time;
    $start = $end - $secsinday;
    return ($start, $end);
  }

  if(!$start) {
    $start = $end - $secsinday;
    return ($start, $end);
  }

  if(!$end) {
    $end = $start + $secsinday;
    return ($start, $end);
  }

  if($start > $end) {
    return ($end, $start);
  }

  return ($start, $end);

}

sub dbg {
  my $msg = shift;

  if ($opt{debug}) {
    print STDERR $msg;
  }
}

__END__

=head1 NAME
 
sa-stats.pl - Builds received spam/ham report from mail log
 
=head1 VERSION
 
    $Revision: 1.1 $
 
=head1 SYNOPSIS
 
 Usage: sa-stats.pl [options]

 Options:
   -l, --logfile=filename       logfile to read (default: /var/log/maillog)
   -s, --start                  Sets date/time for start of reporting period
   -e, --end                    Sets date/time for end of reporting period
   -v, --verbose                Sets verbose mode
   -D, --debug                  Sets debug mode
   -h, --help                   Displays this message
   -V, --version                Display version
   --mail=emailaddress          Sends report to emailaddress
   --sendmail                   Location of sendmail binary (default: /usr/sbin/sendmail)
   --from                       Sets From: field of mail


=head1 DESCRIPTION

Creates simple text report of spam/ham detected by SpamAssassin by
parsing the mail log (generally /var/log/maillog)

=head1 DEPENDENCIES
 
=over 4

=item *

Getopt::Long

=item *

POSIX

=item *

Time::Local

=item *

Date::Manip

=back
 
=head1 BUGS
 
None known.
 
=head1 TO DO

=over 4
 
=item *
Find bugs

=item *
Fix bugs

=item *
Don't call /usr/sbin/sendmail directly; use Mail::Internet or Net::SMTP or other standard module

=item *
Add support for piped-in logs, compressed logs (see gzopen() from Compress::Zlib)

=item *
Have --verbose and --debug actually do something.

=back
 
=head1 AUTHORS
 
Brad Rathbun <brad@computechnv.com> http://www.computechnv.com/

Bob Apthorpe <apthorpe+sa@cynistar.net> http://www.cynistar.net/~apthorpe/

Duncan Findlay <duncf@debian.org>

=head1 SEE ALSO

Mail::SpamAssassin
 
=cut

