#!/usr/bin/perl -w
#Purpose      : Produce stats for SpamAssassin package
#Authors      : Brad Rathbun <brad@computechnv.com> http://www.computechnv.com/
#             : Bob Apthorpe <apthorpe+sa@cynistar.net> http://www.cynistar.net/~apthorpe/
#             : Duncan Findlay <duncf@debian.org>
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

#Configuration section
my %opt = ();
$opt{'logfile'} = '/var/log/maillog';        # Log file 
$opt{'sendmail'} = '/usr/sbin/sendmail';    # Path to sendmail stub
$opt{'from'} = 'SpamAssassin System Admin';    # Who is the mail from
$opt{'end'} = "";
$opt{'start'} = "today";

##########################################################
############# Nothing to edit below here #################
##########################################################

my $VERSION = '$Id: sa-stats.pl,v 1.5 2003/12/28 06:00:28 apthorpe Exp apthorpe $';

# internal modules (part of core perl distribution)
use Getopt::Long;
use Pod::Usage;
use POSIX qw/strftime floor/;
use Time::Local;
use Date::Manip;
use Parse::Syslog;

my $tstart = time;

Getopt::Long::Configure("bundling");
GetOptions('logfile|l=s'  => \$opt{'logfile'},
           'mail=s'       => \$opt{'mail'},
           'sendmail=s'   => \$opt{'sendmail'},
           'from=s'       => \$opt{'from'},
           'debug|D'      => \$opt{'debug'},
           'userstats|u'  => \$opt{'userstats'},
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

#Local variables
my $mean_spam_score = 0;
my $mean_spam_time = 0;
my $mean_spam_bytes = 0;

my $mean_ham_score = 0;
my $mean_ham_time = 0;
my $mean_ham_bytes = 0;

my %stats = ();
# %stats is a multidimensional hash with the following structure:
# $stats{'total'}{'bytes'}
# $stats{'total'}{'count'}
# $stats{'total'}{'time'}
# $stats{'total'}{'threshold'}
# $stats{'ham'}{'bytes'}
# $stats{'ham'}{'count'}
# $stats{'ham'}{'time'}
# $stats{'ham'}{'score'}
# $stats{'ham'}{'byhour'}
# $stats{'spam'}{'bytes'}
# $stats{'spam'}{'count'}
# $stats{'spam'}{'time'}
# $stats{'spam'}{'score'}
# $stats{'spam'}{'byhour'}

my %userstats = ();
# $userstats{$recipient}{'total'}{'bytes'}
# $userstats{$recipient}{'total'}{'count'}
# $userstats{$recipient}{'total'}{'time'}
# $userstats{$recipient}{'ham'}{'bytes'}
# $userstats{$recipient}{'ham'}{'count'}
# $userstats{$recipient}{'ham'}{'time'}
# $userstats{$recipient}{'ham'}{'score'}
# $userstats{$recipient}{'spam'}{'bytes'}
# $userstats{$recipient}{'spam'}{'count'}
# $userstats{$recipient}{'spam'}{'time'}
# $userstats{$recipient}{'spam'}{'score'}

my ($start, $end) = parse_arg($opt{'start'}, $opt{'end'});

die "Can't find " . $opt{'logfile'} . " $!\n" unless (-e $opt{'logfile'});

my $parser = Parse::Syslog->new( $opt{'logfile'} ,
				 year => UnixDate("epoch $start", "%Y"),
				 _last_mon => UnixDate("epoch $start", "%m") - 1);
# Hack for end-of-year support -- sets _last_mon to current month (0 based, not 1 based)

parseloop:
while (my $sl = $parser->next) {
    next parseloop unless ($sl->{'program'} eq 'spamd');
    if ($sl->{'text'} =~ m/
        (clean\smessage|identified\sspam)\s  # Status
        \(([-0-9.]+)\/([-0-9.]+)\)\s         # Score, Threshold
        for\s
        ([^:]+):\d+\s                            # for daf:1000
        in\s
        ([0-9.]+)\sseconds,\s+
        ([0-9]+)\sbytes\.
    /x) {

        # discard records outside defined analysis interval
        next parseloop if ($sl->{'timestamp'} < $start);
        # We can assume that logs are chronological
        last parseloop if ($sl->{'timestamp'} > $end);

        my $status = $1;
        my $score = $2;
        my $threshold = $3;
        my $recipient = $4;
        my $time_processed = $5;
        my $bytes_processed = $6;

		dbg("Found: " . $sl->{'text'} . "\n");
		dbg(" tstamp : " . $sl->{'timestamp'} . "\n");
		dbg("  status: $status\n");
		dbg("  score : $score\n");
		dbg("  thresh: $threshold\n");
		dbg("  recip : $recipient\n");
		dbg("  time  : $time_processed\n");
		dbg("  bytes : $bytes_processed\n\n");

        my $clean_recipient = lc($recipient);
        $clean_recipient =~ s#\+[^@]*(@?)#$1#;

        my $abstime = $sl->{'timestamp'};

        my $abshour = floor ($sl->{'timestamp'} / 3600); # Hours since the epoch

        # aggregate stats
        my $tag = 'unknown';
        if ($status eq "identified spam") {
            $tag = 'spam';
        } elsif ($status eq "clean message") {
            $tag = 'ham';
        } else {
            warn "Strange error in regexp - " . $sl->{'text'} . "\n";
            $tag = 'unknown';
        }

        # Ham/spam stats
        $stats{$tag}{'count'}++;
        $stats{$tag}{'score'} += $score;
        $stats{$tag}{'bytes'} += $bytes_processed;
        $stats{$tag}{'time'} += $time_processed;
        $stats{$tag}{'byhour'}{$abshour}++;

        # Total score
        $stats{'total'}{'count'}++;
        $stats{'total'}{'bytes'} += $bytes_processed;
        $stats{'total'}{'time'} += $time_processed;
        $stats{'total'}{'threshold'} += $threshold;

        if ($opt{'userstats'}) {
            # per-user ham/spam stats
            $userstats{$clean_recipient}{$tag}{'count'}++;
            $userstats{$clean_recipient}{$tag}{'bytes'} += $bytes_processed;
            $userstats{$clean_recipient}{$tag}{'time'} += $time_processed;
            $userstats{$clean_recipient}{$tag}{'score'} += $score;

            # per-user total stats
            $userstats{$clean_recipient}{'total'}{'count'}++;
            $userstats{$clean_recipient}{'total'}{'bytes'} += $bytes_processed;
            $userstats{$clean_recipient}{'total'}{'time'} += $time_processed;
        }

    } else {
        next parseloop;
    }
}

#Calculate some numbers
my $threshavg = 0;
my $spampercent = 0;
my $hampercent = 0;
my $bytesperhour = 0;
my $emailperhour = 0;
my $secperhour = 0;

my $spamcount = $stats{'spam'}{'count'} || 0;
my $hamcount = $stats{'ham'}{'count'} || 0;
my $totalcount = $stats{'total'}{'count'} || 0;

my $hrsinperiod = (($end-$start) / 3600);

if ($totalcount > 0) {
    if ($spamcount > 0) {
        $mean_spam_score = $stats{'spam'}{'score'} / $spamcount;
        $mean_spam_time = $stats{'spam'}{'time'} / $spamcount;
        $mean_spam_bytes = $stats{'spam'}{'bytes'} / $spamcount;
        $spampercent = (($spamcount/$totalcount) * 100);
    }

    if ($hamcount > 0) {
        $mean_ham_score = $stats{'ham'}{'score'} / $hamcount;
        $mean_ham_time = $stats{'ham'}{'time'} / $hamcount;
        $mean_ham_bytes = $stats{'ham'}{'bytes'} / $hamcount;
        $hampercent = (($hamcount/$totalcount) * 100);
    }

    $threshavg = $stats{'total'}{'threshold'} / $totalcount;
    $emailperhour = ($totalcount/$hrsinperiod);
    $bytesperhour = ($stats{'total'}{'bytes'} / $hrsinperiod);
    $secperhour = ($stats{'total'}{'time'} / $hrsinperiod);
}

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
my $rpt = '';
$rpt .=         "Report Title     : SpamAssassin - Spam Statistics\n";
$rpt .=         "Report Date      : " . strftime("%F", localtime) . "\n";
$rpt .=         "Period Beginning : " . strftime("%c", localtime($start)) . "\n";
$rpt .=         "Period Ending    : " . strftime("%c", localtime($end)) . "\n";
$rpt .=         "\n";
$rpt .= sprintf("Reporting Period : %.2f hrs\n", $hrsinperiod);
$rpt .=         "--------------------------------------------------\n";
$rpt .=         "\n";
$rpt .=         "Note: 'ham' = 'nonspam'\n";
$rpt .=         "\n";
$rpt .= sprintf("Total spam detected    : %8d (%7.2f%%)\n", $spamcount, $spampercent || 0);
$rpt .= sprintf("Total ham accepted     : %8d (%7.2f%%)\n", $hamcount, $hampercent || 0);
$rpt .=         "                        -------------------\n";
$rpt .= sprintf("Total emails processed : %8d (%5.f/hr)\n", $totalcount, $emailperhour || 0);
$rpt .=         "\n";
$rpt .= sprintf("Average spam threshold : %11.2f\n", $threshavg || 0);
$rpt .= sprintf("Average spam score     : %11.2f\n", $mean_spam_score || 0);
$rpt .= sprintf("Average ham score      : %11.2f\n", $mean_ham_score || 0);
$rpt .=         "\n";
$rpt .= sprintf("Spam kbytes processed  : %8d   (%5.f kb/hr)\n",
    $stats{'spam'}{'bytes'}/1024,
    $stats{'spam'}{'bytes'}/(1024 * $hrsinperiod));
$rpt .= sprintf("Ham kbytes processed   : %8d   (%5.f kb/hr)\n",
    $stats{'ham'}{'bytes'}/1024,
    $stats{'ham'}{'bytes'}/(1024 * $hrsinperiod));
$rpt .= sprintf("Total kbytes processed : %8d   (%5.f kb/hr)\n",
    $stats{'total'}{'bytes'}/1024, $bytesperhour/1024);
$rpt .=         "\n";
$rpt .= sprintf("Spam analysis time     : %8d s (%5.f s/hr)\n",
    $stats{'spam'}{'time'},
    $stats{'spam'}{'time'}/$hrsinperiod);
$rpt .= sprintf("Ham analysis time      : %8d s (%5.f s/hr)\n",
    $stats{'ham'}{'time'},
    $stats{'ham'}{'time'}/$hrsinperiod);
$rpt .= sprintf("Total analysis time    : %8d s (%5.f s/hr)\n",
    $stats{'total'}{'time'}, $secperhour);
$rpt .=         "\n\n";
$rpt .=         "Statistics by Hour\n";
$rpt .=         "-------------------------------------\n";
$rpt .=         "Hour                 Spam         Ham\n";
$rpt .=         "--------------   --------    --------\n";

my $hour = floor($start/3600);
while ($hour < $end/3600) {
    $rpt .= sprintf("%s   %8d    %8d\n",
        strftime("%F, %H", localtime($hour*3600)),
        $stats{'spam'}{'byhour'}{$hour} || 0,
        $stats{'ham'}{'byhour'}{$hour} || 0);
    $hour++;
}
$rpt .=        "\n\n";

if ($opt{'userstats'}) {
    my $usercount = scalar(keys(%userstats));
    if ($usercount > 0) {
        my $upper_userlimit = ($usercount > 25) ? 25 : $usercount;

        $rpt .=    "Top $upper_userlimit spam victims:\n";
        $rpt .=    "User                               S AvScr   H AvScr      Count    % Count      Bytes    % Bytes       Time     % Time\n";
        $rpt .=    "--------------------------------   -------   -------   -------- ----------   -------- ----------   -------- ----------\n";
        foreach my $user (sort {
          $userstats{$b}{'total'}{'count'} <=> $userstats{$a}{'total'}{'count'}
          } keys %userstats) {
            $rpt .= sprintf("%-32s   %7.2f   %7.2f   %8d (%7.2f%%)   %8d (%7.2f%%)   %8d (%7.2f%%)\n",
              $user, 
    ($userstats{$user}{'spam'}{'count'} > 0) ?
    $userstats{$user}{'spam'}{'score'} / $userstats{$user}{'spam'}{'count'} : 0,
    ($userstats{$user}{'ham'}{'count'} > 0) ?
    $userstats{$user}{'ham'}{'score'} / $userstats{$user}{'ham'}{'count'} : 0,
    $userstats{$user}{'spam'}{'count'},
    ($userstats{$user}{'total'}{'count'} > 0) ?
    $userstats{$user}{'spam'}{'count'} / $userstats{$user}{'total'}{'count'} * 100 : 0,
    $userstats{$user}{'spam'}{'bytes'},
    ($userstats{$user}{'total'}{'bytes'} > 0) ?
    $userstats{$user}{'spam'}{'bytes'} / $userstats{$user}{'total'}{'bytes'} * 100 : 0,
    $userstats{$user}{'spam'}{'time'},
    ($userstats{$user}{'total'}{'time'} > 0) ?
    $userstats{$user}{'spam'}{'time'} / $userstats{$user}{'total'}{'time'} * 100 : 0,
            );
        }
    }
    $rpt .=        "\n";
}

$rpt .=        "Done. Report generated in $telapsed sec.\n";

print $rpt;

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

    # This assertion should always fail.
    die "Warning: start time = end time -> $startdate = $enddate\n"
        if ($start == $end);

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
 
    $Revision: 1.5 $
 
=head1 SYNOPSIS
 
 Usage: sa-stats.pl [options]

 Options:
   -l, --logfile=filename       logfile to read (default: /var/log/maillog)
   -s, --start                  Sets date/time for start of reporting period
   -e, --end                    Sets date/time for end of reporting period
   -u, --userstats              Generates stats for the top 25 spam victims
   -h, --help                   Displays this message
   -V, --version                Display version info
   --mail=emailaddress          Sends report to emailaddress
   --sendmail=/path/to/sendmail Location of sendmail binary (default: /usr/sbin/sendmail)
   --from=emailaddress          Sets From: field of mail          
   -v, --verbose                Sets verbose mode
   -D, --debug                  Sets debug mode

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

=item *

Parse::Syslog;

=back
 
=head1 BUGS
 
=item *

Because of poor year handling in Parse::Syslog, the script may not
work well when the log file dates back to the previous year.
 
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

