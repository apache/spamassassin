#!/usr/bin/perl -w
#Purpose      : Produce stats for SpamAssassin package
#Authors      : Brad Rathbun <brad@computechnv.com> http://www.computechnv.com/
#             : Bob Apthorpe <apthorpe+sa@cynistar.net> http://www.cynistar.net/~apthorpe/
#             : Duncan Findlay <duncf@debian.org>
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

# Configuration section
my %opt = ();
$opt{'logfile'} = '/var/log/maillog';        # Log file
$opt{'sendmail'} = '/usr/sbin/sendmail';    # Path to sendmail stub
$opt{'from'} = 'SpamAssassin System Admin';    # Who is the mail from
$opt{'end'} = "";
$opt{'start'} = "today";

my $diag = '';
$diag .= "Default options:\n" . join('', map { "opt{$_} => " . ($opt{$_} || '<undefined>') . "\n" } (sort keys %opt));
# &vdbg($diag); # This won't work until *after* getopt() is called. Duh.

##########################################################
############# Nothing to edit below here #################
##########################################################

my $VERSION = '$Id$';
my ($VER_NUM) = '$Revision: 6256 $' =~ m#\$Revision:\s+(\S+)#o;

# internal modules (part of core perl distribution)
use Getopt::Long;
use Pod::Usage;
use POSIX qw/strftime floor/;
use Time::Local;
use Date::Manip;
use Parse::Syslog;

my %timing = ();
$timing{'start'} = 0;
$timing{'end'} = 0;
$timing{'hrsinperiod'} = 0;
$timing{'telapsed'} = time;

Getopt::Long::Configure("bundling");
GetOptions('logfile|l=s'  => \$opt{'logfile'},
           'mail=s'       => \$opt{'mail'},
           'sendmail=s'   => \$opt{'sendmail'},
           'from=s'       => \$opt{'from'},
           'debug|D'      => \$opt{'debug'},
           'userstats|u'  => \$opt{'userstats'},
           'verbose|v'    => \$opt{'verbose'},
           'html|H'       => \$opt{'html'},
           'top|T:25'     => \$opt{'topusers'},
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

# No point in specifying topusers w/o specifying userstats; coerce -u if -T
if ($opt{'topusers'}) {
    $opt{'userstats'} = 1;
}

$diag .= "\nUser options:\n" . join('', map { "opt{$_} => " . ($opt{$_} || '<undefined>') . "\n" } (sort keys %opt));
&vdbg($diag . "\n");

# Local variables

# %stats is a multidimensional hash with the following structure:
my %stats = ();

$stats{'spam'}{'mean_score'} = 0;
$stats{'spam'}{'mean_time'} = 0;
$stats{'spam'}{'mean_bytes'} = 0;

$stats{'ham'}{'mean_score'} = 0;
$stats{'ham'}{'mean_time'} = 0;
$stats{'ham'}{'mean_bytes'} = 0;

$stats{'total'}{'bytes'} = 0;
$stats{'total'}{'count'} = 0;
$stats{'total'}{'time'} = 0;
$stats{'total'}{'score'} = 0;
# $stats{'total'}{'byhour'}{$hr}
$stats{'total'}{'threshold'} = 0;

$stats{'ham'}{'bytes'} = 0;
$stats{'ham'}{'count'} = 0;
$stats{'ham'}{'time'} = 0;
$stats{'ham'}{'score'} = 0;
# $stats{'ham'}{'byhour'}{$hr}

$stats{'spam'}{'bytes'} = 0;
$stats{'spam'}{'count'} = 0;
$stats{'spam'}{'time'} = 0;
$stats{'spam'}{'score'} = 0;
# $stats{'spam'}{'byhour'}{$hr}

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

# my ($start, $end) = parse_arg($opt{'start'}, $opt{'end'});
($timing{'start'}, $timing{'end'}) = parse_arg($opt{'start'}, $opt{'end'});

&vdbg("Timing:\nstart = $timing{'start'} " . UnixDate("epoch " . $timing{'start'}, '%C')
           . "\n  end = $timing{'end'} "   . UnixDate("epoch " . $timing{'end'}, '%C') . "\n\n");

die "Can't find " . $opt{'logfile'} . " $!\n" unless (-e $opt{'logfile'} || ($opt{'logfile'} eq '-'));

my $logyear = UnixDate("epoch " . $timing{'start'}, "%Y");
my $logmonth = UnixDate("epoch " . $timing{'start'}, "%m") - 1;

&vdbg("Creating log parser: Parse::Syslog->new(" . $opt{'logfile'}
    . ", year => $logyear, _last_mon => $logmonth,)\n"
    . "Note that _last_mon = month - 1\n\n");

my $parser = Parse::Syslog->new( $opt{'logfile'} ,
                                 year => $logyear,
                                 _last_mon => $logmonth,);
# Hack for end-of-year support -- sets _last_mon to current month (0 based, not
# 1 based)

&vdbg("##### Entering parseloop:\n\n");

parseloop:
while (my $sl = $parser->next) {
    &vdbg('Found log entry at ' . $sl->{'timestamp'} . ' for ' . $sl->{'program'} . ' containing ' . $sl->{'text'} . "\n");
    next parseloop unless ($sl->{'program'} eq 'spamd');
    if ($sl->{'text'} =~ m/
        (clean\smessage|identified\sspam)\s  # Status
        \(([-0-9.]+)\/([-0-9.]+)\)\s         # Score, Threshold
        for\s
        ([^:]+):\d+\s                        # for daf:1000
        in\s
        ([0-9.]+)\sseconds,\s+
        ([0-9]+)\sbytes\.
    /x) {

        # discard records outside defined analysis interval
        next parseloop if ($sl->{'timestamp'} < $timing{'start'});
        # We can assume that logs are chronological
        last parseloop if ($sl->{'timestamp'} > $timing{'end'});

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
        $stats{'total'}{'score'} += $score;
        $stats{'total'}{'bytes'} += $bytes_processed;
        $stats{'total'}{'time'} += $time_processed;
        $stats{'total'}{'byhour'}{$abshour}++;
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

&vdbg("##### Exiting parseloop:\n\n");

#Calculate some numbers
my %aggregate_stats = ();

$aggregate_stats{'threshavg'} = 0;
$aggregate_stats{'spampercent'} = 0;
$aggregate_stats{'hampercent'} = 0;
$aggregate_stats{'bytesperhour'} = 0;
$aggregate_stats{'emailperhour'} = 0;
$aggregate_stats{'secperhour'} = 0;

$timing{'hrsinperiod'} = (($timing{'end'} - $timing{'start'}) / 3600);

if ($stats{'total'}{'count'} > 0) {
    $stats{'total'}{'mean_score'} = ($stats{'total'}{'score'} || 0) / $stats{'total'}{'count'};

    if ($stats{'spam'}{'count'} > 0) {
        $stats{'spam'}{'mean_score'} = $stats{'spam'}{'score'} / $stats{'spam'}{'count'};
        $stats{'spam'}{'mean_time'} = $stats{'spam'}{'time'} / $stats{'spam'}{'count'};
        $stats{'spam'}{'mean_bytes'} = $stats{'spam'}{'bytes'} / $stats{'spam'}{'count'};
        $aggregate_stats{'spampercent'} = (($stats{'spam'}{'count'}/$stats{'total'}{'count'}) * 100);
    }

    if ($stats{'ham'}{'count'} > 0) {
        $stats{'ham'}{'mean_score'} = $stats{'ham'}{'score'} / $stats{'ham'}{'count'};
        $stats{'ham'}{'mean_time'} = $stats{'ham'}{'time'} / $stats{'ham'}{'count'};
        $stats{'ham'}{'mean_bytes'} = $stats{'ham'}{'bytes'} / $stats{'ham'}{'count'};
        $aggregate_stats{'hampercent'} = (($stats{'ham'}{'count'}/$stats{'total'}{'count'}) * 100);
    }

    $aggregate_stats{'threshavg'} = $stats{'total'}{'threshold'} / $stats{'total'}{'count'};
    $aggregate_stats{'emailperhour'} = ($stats{'total'}{'count'}/$timing{'hrsinperiod'});
    $aggregate_stats{'bytesperhour'} = ($stats{'total'}{'bytes'} / $timing{'hrsinperiod'});
    $aggregate_stats{'secperhour'} = ($stats{'total'}{'time'} / $timing{'hrsinperiod'});

    foreach my $partition (qw(ham spam total)) {
        $stats{$partition}{'d_mean_score'} = sprintf("%.2f", $stats{$partition}{'mean_score'});
        $stats{$partition}{'d_kbytes'} = sprintf("%.2f", $stats{$partition}{'bytes'} / 1024);
        $stats{$partition}{'d_mbytes'} = sprintf("%.2f", $stats{$partition}{'bytes'} / (1024 * 1024));
        foreach my $metric (qw(count bytes time)) {
            if ($partition eq 'total') {
                $stats{'total'}{'percent'}{$metric} = '100%';
            } else {
                if (defined($stats{'total'}{$metric}) && ($stats{'total'}{$metric} > 0)) {
                    $stats{$partition}{'percent'}{$metric} =
                        sprintf("%.2f%%", 100 * ($stats{$partition}{$metric} || 0) / $stats{'total'}{$metric});
                } else {
                    $stats{$partition}{'percent'}{$metric} = '-- %';
                }
            }

            $stats{$partition}{'perhour'}{$metric} =
                sprintf("%.2f", ($stats{$partition}{$metric} || 0) / $timing{'hrsinperiod'});
        }
        $stats{$partition}{'d_time'} = sprintf("%.1f", $stats{$partition}{'time'});
        $stats{$partition}{'perhour'}{'d_kbytes'} = sprintf("%.2f", $stats{$partition}{'perhour'}{'bytes'} / 1024);
        $stats{$partition}{'perhour'}{'d_mbytes'} = sprintf("%.2f", $stats{$partition}{'perhour'}{'bytes'} / (1024 * 1024));
    }

}

$timing{'telapsed'} = time - $timing{'telapsed'};

# build report
my $rpt = '';
if ($opt{'html'}) {
    $rpt = &build_html_report(\%timing, \%stats, \%userstats, \%aggregate_stats, );
} else {
    $rpt = &build_text_report(\%timing, \%stats, \%userstats, \%aggregate_stats, );
}

# send report via mail or just print it out
if ($opt{'mail'}) {
    open (SENDMAIL, "|$opt{'sendmail'} -oi -t -odq") or die "Can't open sendmail: $!\n";
    print SENDMAIL "From: $opt{'from'}\n";
    print SENDMAIL "To: $opt{'mail'}\n";
    print SENDMAIL "Subject: SpamAssassin statistics\n\n";
    print SENDMAIL $rpt;
    close (SENDMAIL);
} else {
    print $rpt;
}

#All done
exit 0;

#############################################################################
# Subroutines ###############################################################
#############################################################################


########################################
# Build text report                    #
########################################
sub build_text_report {
    my $Rh_timing = shift;
    my $Rh_stats = shift;
    my $Rh_userstats = shift;
    my $Rh_aggregate_stats = shift;

    my $rpt = '';
    $rpt .=         "Report Title     : SpamAssassin - Spam Statistics\n";
    $rpt .=         "Report Date      : " . strftime("%Y-%m-%d", localtime) . "\n";
    $rpt .=         "Period Beginning : " . strftime("%c", localtime($Rh_timing->{'start'})) . "\n";
    $rpt .=         "Period Ending    : " . strftime("%c", localtime($Rh_timing->{'end'})) . "\n";
    $rpt .=         "\n";
    $rpt .= sprintf("Reporting Period : %.2f hrs\n", $Rh_timing->{'hrsinperiod'});
    $rpt .=         "--------------------------------------------------\n";
    $rpt .=         "\n";
    $rpt .=         "Note: 'ham' = 'nonspam'\n";
    $rpt .=         "\n";
    $rpt .= sprintf("Total spam detected    : %8d (%7.2f%%)\n", $Rh_stats->{'spam'}{'count'}, $Rh_aggregate_stats->{'spampercent'} || 0);
    $rpt .= sprintf("Total ham accepted     : %8d (%7.2f%%)\n", $Rh_stats->{'ham'}{'count'}, $Rh_aggregate_stats->{'hampercent'} || 0);
    $rpt .=         "                        -------------------\n";
    $rpt .= sprintf("Total emails processed : %8d (%5.f/hr)\n", $Rh_stats->{'total'}{'count'}, $Rh_aggregate_stats->{'emailperhour'} || 0);
    $rpt .=         "\n";
    $rpt .= sprintf("Average spam threshold : %11.2f\n", $Rh_aggregate_stats->{'threshavg'} || 0);
    $rpt .= sprintf("Average spam score     : %11.2f\n", $Rh_stats->{'spam'}{'mean_score'} || 0);
    $rpt .= sprintf("Average ham score      : %11.2f\n", $Rh_stats->{'ham'}{'mean_score'} || 0);
    $rpt .=         "\n";
    $rpt .= sprintf("Spam kbytes processed  : %8d   (%5.f kb/hr)\n",
        $Rh_stats->{'spam'}{'bytes'}/1024,
        $Rh_stats->{'spam'}{'bytes'}/(1024 * $Rh_timing->{'hrsinperiod'}));
    $rpt .= sprintf("Ham kbytes processed   : %8d   (%5.f kb/hr)\n",
        $Rh_stats->{'ham'}{'bytes'}/1024,
        $Rh_stats->{'ham'}{'bytes'}/(1024 * $Rh_timing->{'hrsinperiod'}));
    $rpt .= sprintf("Total kbytes processed : %8d   (%5.f kb/hr)\n",
        $Rh_stats->{'total'}{'bytes'}/1024, $Rh_aggregate_stats->{'bytesperhour'}/1024);
    $rpt .=         "\n";
    $rpt .= sprintf("Spam analysis time     : %8d s (%5.f s/hr)\n",
        $Rh_stats->{'spam'}{'time'},
        $Rh_stats->{'spam'}{'time'}/$Rh_timing->{'hrsinperiod'});
    $rpt .= sprintf("Ham analysis time      : %8d s (%5.f s/hr)\n",
        $Rh_stats->{'ham'}{'time'},
        $Rh_stats->{'ham'}{'time'}/$Rh_timing->{'hrsinperiod'});
    $rpt .= sprintf("Total analysis time    : %8d s (%5.f s/hr)\n",
        $Rh_stats->{'total'}{'time'}, $Rh_aggregate_stats->{'secperhour'});
    $rpt .=         "\n\n";
    $rpt .=         "Statistics by Hour\n";
    $rpt .=         "----------------------------------------------------\n";
    $rpt .=         "Hour                          Spam               Ham\n";
    $rpt .=         "-------------    -----------------    --------------\n";

    my $hour = floor($Rh_timing->{'start'}/3600);

    while ($hour < $Rh_timing->{'end'}/3600) {

        my $hourly_spam_percent = 0;
        my $hourly_ham_percent = 0;

        if (defined($Rh_stats->{'total'}{'byhour'}{$hour}) && ($Rh_stats->{'total'}{'byhour'}{$hour} > 0)) {
            if (!defined($Rh_stats->{'spam'}{'byhour'}{$hour}) || $Rh_stats->{'spam'}{'byhour'}{$hour} == 0) {
                $Rh_stats->{'spam'}{'byhour'}{$hour} = 0;
                $hourly_ham_percent = 100;
            } elsif (!defined($Rh_stats->{'ham'}{'byhour'}{$hour}) || $Rh_stats->{'ham'}{'byhour'}{$hour} == 0) {
                $Rh_stats->{'ham'}{'byhour'}{$hour} = 0;
                $hourly_spam_percent = 100;
            } else {
                $hourly_spam_percent = 100 * $Rh_stats->{'spam'}{'byhour'}{$hour} / $Rh_stats->{'total'}{'byhour'}{$hour};
                $hourly_ham_percent = 100 * $Rh_stats->{'ham'}{'byhour'}{$hour} / $Rh_stats->{'total'}{'byhour'}{$hour};
            }
        }

        $rpt .= sprintf("%-16s   %8d (%3d%%)   %8d (%3d%%)\n",
            strftime("%Y-%m-%d %H", localtime($hour*3600)),
            $Rh_stats->{'spam'}{'byhour'}{$hour} || 0,
            $hourly_spam_percent,
            $Rh_stats->{'ham'}{'byhour'}{$hour} || 0,
            $hourly_ham_percent);
        $hour++;
    }
    $rpt .= "\n\n";

    if ($opt{'userstats'}) {
        my $topusers = 25;
        if (defined($opt{'topusers'}) && ($opt{'topusers'} > 0)) {
            $topusers = $opt{'topusers'};
        }
        my $usercount = scalar(keys(%{$Rh_userstats}));
        if ($usercount > 0) {
            my $upper_userlimit = ($usercount > $topusers) ? $topusers : $usercount;

            $rpt .=    "Top $upper_userlimit spam victims:\n";
            $rpt .=    "User                               S AvScr   H AvScr      Count    % Count      Bytes    % Bytes       Time     % Time\n";
            $rpt .=    "--------------------------------   -------   -------   -------- ----------   -------- ----------   -------- ----------\n";
            foreach my $user (sort {
              $Rh_userstats->{$b}{'total'}{'count'} <=> $Rh_userstats->{$a}{'total'}{'count'}
              } keys %{$Rh_userstats}) {

                foreach my $partition (qw(spam ham total)) {
                    foreach my $metric (qw(score bytes count time)) {
                        $Rh_userstats->{$user}{$partition}{$metric} ||= 0;
                    }
                }

                $rpt .= sprintf("%-32s   %7.2f   %7.2f   %8d (%7.2f%%)   %8d (%7.2f%%)   %8d (%7.2f%%)\n",
                $user,
                ($Rh_userstats->{$user}{'spam'}{'count'} > 0) ?
                $Rh_userstats->{$user}{'spam'}{'score'} / $Rh_userstats->{$user}{'spam'}{'count'} : 0,
                ($Rh_userstats->{$user}{'ham'}{'count'} > 0) ?
                $Rh_userstats->{$user}{'ham'}{'score'} / $Rh_userstats->{$user}{'ham'}{'count'} : 0,
                $Rh_userstats->{$user}{'spam'}{'count'},
                ($Rh_userstats->{$user}{'total'}{'count'} > 0) ?
                100 * $Rh_userstats->{$user}{'spam'}{'count'} / $Rh_userstats->{$user}{'total'}{'count'} : 0,
                $Rh_userstats->{$user}{'spam'}{'bytes'},
                ($Rh_userstats->{$user}{'total'}{'bytes'} > 0) ?
                100 * $Rh_userstats->{$user}{'spam'}{'bytes'} / $Rh_userstats->{$user}{'total'}{'bytes'} : 0,
                $Rh_userstats->{$user}{'spam'}{'time'},
                ($Rh_userstats->{$user}{'total'}{'time'} > 0) ?
                100 * $Rh_userstats->{$user}{'spam'}{'time'} / $Rh_userstats->{$user}{'total'}{'time'} : 0,
                );
            }
        }
        $rpt .= "\n";
    }

    my $codename = $0;
    $codename =~ s#^.*/##o;
    $rpt .= "Done. Report generated in " . $Rh_timing->{'telapsed'} . " sec by $codename, version $VER_NUM.\n";

    return $rpt;
}

########################################
# Build HTML report                    #
########################################
sub build_html_report {
    my $Rh_timing = shift;
    my $Rh_stats = shift;
    my $Rh_userstats = shift;
    my $Rh_aggregate_stats = shift;

    my $rpt = '';

    my $d_now = strftime("%c", localtime(time));
    my $d_start = strftime("%A, %B %e %Y %T %Z", localtime($Rh_timing->{'start'}));
    my $d_end = strftime("%A, %B %e %Y %T %Z", localtime($Rh_timing->{'end'}));
    my $d_telapsed = $Rh_timing->{'telapsed'};
    my $d_period = sprintf("%.2f", $Rh_timing->{'hrsinperiod'});

    my $d_mean_thresh = sprintf("%.2f", $Rh_aggregate_stats->{'threshavg'});

    my $t_spam_overview =<<"T_OVERVIEW";
<table border="1" summary="Aggregate mail statistics">
<tr>
<th rowspan="2"></th>
<th colspan="3">Messages</th>
<th colspan="3">Size</th>
<th colspan="3">Time</th>
<th>Mean Score</th>
</tr>

<tr>
<th>[#]</th>
<th>[#/hr]</th>
<th>[%]</th>
<th>[Kb]</th>
<th>[Kb/hr]</th>
<th>[%]</th>
<th>[s]</th>
<th>[s/hr]</th>
<th>[%]</th>
<th>[#]</th>
</tr>

<tr>
<th bgcolor="#CCFFCC">Ham</th>
<td align="right">$Rh_stats->{'ham'}{'count'}</td>
<td align="right">$Rh_stats->{'ham'}{'perhour'}{'count'}</td>
<td align="right">$Rh_stats->{'ham'}{'percent'}{'count'}</td>
<td align="right">$Rh_stats->{'ham'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'ham'}{'perhour'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'ham'}{'percent'}{'bytes'}</td>
<td align="right">$Rh_stats->{'ham'}{'d_time'}</td>
<td align="right">$Rh_stats->{'ham'}{'perhour'}{'time'}</td>
<td align="right">$Rh_stats->{'ham'}{'percent'}{'time'}</td>
<td align="right">$Rh_stats->{'ham'}{'d_mean_score'}</td>
</tr>

<tr>
<th bgcolor="#FFCCCC">Spam</th>
<td align="right">$Rh_stats->{'spam'}{'count'}</td>
<td align="right">$Rh_stats->{'spam'}{'perhour'}{'count'}</td>
<td align="right">$Rh_stats->{'spam'}{'percent'}{'count'}</td>
<td align="right">$Rh_stats->{'spam'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'spam'}{'perhour'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'spam'}{'percent'}{'bytes'}</td>
<td align="right">$Rh_stats->{'spam'}{'d_time'}</td>
<td align="right">$Rh_stats->{'spam'}{'perhour'}{'time'}</td>
<td align="right">$Rh_stats->{'spam'}{'percent'}{'time'}</td>
<td align="right">$Rh_stats->{'spam'}{'d_mean_score'}</td>
</tr>

<tr>
<th bgcolor="#CCCCFF">Total</th>
<td align="right">$Rh_stats->{'total'}{'count'}</td>
<td align="right">$Rh_stats->{'total'}{'perhour'}{'count'}</td>
<td align="right">$Rh_stats->{'total'}{'percent'}{'count'}</td>
<td align="right">$Rh_stats->{'total'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'total'}{'perhour'}{'d_kbytes'}</td>
<td align="right">$Rh_stats->{'total'}{'percent'}{'bytes'}</td>
<td align="right">$Rh_stats->{'total'}{'d_time'}</td>
<td align="right">$Rh_stats->{'total'}{'perhour'}{'time'}</td>
<td align="right">$Rh_stats->{'total'}{'percent'}{'time'}</td>
<td align="right">$Rh_stats->{'total'}{'d_mean_score'}</td>
</tr>
</table>
T_OVERVIEW

    my $t_hourly =<<"T_HOURLY";
<table border="0" summary="Hourly ham/spam trends">
<tr>
<th colspan="3">Statistics by hour</th>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
<td>&nbsp;</td>
</tr>

<tr>
<th>Hour</th>
<th bgcolor="#FFCCCC">Spam</th>
<th bgcolor="#CCFFCC">Ham</th>
<td colspan="10"></td>
</tr>
T_HOURLY

    my $hour = floor($Rh_timing->{'start'}/3600);
    my $prev_day = '';

    my $null_color = 'bgcolor="#CCCCFF"';
    my $spam_color = 'bgcolor="#FFCCCC"';
    my $ham_color = 'bgcolor="#CCFFCC"';
#    my $spam_mark = qq{<td $spamcolor">&nbsp;</td>};
#    my $ham_mark = qq{<td $hamcolor">&nbsp;</td>};
    while ($hour < $Rh_timing->{'end'}/3600) {
        foreach my $partition (qw(spam ham total)) {
            $Rh_stats->{$partition}{'byhour'}{$hour} = 0 unless
                (defined($Rh_stats->{$partition}{'byhour'}{$hour}) &&
                 ($Rh_stats->{$partition}{'byhour'}{$hour} > 0));
        }

        my $curr_hour = strftime("%H:00", localtime($hour*3600));
        my $curr_day = strftime("%Y-%m-%d", localtime($hour*3600));
        if ($curr_day ne $prev_day) {
            $curr_hour = "<b>$curr_day $curr_hour</b>";
        }
        $prev_day = $curr_day;

        my $ham_fraction = 0;
        my $spam_fraction = 0;
        my $check_total = $Rh_stats->{'ham'}{'byhour'}{$hour} + $Rh_stats->{'spam'}{'byhour'}{$hour};
        my $tab_graph = qq{<td colspan="10" $null_color>&nbsp;</td>};
        if ($Rh_stats->{'total'}{'byhour'}{$hour} > 0) {
            $spam_fraction = int(10 * ($Rh_stats->{'spam'}{'byhour'}{$hour} / $check_total));
            $ham_fraction = 10 - $spam_fraction;
            if ($spam_fraction == 10) {
                $tab_graph = qq{<td colspan="10" $spam_color>&nbsp;</td>};
            } elsif ($spam_fraction == 9) {
                $tab_graph = qq{<td colspan="9" $spam_color>&nbsp;</td>};
                $tab_graph .= "<td $ham_color>&nbsp;</td>";
            } elsif ($spam_fraction == 1) {
                $tab_graph = "<td $spam_color>&nbsp;</td>";
                $tab_graph .= qq{<td colspan="9" $ham_color>&nbsp;</td>};
            } elsif ($spam_fraction == 0) {
                $tab_graph = qq{<td colspan="10" $ham_color>&nbsp;</td>};
            } else {
                $tab_graph = qq{<td colspan="$spam_fraction" $spam_color>&nbsp;</td>};
                $tab_graph .= qq{<td colspan="$ham_fraction" $ham_color>&nbsp;</td>};
            }
#            $tab_graph = ($spam_mark x $spam_fraction) . ($ham_mark x $ham_fraction);
        }

        $t_hourly .= sprintf(qq{<tr align="right"><td>%s</td><td>%d</td><td>%d</td>%s</tr>\n},
            $curr_hour,
            $Rh_stats->{'spam'}{'byhour'}{$hour},
            $Rh_stats->{'ham'}{'byhour'}{$hour},
            $tab_graph,);

        $hour++;
    }
    $t_hourly .= "</table>\n";

    my $t_userstats = '';
    if ($opt{'userstats'} && defined($Rh_stats->{'total'}{'count'}) &&
        ($Rh_stats->{'total'}{'count'} > 0)) {
        my $topusers = 25;
        if (defined($opt{'topusers'}) && ($opt{'topusers'} > 0)) {
            $topusers = $opt{'topusers'};
        }

        my $usercount = scalar(keys(%{$Rh_userstats}));
        if ($usercount > 0) {
            my $upper_userlimit = ($usercount > $topusers) ? $topusers : $usercount;

            $t_userstats =<<"T_USERSTATS";
<table border="1" summary="Top $upper_userlimit spam victims">
<tr>
<th colspan="3">Top $upper_userlimit spam victims</th>
<th colspan="6" bgcolor="#FFCCCC">Spam</th>
</tr>
<tr>
<th rowspan="2">User</th>
<th colspan="2">Avg. Score</th>
<th colspan="2">Messages Received</th>
<th colspan="2">Bytes Received</th>
<th colspan="2">Processing Time</th>
</tr>
<tr>
<th bgcolor="#FFCCCC">Spam</th>
<th bgcolor="#CCFFCC">Ham</th>
<th>[#]</th>
<th>%</th>
<th>[bytes]</th>
<th>%</th>
<th>[s]</th>
<th>%</th>
</tr>
T_USERSTATS

#            $rpt .=    "Top $upper_userlimit spam victims:\n";
#            $rpt .=    "User                               S AvScr   H AvScr      Count    % Count      Bytes    % Bytes       Time     % Time\n";
#            $rpt .=    "--------------------------------   -------   -------   -------- ----------   -------- ----------   -------- ----------\n";
        foreach my $user (sort {
          $Rh_userstats->{$b}{'total'}{'count'} <=> $Rh_userstats->{$a}{'total'}{'count'}
          } keys %{$Rh_userstats}) {

            foreach my $partition (qw(spam ham total)) {
                foreach my $metric (qw(score bytes count)) {
                    $Rh_userstats->{$user}{$partition}{$metric} ||= 0;
                }
            }

            my %avg_score = ();
            foreach my $partition (qw(ham spam total)) {

                foreach my $metric (qw(count bytes time)) {
                    $Rh_userstats->{$user}{$partition}{$metric} = 0 unless
                    (defined($Rh_userstats->{$user}{$partition}{$metric}));
                }

                if ($partition ne 'total') {
                    if (defined($Rh_userstats->{$user}{$partition}{'count'})
                      && ($Rh_userstats->{$user}{$partition}{'count'} > 0)) {
                        $avg_score{$partition} = sprintf('%.2f',
                            $Rh_userstats->{$user}{$partition}{'score'}
                            / $Rh_userstats->{$user}{$partition}{'count'});
                    } else {
                        $avg_score{$partition} = 0;
                    }
                }
            }

            $t_userstats .= sprintf(qq{<tr align="right"><td align="left">%s</td><td>%.2f</td><td>%.2f</td><td>%d</td><td>%.2f%%</td><td>%d</td><td>%.2f%%</td><td>%d</td><td>%.2f%%</td></tr>\n},
        $user,
        $avg_score{'spam'},
        $avg_score{'ham'},
        $Rh_userstats->{$user}{'spam'}{'count'},
        (defined($Rh_userstats->{$user}{'total'}{'count'}) && ($Rh_userstats->{$user}{'total'}{'count'} > 0)) ?
        100 * $Rh_userstats->{$user}{'spam'}{'count'} / $Rh_userstats->{$user}{'total'}{'count'} : 0,
        $Rh_userstats->{$user}{'spam'}{'bytes'},
        (defined($Rh_userstats->{$user}{'total'}{'bytes'}) && ($Rh_userstats->{$user}{'total'}{'bytes'} > 0)) ?
         100 * $Rh_userstats->{$user}{'spam'}{'bytes'} / $Rh_userstats->{$user}{'total'}{'bytes'} : 0,
        $Rh_userstats->{$user}{'spam'}{'time'},
        (defined($Rh_userstats->{$user}{'total'}{'time'}) && ($Rh_userstats->{$user}{'total'}{'time'} > 0)) ?
        100 * $Rh_userstats->{$user}{'spam'}{'time'} / $Rh_userstats->{$user}{'total'}{'time'}: 0,
                );
            }

            $t_userstats .= "</table>\n<hr>\n";

        }
    }

    my $codename = $0;
    $codename =~ s#^.*/##o;

    $rpt .=<<"HTMLPAGE";
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>SpamAssassin Statistics: $d_start - $d_end</title>
</head>
<body>
<h1>SpamAssassin Statistics:</h1>
<p>
Period of <b>$d_period</b> hour(s) extending from<br>
<b>$d_start</b> to<br>
<b>$d_end</b>
</p>
<p>
Generated on <b>$d_now</b> in $d_telapsed second(s) by $codename, version $VER_NUM.
</p>
<hr>
<p>
Note: 'ham' = 'nonspam'
</p>
<p>
The mean spam threshold score is $d_mean_thresh; mail scoring below the threshold is ham, mail scoring at or above the threshold is spam.
</p>
$t_spam_overview
<hr>
$t_hourly
<hr>
$t_userstats
<p>
Generated on <b>$d_now</b> in $d_telapsed second(s) by $codename, version $VER_NUM.
</p>
</body>
</html>
HTMLPAGE

    return $rpt;
}


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
    print STDERR @_ if ($opt{debug});
}

sub vdbg {
    print STDERR @_ if ($opt{debug} && $opt{verbose});
}

__END__

=head1 NAME

sa-stats.pl - Builds received spam/ham report from mail log

=head1 VERSION

    $Revision: 1.17 $

=head1 SYNOPSIS

 Usage: sa-stats.pl [options]

 Options:
   -l, --logfile=filename       logfile to read
                                (default: /var/log/maillog)
   -s, --start                  Sets date/time for start of reporting period
   -e, --end                    Sets date/time for end of reporting period
   -u, --userstats              Generates stats for the top spam victims
                                (default is 25; see -T)
   -H, --html                   Generates HTML report
                                (default: plain text)
   -T, --top=#                    Display top # spam victims
                                (# defaults to 25; -T implies -u)
   -h, --help                   Displays this message
   -V, --version                Display version info
   --mail=emailaddress          Sends report to emailaddress
   --sendmail=/path/to/sendmail Location of sendmail binary
                                (default: /usr/sbin/sendmail)
   --from=emailaddress          Sets From: field of mail
   -v, --verbose                Sets verbose mode (requires -D)
   -D, --debug                  Sets debug mode

=head1 DESCRIPTION

Creates simple text report of spam/ham detected by SpamAssassin by
parsing spamd entries in the mail log (generally /var/log/maillog)

=head1 EXAMPLES

To generate a text report from midnight to present using /var/log/maillog:

 ./sa-stats.pl -s 'midnight' -e 'now' > sa_stats.txt

To generate an HTML report including the top 5 spam victims for the month of
January 2004 from compressed mail logs:

 gunzip -c /var/log/maillog-200401*.gz | ./sa-stats.pl -H -T 5 -l - \
 -s '2001-01-01 00:00:00' -e '2004-01-31 23:59:59' > jan_2004_stats.html

Note the use of '-' as a filename to represent STDIN.

To generate a text report with per-user stats from yesterday, reading from
/var/log/mail and turning on all debugging output:

 ./sa-stats.pl -v -D -u -l /var/log/mail \
 -s 'yesterday midnight' 1>stats.txt 2>stats.err

=head1 TIPS

=over 4

=item *

Are you running spamd? Currently sa-stats.pl only reads syslog entries from
spamd; it doesn't work with MTA-level calls to Mail::SpamAssassin or with logs
generated by the spamassassin perl script.

=item *

Are there spamd entries in your mail log? Use 'grep spamd /var/log/maillog' to find out.

=item *

Are there spamd entries in your mail log within the analysis interval? Run
'sa-stats.pl -v -D ...' to see the entries that are found and discarded as well
as to see the actual analysis interval.

=back

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

=over 4

=item *

Because of poor year handling in Parse::Syslog, the script may not
work well when the log file dates back to the previous year.

=back

=head1 TO DO

=over 4

=item *

Find bugs

=item *

Fix bugs

=item *

Don't call /usr/sbin/sendmail directly; use Mail::Internet or Net::SMTP or other standard module

=item *

Add support for compressed logs (see gzopen() from Compress::Zlib)

=item *

Have --verbose work without --debug

=back

=head1 AUTHORS

Brad Rathbun <brad@computechnv.com> http://www.computechnv.com/

Bob Apthorpe <apthorpe+sa@cynistar.net> http://www.cynistar.net/~apthorpe/

Duncan Findlay <duncf@debian.org>

=head1 SEE ALSO

Mail::SpamAssassin, Date::Manip, spamd(1)

=cut
