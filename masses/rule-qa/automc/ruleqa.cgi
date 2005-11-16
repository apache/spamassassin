#!/local/perl586/bin/perl -w
my $automcdir = "/home/automc/svn/spamassassin/masses/rule-qa/automc";

###!/usr/bin/perl -w
##my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";

use CGI;
use Template;
use Date::Manip;
use XML::Simple;

use strict;
use bytes;
use POSIX qw(strftime);

my $myperl = $^X;

open (CF, "<$automcdir/config");
my %conf; while(<CF>) { /^(\S+)=(\S+)/ and $conf{$1} = $2; }
close CF;

our %freqs_filenames = (
    'DETAILS.age' => 'set 0, broken down by message age in weeks',
    'DETAILS.all' => 'set 0, broken down by contributor',
    'DETAILS.new' => 'set 0, in aggregate',
    'HTML.age' => 'set 0, by message age, HTML messages only',
    'HTML.all' => 'set 0, by contributor, HTML messages only',
    'HTML.new' => 'set 0, in aggregate, HTML messages only',
    'NET.age' => 'set 1 (network), by message age in weeks',
    'NET.all' => 'set 1 (network), by contributor',
    'NET.new' => 'set 1 (network), in aggregate',
    'SCOREMAP.new' => 'set 0, score-map',
    'OVERLAP.new' => 'set 0, overlaps between rules',
);

my $q = new CGI;

my $ttk = Template->new;

my $cgi_url;
my @cgi_params;
my %cgi_params = ();
precache_params();

my %s = ();
# selection of what will be displayed.
$s{defcorpus} = get_url_switch('s_defcorpus', 1);
$s{html} = get_url_switch('s_html', 0);
$s{net} = get_url_switch('s_net', 0);
$s{zero} = get_url_switch('s_zero', 0);

$s{new} = get_url_switch('s_new', 1);
$s{detail} = get_url_switch('s_detail', 0);
$s{g_over_time} = get_url_switch('s_g_over_time', 0);

# note: age, new, overlap are all now synonyms for detail ;)
if ($s{age} || $s{overlap} || $s{detail}) {
  $s{age} = 1;
  $s{all} = 1;
  $s{new} = 1;
  $s{overlap} = 1;
  $s{scoremap} = 1;
  $s{zero} = 1;
}

if (!grep { $_ } values %s) {
  $s{defcorpus} = 1;      # set the defaults
  $s{new} = 1;
}

# $s{headers} = get_url_switch('s_headers', 0);

sub get_url_switch {
  my ($name, $defval) = @_;
  my $val = $q->url_param($name);

  if (!defined $val) { return $defval; }
  return ($val) ? 1 : 0;
}

# when and what
my $daterev = $q->url_param('daterev') || '';

# sanitise daterev string
if (defined $daterev) {
  $daterev =~ /(\d+)[\/-](r\d+)/; undef $daterev;
  if ($2) {
    $daterev = "$1-$2";
  } else {
    $daterev = undef;
  }
}

# all known date/revision combos.  warning: could get slow in future
my @daterevs = get_all_daterevs();
# turn possibly-empty $daterev into a real date/rev combo (that exists)
$daterev = date_in_direction($daterev, 0);

my $rule = $q->url_param('rule') || '';
my $nicerule = $rule; if (!$nicerule) { $nicerule = 'all rules'; }

my $datadir;
my %freqs_head = ();
my %freqs_data = ();
my %freqs_ordr = ();
my $line_counter = 0;

# ---------------------------------------------------------------------------
# supported views

my $graph = $q->url_param('graph');
if ($graph) {
  if ($graph eq 'over_time') { graph_over_time(); }
  else { die "graph '$graph' unknown"; }
}
elsif ($q->url_param('longdatelist')) {
  show_daterev_selector_page();
}
else {
  show_default_view();
}
exit;

# ---------------------------------------------------------------------------

sub show_default_header {
my $title = shift;

my $hdr = $q->header . q{<html><head>

  <title>}.$title.q{</title>

  <style type="text/css" media="all">

    body {
      padding: 1em 1em 1em 1em;
    }
    pre.freqs {
      font-family: monospace;
      font-size: 14px;
      border: 1px dashed #ddb;
      margin: 0em -0.5em 0em -0.5em;
      padding: 10px 20px 10px 20px;
    }
    div.updateform {
      border: 3px solid #aaa;
      background: #eec;
      margin: 0em 0em 1em 0em;
      padding: 0em 1em 0em 2em;
    }

    p.showfreqslink {
      color: #999;
      font-size: 50%;
      text-align: right;
      margin: 0px 0px 0px 0px;
      border: 0px 0px 0px 0px;
    }
    p.showfreqslink a { color: #999; }

    div.headdiv {
      border: 1px solid;
      background: #f0f8c0;
      margin: 0px 0px 0px 20px;
    }
    p.headclosep {
      margin: 0px 0px 0px 0px;
      border: 0px 0px 0px 0px;
    }
    pre.head {
      margin-left: 10px;
    }
    
    table.freqs {
      border: 1px dashed #ddb;
      background: #fff;
      padding: 10px 5px 10px 5px;
    }
    tr.freqsline_a td {
      text-align: right;
      padding: 0.1em 0.2em 0.1em 0.2em;
    }
    tr.freqsline_b td {
      text-align: right;
      padding: 0.1em 0.2em 0.1em 0.2em;
      background: #f0f0d8;
    }

    h3 {
      border: 1px solid;
      padding: 10px 20px 10px 20px;
      margin: 20px -20px -10px -20px;
      background: #fe8;
    }

    td.daterevtd {
      font-size: 75%;
      padding: 1px 3px 1px 5px;
    }

    tr.daterevtr {
      background: #fff;
    }

    tr.daterevdesc {
      background: #f0e0a0;
    }

    /* Sortable tables, see http://www.kryogenix.org/code/browser/sorttable/ */
    table.sortable a.sortheader {
       background: #ddd;
       color:#666;
       font-weight: bold;
       text-decoration: none;
       display: block;
    }
    tr.freqsheader {
       background: #ddd;
    }
    table.sortable span.sortarrow {
       color: black;
       text-decoration: none;
    }

  </style>

  <script type="text/javascript"><!--

    function hide_header(id) {
      document.getElementById(id).style.display = "none";
    }
    function show_header(id) {
      document.getElementById(id).style.display = "block";
    }

    //-->
  </script>
  <script src="http://buildbot.spamassassin.org/sorttable.js"></script>

  </head><body>

};
return $hdr;
}

sub show_default_view {
my $title;
if ($s{detail}) {
  $title = "Rule QA: details for $nicerule (in $daterev)";
} else {
  $title = "Rule QA: overview of all rules (in $daterev)";
}
print show_default_header($title);

my $tmpl = q{

<div class=updateform>
<form action="!THISURL!" method=GET>
  <h4> Which Corpus? </h4>
  <input type=checkbox name=s_defcorpus !s_defcorpus!> Show default non-net ruleset and corpus, set 0<br/>
  <input type=checkbox name=s_net !s_net!> Show frequencies from network tests, set 1<br/>
  <input type=checkbox name=s_html !s_html!> Show frequencies for mails containing HTML only, set 0<br/>
  <br/>

  <table style="padding-left: 0px" class=datetable>

      <tr>
       <th> Mass-Check </th>
       <th> Date </th>
       <th> MC-Rev </th>
       <th> Commit </th>
       <th> Rev </th>
       <th> Author </th>
      </tr>

           <tr class=daterevtr><td class=daterevtd><b>Earlier</b></td>
       !daylinkneg2!
      </tr><tr class=daterevtr><td class=daterevtd></td>
       !daylinkneg1!
      </tr><tr class=daterevtr><td class=daterevtd><b>Viewing</b></td>
       !todaytext!
      </tr><tr class=daterevtr><td class=daterevtd></td>
       !daylinkpls1!
      </tr><tr class=daterevtr><td class=daterevtd><b>Later</b></td>
       !daylinkpls2!
      </tr>
  </table>

<table width=100%>
<tr>
<td width=90%>
  Date/Rev to display (UTC timezone):
  <input type=textfield name=daterev value="!daterev!">
</td>
<td width=10%><div align=right>
  <a href="!longdatelist!">(List&nbsp;All)</a><br/>
</div></td>
</tr>
</table>

  <br/>
  <h4> Which Rules?</h4>
  Show only these rules (space separated, or regexp with '/' prefix):<br/>
  <input type=textfield size=60 name=rule value="!rule!"><br/>
  <br/>
  <input type=checkbox name=s_zero !s_zero!> Display rules with no hits<br/>
  <br/>
  <input type=hidden name=s_detail value="!s_detail!" />

  <input type=submit name=g value="Change"><br/>
</form>
</div>

};

my $days = {
  neg3 => -3,
  neg2 => -2,
  neg1 => -1,
  pls1 => 1,
  pls2 => 2,
  pls3 => 3
};

my ($key, $daycount);
while (($key, $daycount) = each %{$days}) {
  my $dr = date_in_direction($daterev, $daycount);
  my $drtext = $dr;

  if (!$dr) {
    $tmpl =~ s,!daylink${key}!,

       <td colspan=6 class=daterevtd>
         <em>(no logs available)</em>
       </td>

    ,gs;
  }
  else {
    $dr = gen_switch_url("daterev", $dr);
    my $drtext = get_daterev_description($drtext);
    $drtext =~ s/!drhref!/$dr/gs;

    $tmpl =~ s,!daylink${key}!,
       $drtext
    ,gs;
  }
}

$daterev = date_in_direction($daterev, 0);
{
  my $todaytext = get_daterev_description($daterev);
  my $dr = gen_switch_url("daterev", $daterev);
  $todaytext =~ s/!drhref!/$dr/gs;
  $tmpl =~ s/!todaytext!/$todaytext/gs;
}


my $dranchor = "r".$daterev; $dranchor =~ s/[^A-Za-z0-9]/_/gs;
my $ldlurl = gen_switch_url("longdatelist", 1)."#".$dranchor;

$tmpl =~ s/!longdatelist!/$ldlurl/gs;
$tmpl =~ s/!THISURL!/$cgi_url/gs;
$tmpl =~ s/!daterev!/$daterev/gs;
$tmpl =~ s/!rule!/$rule/gs;
foreach my $opt (keys %s) {
  if ($s{$opt}) {
    $tmpl =~ s/!s_$opt!/checked /gs;
  } else {
    $tmpl =~ s/!s_$opt!/ /gs;
  }
}

print $tmpl;

if (!$s{detail}) {

  print qq{

    <p class=intro> <strong>Instructions</strong>: click the '&gt;' symbol, or
    the rule name, to view details of a particular rule. </p>

  };
}

show_all_sets_for_daterev($daterev, $daterev);

if ($s{detail}) {
  {
    my $graph_on = qq{

      <p><a id="over_time_anchor" 
        href="}.gen_switch_url("s_g_over_time", "0").qq{#over_time_anchor"
        >Hide Graph</a></p>
      <img src="}.gen_switch_url("graph", "over_time").qq{" 
        width=800 height=815 />

    };

    my $graph_off = qq{

      <p><a id="over_time_anchor" 
        href="}.gen_switch_url("s_g_over_time", "1").qq{#over_time_anchor"
        >Show Graph</a></p>

    };

    print qq{

      <h3 class=graph_title>Graph, hit-rate over time</h3>
      }.($s{g_over_time} ? $graph_on : $graph_off).qq{

      </ul>

    };
  }

  my @parms =get_params_except(qw(
          rule s_age s_overlap s_all s_detail
        ));
  my $url_back = assemble_url(@parms);

  print qq{

    <p><a href="$url_back">&lt; Back</a> to overview.</p>

  };
}

print qq{

  <p>(thanks to <a href=http://www.kryogenix.org/code/browser/sorttable/>Stuart
  Langridge</a> for the sort-table DHTML code used here.)</p>

  </body></html>

  };

exit;

}

sub get_all_daterevs {
  return sort map {
      s/^.*\/(\d+)\/(r\d+)$/$1-$2/; $_;
    } grep { /\/(\d+\/r\d+)$/ && -d $_ } (<$conf{html}/2*/r*>);
}

sub date_in_direction {
  my ($origdaterev, $dir) = @_;

  my $orig;
  if ($origdaterev && $origdaterev =~ /^(\d+)[\/-](r\d+)$/) {
    $orig = "$1-$2";
  } else {
    $orig = $daterevs[-1];      # the most recent
  }

  my $cur;
  for my $i (0 .. scalar(@daterevs)) {
    if ($daterevs[$i] eq $orig) {
      $cur = $i; last;
    }
  }

  # if it's not in the list, $cur should be the last entry
  if (!defined $cur) { $cur = scalar(@daterevs)-1; }

  my $new;
  if ($dir < 0) {
    if ($cur+$dir >= 0) {
      $new = $daterevs[$cur+$dir];
    }
  }
  elsif ($dir == 0) {
    $new = $daterevs[$cur];
  }
  else {
    if ($cur+$dir <= scalar(@daterevs)-1) {
      $new = $daterevs[$cur+$dir];
    }
  }

  if ($new && -d get_datadir_for_daterev($new)) {
    return $new;
  }

  return undef;       # couldn't find one
}

sub show_all_sets_for_daterev {
  my ($path, $strdate) = @_;

  $strdate = "mass-check date/rev: $path";

  $datadir = get_datadir_for_daterev($path);

  $s{defcorpus} and showfreqset('DETAILS', $strdate);
  $s{html} and showfreqset('HTML', $strdate);
  $s{net} and showfreqset('NET', $strdate);

  # special case: we only build this for one set, as it's quite slow
  # to generate
  $s{scoremap} and showfreqsubset("SCOREMAP.new", $strdate);
  $s{overlap} and showfreqsubset("OVERLAP.new", $strdate);
}

###########################################################################

sub graph_over_time {
  $datadir = get_datadir_for_daterev($daterev);

  # logs are named e.g.
  # /home/automc/corpus/html/20051028/r328993/LOGS.all-ham-mc-fast.log.gz

  # untaint
  $rule =~ /([_0-9a-zA-Z]+)/; my $saferule = $1;

  $datadir =~ s/\.\.\//__\//gs;
  $datadir =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  exec ("$myperl $automcdir/../rule-hits-over-time ".
        "--cgi --scale_period=200 --rule='$saferule' ".
        "$safedatadir/LOGS.*.log.gz");

  die "exec failed";
}

###########################################################################

sub showfreqset {
  my ($type, $strdate) = @_;
  $s{new} and showfreqsubset("$type.new", $strdate);
  $s{age} and showfreqsubset("$type.age", $strdate);
  $s{all} and showfreqsubset("$type.all", $strdate);
}

sub showfreqsubset {
  my ($filename, $strdate) = @_;
  read_freqs_file($filename);

  if ($filename eq 'DETAILS.new') {
    # report which sets we used
    summarise_head($freqs_head{$filename}, $filename, $strdate, $rule);
  }

  get_freqs_for_rule($filename, $strdate, $rule);
}

sub summarise_head {
  my ($head, $filename, $strdate, $rule) = @_;

  my @mcfiles = ();
  if ($head =~ /^# ham results used for \S+ \S+ \S+: (.*)$/m) {
    @mcfiles = split(' ', $1);
  }

  map {
    s/^ham-//; s/\.log$//;
  } @mcfiles;

  my $who = join(', ', @mcfiles);

  print qq{

    <!-- <em>(Using mass-check data from: $who)</em> -->

  };
}

sub read_freqs_file {
  my ($key) = @_;

  my $file = $datadir.$key;
  if (!open (IN, "<$file")) {
    warn "cannot read $file";
    return;
  }

  $freqs_head{$key}=<IN>;
  $freqs_data{$key} = { };
  $freqs_ordr{$key} = [ ];
  my $lastrule;

  my $subset_is_user = 0;
  my $subset_is_age = 0;
  if ($file =~ /\.age/) { $subset_is_age = 1; }
  if ($file =~ /\.all/) { $subset_is_user = 1; }

  while (<IN>) {
    if (/(?: \(all messages| results used|OVERALL\%|was at r\d+)/) {
      $freqs_head{$key} .= $_;
    }
    elsif (/MSEC/) {
      next;	# just ignored for now
    }
    elsif (/\s+scoremap (.*)$/) {
      $freqs_data{$key}{$lastrule}{scoremap} .= $_;
    }
    elsif (/\s+overlap (.*)$/) {
      $freqs_data{$key}{$lastrule}{overlap} .= $_;
    }
    elsif (/\s+(\S+?)(\:\S+)?\s*$/) {
      $lastrule = $1;
      my $subset = $2;
      if ($subset) { $subset =~ s/^://; }

      my @vals = split;
      if (!exists $freqs_data{$key}{$1}) {
        push (@{$freqs_ordr{$key}}, $1);
        $freqs_data{$key}{$1} = {
          lines => [ ]
        };
      }

      my $line = {
        name => $lastrule,
        msecs => $vals[0],
        spampc => $vals[1],
        hampc => $vals[2],
        so => $vals[3],
        rank => $vals[4],
        score => $vals[5],
        username => ($subset_is_user ? $subset : undef),
        age => ($subset_is_age ? $subset : undef),
      };
      push @{$freqs_data{$key}{$1}{lines}}, $line;
    }
    else {
      warn "ERROR: dunno $_";
    }
  }
  close IN;
}

sub get_freqs_for_rule {
  my ($key, $strdate, $ruleslist) = @_;

  my $desc = $freqs_filenames{$key};
  my $file = $datadir.$key;

  my $titleplink = "$key.$strdate"; $titleplink =~ s/[^A-Za-z0-9]+/_/gs;
  my $comment = qq{
  
    <!-- freqs start $key -->
    <h3 class=freqs_title>$desc</h3>
    <!-- <h4>$strdate</h4> -->

  };

  my $heads = sub_freqs_head_line($freqs_head{$key});
  my $headers_id = $key; $headers_id =~ s/[^A-Za-z0-9]/_/gs;

  $comment .= qq{ 
    
    <div id="$headers_id" class=headdiv style='display: none'>
    <p class=headclosep align=right><a
          href="javascript:hide_header('$headers_id')">[close]</a></p>
    <pre class=head>$heads</pre>
    </div>

  };

  $comment .= qq{
    <br clear="all"/>
    <p class=showfreqslink><a
      href="javascript:show_header('$headers_id')">(source details)</a></p>

    <table class=sortable id='freqs_${headers_id}' class=freqs>
      <tr class=freqshead>
      <th><a name='$titleplink' href='#$titleplink'
          class=title_permalink>#</a></th>
      <th>MSECS</th>
      <th>SPAM%</th>
      <th>HAM%</th>
      <th>S/O%</th>
      <th>RANK</th>
      <th>SCORE</th>
      <th>NAME</th>
      <th>WHO</th>
      <th>AGE</th>
    </tr>

  };

  $ruleslist ||= '';
  my @rules = split (' ', $ruleslist);
  if (scalar @rules == 0) { @rules = (''); }

  # my $first_round_in_loop = 1;

  foreach my $rule (@rules) {
    # if (!$first_round_in_loop) {
    # $comment .= "<table class=freqs>";
    # $first_round_in_loop = 0;
    # }
    if ($rule && defined $freqs_data{$key}{$rule}) {
      $comment .= rule_anchor($key,$rule);
      $comment .= output_freqs_data_line($freqs_data{$key}{$rule});
    }
    elsif ($rule eq '') {
      # all rules please...
      foreach my $r (@{$freqs_ordr{$key}}) {
        $comment .= rule_anchor($key,$r);
        $comment .= output_freqs_data_line($freqs_data{$key}{$r});
      }
    }
    elsif ($rule =~ /^\/(.*)$/) {
      my $regexp = $1;
      foreach my $r (@{$freqs_ordr{$key}}) {
        next unless ($r =~/${regexp}/i);
        $comment .= rule_anchor($key,$r);
        $comment .= output_freqs_data_line($freqs_data{$key}{$r});
      }
    }
    else {
      $comment .= rule_anchor($key,$rule);
      $comment .= "
      <tr><td colspan=9>
        (no data found)
      </td></tr>
      ";
    }
  }
  
  print $comment;
  print "</table>";
}

sub rule_anchor {
  my ($key, $rule) = @_;
  return "<a name='".uri_escape($key."_".$rule)."'></a>".
            "<a name='$rule'></a>";
}

sub sub_freqs_head_line {
  my ($str) = @_;
  $str = "<em><tt>".($str || '')."</tt></em><br/>";
  return $str;
}

sub output_freqs_data_line {
  my ($obj) = @_;

  my $LINE_TEMPLATE = qq{

    <tr class=freqsline_[% LINEALT %]>
      <td>
      [% IF RULEDETAIL != '' %]
	<a href="[% RULEDETAIL %]">&gt;</a>
      [% END %]
      </td>
      <td>[% MSECS %]</td>
      <td>[% SPAMPC %]</td>
      <td>[% HAMPC %]</td>
      <td>[% SO %]</td>
      <td>[% RANK %]</td>
      <td>[% SCORE %]</td>
      <td style='text-align: left'><a href="[% NAMEREF %]">[% NAME %]</a></td>
      <td>[% USERNAME %]</td>
      <td>[% AGE %]</td>
    </tr>

  };

  my $EXTRA_TEMPLATE = qq{

    <tr class=freqsextra>
      <td colspan=7><pre class=perruleextra>[% EXTRA %]</pre></td>
    </tr>

  };

  # normal freqs lines, with optional subselector after rule name
  my $out = '';
  foreach my $line (@{$obj->{lines}}) {
    if (!$s{zero}) {
      my $ov = $line->{spampc} + $line->{hampc};
      if (!$ov || $ov !~ /^\s*\d/ || $ov+0 == 0) {
        next;       # skip this line, it's a 0-hitter
      }
    }

    my $detailurl = '';
    if (!$s{detail}) {	# not already in "detail" mode
      $detailurl = create_detail_url($line->{name});
    }

    my $score = $line->{score};
    if ($line->{name} =~ /^__/) {
      $score = '(n/a)';
    }

    $ttk->process(\$LINE_TEMPLATE, {
        RULEDETAIL => $detailurl,
        MSECS => $line->{msecs},
        SPAMPC => $line->{spampc},
        HAMPC => $line->{hampc},
        SO => $line->{so},
        RANK => $line->{rank},
        SCORE => $score,
        NAME => $line->{name},
        NAMEREF => create_detail_url($line->{name}),
        USERNAME => $line->{username} || '',
        AGE => $line->{age} || '',
       LINEALT => (($line_counter & 1) == 0 ? "a" : "b")
    }, \$out) or die $ttk->error();

    $line_counter++;
  }

  # add scoremap using the EXTRA_TEMPLATE if it's present
  if ($obj->{scoremap}) {
    my $ovl = $obj->{scoremap} || '';
    #   scoremap spam: 16  12.11%  777 ****

    $ttk->process(\$EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $ttk->error();
  }

  # add overlap using the EXTRA_TEMPLATE if it's present
  if ($obj->{overlap}) {
    my $ovl = $obj->{overlap} || '';

    $ovl =~ s/^(\s+overlap\s+(?:ham|spam):\s+\d+% )(\S.+?)$/
        my $str = "$1";
        foreach my $rule (split(' ', $2)) {
          $str .= gen_rule_link($rule,$rule)." ";
        }
        $str;
      /gem;

    $ttk->process(\$EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $ttk->error();
  }

  return $out;
}

sub create_detail_url {
  my ($rulename) = @_;
  my @parms = (
        get_params_except(qw(
          rule s_age s_overlap s_all s_detail
        )), 
        "rule=".uri_escape($rulename), "s_detail=1",
      );
  return assemble_url(@parms);
}

sub gen_rule_link {
  my ($rule, $linktext) = @_;
  return "<a href='".create_detail_url($rule)."'>$linktext</a>";
}

sub gen_switch_url {
  my ($switch, $newval) = @_;

  my @parms = get_params_except($switch);
  $newval ||= '';
  if (!defined $switch) { warn "switch '$switch'='$newval' undef value"; }
  # if (!defined $newval) { warn "newval '$switch'='$newval' undef value"; }
  push (@parms, "$switch=$newval");
  return assemble_url(@parms);
}

sub assemble_url {
  my @parms = @_;
  my $url = $cgi_url.'?'.join('&', sort @parms);
  return $url;
}

sub precache_params {
  use URI::Escape;
  $cgi_url = $q->url(-relative=>1);
  @cgi_params = $q->url_param();
  foreach my $k (@cgi_params) {
    next unless defined ($k);
    my $v = $q->url_param($k);
    if (!defined $v) { $v = ''; }
    $cgi_params{$k} = "$k=".uri_escape($v);
  }
}

sub get_params_except {
  my @excepts = @_;

  my @str = ();
  foreach my $p (@cgi_params) {
    foreach my $skip (@excepts) {
      goto nextnext if ($skip eq $p || $cgi_params{$p} =~ /^\Q$skip\E=/);
    }
    push (@str, $cgi_params{$p});
nextnext: ;
  }
  @str;
}

sub get_datadir_for_daterev {
  my $npath = shift;
  $npath =~ s/-/\//;
  return $conf{html}."/".$npath."/";
}

sub get_daterev_description {
  my ($dr) = @_;
  my $fname = get_datadir_for_daterev($dr)."/info.xml";
  my $fastfname = get_datadir_for_daterev($dr)."/fastinfo.xml";

  my $dranchor = "r".$dr; $dranchor =~ s/[^A-Za-z0-9]/_/gs;

  my $txt;
  if (-f $fname) {
    eval {
      my $info = XMLin($fname);
      my $fastinfo = XMLin($fastfname);
      # use Data::Dumper; print Dumper $info;

      my $cdate = $info->{checkin_date};
      $cdate =~ s/T(\S+)\.\d+Z$/ $1/;

      my $net = $fastinfo->{includes_net} ? "[net]" : "";

      my $drtitle = ($info->{msg} ? $info->{msg} : '');
      $drtitle =~ s/[\"\']/ /gs;
      $drtitle =~ s/\s+/ /gs;
      $drtitle =~ s/^(.{0,160}).*$/$1/gs;

      $txt = qq{

          <td class=daterevtd>
        <a name="$dranchor" title="$drtitle" href="!drhref!">$fastinfo->{date}</a></td>
          <td class=daterevtd>
        <a title="$drtitle" href="!drhref!">$fastinfo->{rev}</a></td>
          <td class=daterevtd>
        <a title="$drtitle" href="!drhref!">$cdate</a></td>
          <td class=daterevtd>
        <a title="$drtitle" href="!drhref!">$info->{checkin_rev}</a></td>
          <td class=daterevtd> <em><mcauthor>$info->{author}</mcauthor></em>
            <em><mcwasnet>$net</mcwasnet></em> </td>

        </tr>
        <tr class=daterevdesc>

          <td></td>
          <td class=daterevtd colspan=4>
            <em>($drtitle)</em>
          </td>
          <td class=daterevtd colspan=1>
            <em><mcsubmitters>$fastinfo->{submitters}</mcsubmitters></em>
          </td>

      };
    };

    if ($@) {
      warn "daterev info.xml: $@";
    }

    if ($txt) { return $txt; }
  }

  # if that failed, just use the daterev itself.
  $dr =~ /^(\d+)-r(\d+)$/;
  my $date = $1;
  my $rev = $2;
  my $drtitle = "(no info)";

  $txt = qq{

        <td class=daterevtd>
       <a title="$drtitle" href="!drhref!">$date</a></td>
        <td class=daterevtd>
       <a title="$drtitle" href="!drhref!">$rev</a></td>
        <td class=daterevtd colspan=3>
       <a title="$drtitle" href="!drhref!">(no info on this commit)</a></td>

  };

  return $txt;
}

sub show_daterev_selector_page {
  my $title = "Rule QA: all recent mass-check results";
  print show_default_header($title);

  my @drs_net = ();
  my @drs_nightly = ();
  my @drs_preflight = ();

  # foreach my $i (-50 .. +50) { my $dr = date_in_direction($daterev, $i); }
  foreach my $dr (@daterevs) {
    next unless $dr;

    my $obj = {
        dr => $dr,
        text => get_daterev_description($dr) || ''
      };

    # now match against the microformat data in the HTML, to select
    # the desired subsets of certain types
    if ($obj->{text} =~ /<mcsubmitters>\s*mc-/) {
      push @drs_preflight, $obj;
    }
    elsif ($obj->{text} =~ /<mcwasnet>\s*.net/) {
      push @drs_net, $obj;
    }
    else {
      push @drs_nightly, $obj;
    }
  }

  if (scalar @drs_net > 100)       { splice(@drs_net, 0, -100); }
  if (scalar @drs_preflight > 100) { splice(@drs_preflight, 0, -100); }
  if (scalar @drs_nightly > 100)   { splice(@drs_nightly, 0, -100); }

  print qq{
    <h3> Network Mass-Checks </h3>
    <br/> <a href='#net' name=net>#</a>
  }.  gen_daterev_table(@drs_net);

  print qq{
    <h3> Nightly Mass-Checks </h3>
    <br/> <a href='#nightly' name=nightly>#</a>
  }.  gen_daterev_table(@drs_nightly);

  print qq{
    <h3> Preflight Mass-Checks </h3>
    <br/> <a href='#preflight' name=preflight>#</a>
  }.  gen_daterev_table(@drs_preflight);
}

sub gen_daterev_table {
  my @list = @_;

  my @parms =get_params_except(qw(
          daterev longdatelist
        ));
  my $url_back = assemble_url(@parms);

  my $str = qq{

      <br clear=all />
      <div class=updateform>
       <table style="padding-left: 0px" class=datetable>
       <tr>
       <th> </th>
        <th> Date </th>
        <th> MC-Rev </th>
        <th> Prior Commit </th>
        <th> Rev </th>
        <th> Author </th>
       </tr>

    }. join(' ', map {
      my $dr = $_->{dr};
      my $text = $_->{text};
      my $drhref = assemble_url("daterev=".$dr, @parms);
      $text =~ s/!drhref!/$drhref/gs;
      qq{

       <tr class=daterevtr><td></td>

      }.$text.qq{

       </tr>

      };
    } reverse @list). qq{

      </table></div>

    };
}
  
=cut

to install, add this line to httpd.conf:

  ScriptAlias /ruleqa "/path/to/spamassassin/automc/ruleqa.cgi"


