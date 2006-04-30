#!/local/perl586/bin/perl -w
my $automcdir = "/home/automc/svn/spamassassin/masses/rule-qa/automc";

###!/usr/bin/perl -w
##my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";

# open (O, ">/tmp/xx");print O "foo"; close O;

use CGI;
use Template;
use Date::Manip;
use XML::Simple;
use URI::Escape;

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

# daterevs -- e.g. "20060429/r239832-r" -- are aligned to just before
# the time of day when the mass-check tagging occurs; that's 0850 GMT,
# so align the daterev to 0800 GMT.
#
use constant DATEREV_ADJ => - (8 * 60 * 60);

my $q = new CGI;

my $ttk = Template->new;
set_freqs_templates();

my $cgi_url;
my @cgi_params;
my %cgi_params = ();
precache_params();

# ---------------------------------------------------------------------------

# Allow path info to become CGI-ish parameters.
# the two parts of path info double as (a) daterev, (b) rulename,
# (c) "s_detail=1".
# CGI parameters "daterev", "rule", "s_detail" override them though
#
my $url_abs = $q->url(-absolute=>1);
my $url_with_path = $q->url(-absolute=>1, -path_info=>1);

# if we have a valid, full URL (non-cgi use), use that instead of
# the "path_info" one, since CGI.pm will unhelpfully remove duplicate
# slashes.  this screws up "/FOO" rule grep searches.   Also,
# fix $url_abs to be correct for the "entire website is web app" case,
# as CGI.pm gets that wrong, too!

if ($url_abs =~ m,^/\d,) {
  $url_with_path = $url_abs;
  $url_abs = "/";
} else {
  $url_with_path =~ s,^${url_abs},,;
}

if ($url_with_path =~ s,^/*([^/]+),,) { add_cgi_path_param("daterev", $1); }
if ($url_with_path =~ s,^/(/?[^/]+),,) { add_cgi_path_param("rule", $1); }
if ($url_with_path =~ s,^/detail,,) { add_cgi_path_param("s_detail", "1"); }

# cgi_url: used in hrefs from the generated document
$cgi_url = $url_abs;
$cgi_url =~ s,/ruleqa/ruleqa$,/ruleqa,s;
$cgi_url ||= '/';

# ---------------------------------------------------------------------------

my %s = ();
# selection of what will be displayed.
$s{defcorpus} = get_url_switch('s_defcorpus', 1);
$s{html} = get_url_switch('s_html', 0);
$s{net} = get_url_switch('s_net', 0);
$s{zero} = get_url_switch('s_zero', 1);

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

sub get_url_switch {
  my ($name, $defval) = @_;
  my $val = $q->param($name);
  if (!defined $val) { return $defval; }
  return ($val) ? 1 : 0;
}

# when and what
my $daterev = $q->param('daterev') || '';
# all known date/revision combos.  warning: could get slow in future
my @daterevs = get_all_daterevs();

# sanitise daterev string
if (defined $daterev) {
  if ($daterev eq 'last-night') {
    $daterev = get_last_night_daterev();
    $q->param('daterev', $daterev);                # make it absolute
  }
  else {
    $daterev =~ /(\d+)[\/-](r\d+)-(\S+)/; undef $daterev;
    if ($2) {
      $daterev = "$1-$2-$3";
    } else {
      $daterev = undef;
    }
  }
}

# turn possibly-empty $daterev into a real date/rev combo (that exists)
$daterev = date_in_direction($daterev, 0);

# which rules?
my $rule = $q->param('rule') || '';
my $rules_all = 0;
my $rules_grep = 0;
my $nicerule = $rule;
if (!$nicerule) { $rules_all++; $nicerule = 'all rules'; }
if ($rule =~ /^\//) { $rules_grep++; $nicerule = 'regexp '.$rule; }

my $datadir;
my %freqs_head = ();
my %freqs_data = ();
my %freqs_ordr = ();
my $line_counter = 0;

# ---------------------------------------------------------------------------
# supported views

my $graph = $q->param('graph');
if ($graph) {
  if ($graph eq 'over_time') { graph_over_time(); }
  else { die "graph '$graph' unknown"; }
}
elsif ($q->param('longdatelist')) {
  print $q->header();
  show_daterev_selector_page();
}
else {
  print $q->header();
  show_default_view();
}
exit;

# ---------------------------------------------------------------------------

sub show_default_header {
my $title = shift;

my $hdr = q{<html><head>

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

    tr.freqsline_promo1 td {
      text-align: right;
      padding: 0.1em 0.2em 0.1em 0.2em;
    }
    tr.freqsline_promo0 td {
      text-align: right;
      padding: 0.1em 0.2em 0.1em 0.2em;
      color: #999;
    }
    tr.freqsline_promo0 td a { color: #999; }

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


    /* mouseover data for the freqs spam% and ham% figures using CSS2.
     * see: http://www.meyerweb.com/eric/css/edge/popups/demo.html
     */
    table tr td a.ftd {
      position: relative;
      /* relative positioning so that the span will be
       * "absolute" positioned relative to this block */
    }
    table tr td a.ftd span {
      display: none;
    }
    table tr td a.ftd:hover span {
      display: block;
      position: absolute; top: 1em; left: 0.5em;
      padding: 5px 20px 5px 20px; margin: 10px; z-index: 100;
      border: 1px dashed;
      background: #ffc;
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
  <script src="http://ruleqa.spamassassin.org/sorttable.js"></script>

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

  <h4> Which Corpus? </h4>
  <input type=checkbox name=s_defcorpus !s_defcorpus!> Show default non-net ruleset and corpus, set 0<br/>
  <input type=checkbox name=s_net !s_net!> Show frequencies from network tests, set 1<br/>
  <input type=checkbox name=s_html !s_html!> Show frequencies for mails containing HTML only, set 0<br/>
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

    <p class=intro> <strong>Instructions</strong>: click
    the rule name to view details of a particular rule. </p>

  };
}

show_all_sets_for_daterev($daterev, $daterev);

# don't show "graph" link unless only a single rule is being displayed
if ($s{detail} && !($rules_all || $rules_grep))
{
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

  <p>Note: the freqs tables are sortable.  Click on the headers to resort them
  by that column.  <a
  href="http://www.kryogenix.org/code/browser/sorttable/">(thanks!)</a></p>

  </body></html>

  };

exit;

}

sub get_all_daterevs {
  return sort map {
      s/^.*\/(\d+)\/(r\d+-\S+)$/$1-$2/; $_;
    } grep { /\/\d+\/r\d+-\S+$/ && -d $_ } (<$conf{html}/2*/r*>);
}

sub date_in_direction {
  my ($origdaterev, $dir) = @_;

  my $orig;
  if ($origdaterev && $origdaterev =~ /^(\d+)[\/-](r\d+-\S+)$/) {
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

sub get_last_night_daterev {
  # don't use a daterev after (now - 12 hours); that's too recent
  # to be "last night", for purposes of rule-update generation.

  my $notafter = strftime "%Y%m%d",
        gmtime ((time + DATEREV_ADJ) - (12*60*60));

  foreach my $dr (reverse @daterevs) {
    my $t = get_daterev_description($dr);
    next unless $t;
    if ($t =~ /<span class="date">(.+?)<\/span>/) {
      next if ($1+0 > $notafter);
    }
    if ($t =~ / tag=n /) {
      return $dr;
    }
  }
  return undef;
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
  $datadir =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  # outright block possibly-hostile stuff here:
  # no "../" path traversal
  die "forbidden: $safedatadir .." if ($safedatadir =~ /\.\./);

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
    if (/(?: \(all messages| results used|OVERALL\%|<mclogmd>|was at r\d+)/) {
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
    elsif (/ ([\+\-])? *(\S+?)(\:\S+)?\s*$/) {
      my $promochar = $1;
      $lastrule = $2;
      my $subset = $3;
      if ($subset) { $subset =~ s/^://; }

      my $is_testing = ($lastrule =~ /^T_/);
      my $is_subrule = ($lastrule =~ /^__/);

      # assume a default based on rule name; turn off explicitly
      # the rules that are not hitting qual thresholds.  list
      # both testing and core rules.
      my $promo = (!$is_subrule);
      if ($promochar eq '-') {
        $promo = 0;
      }

      my @vals = split;
      if (!exists $freqs_data{$key}{$lastrule}) {
        push (@{$freqs_ordr{$key}}, $lastrule);
        $freqs_data{$key}{$lastrule} = {
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
        promotable => $promo ? '1' : '0',
      };
      push @{$freqs_data{$key}{$lastrule}{lines}}, $line;
    }
    elsif (!/\S/) {
      # silently ignore empty lines
    }
    else {
      warn "warning: unknown freqs line in $file: '$_'";
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
  my $header_context = extract_freqs_head_info($freqs_head{$key});

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
      href="javascript:show_header('$headers_id')">(source details)</a>
      <a name='$titleplink' href='#$titleplink' class=title_permalink>(#)</a>
    </p>

    <table class=sortable id='freqs_${headers_id}' class=freqs>
      <tr class=freqshead>
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

  foreach my $rule (@rules) {
    if ($rule && defined $freqs_data{$key}{$rule}) {
      $comment .= rule_anchor($key,$rule);
      $comment .= output_freqs_data_line($freqs_data{$key}{$rule},
                $header_context);
    }
    elsif ($rules_all) {
      # all rules please...
      foreach my $r (@{$freqs_ordr{$key}}) {
        $comment .= rule_anchor($key,$r);
        $comment .= output_freqs_data_line($freqs_data{$key}{$r},
                $header_context);
      }
    }
    elsif ($rules_grep && $rule =~ /^\/(.*)$/) {
      my $regexp = $1;
      foreach my $r (@{$freqs_ordr{$key}}) {
        next unless ($r =~/${regexp}/i);
        $comment .= rule_anchor($key,$r);
        $comment .= output_freqs_data_line($freqs_data{$key}{$r},
                $header_context);
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

my $FREQS_LINE_TEMPLATE;
my $FREQS_EXTRA_TEMPLATE;

sub set_freqs_templates {
  $FREQS_LINE_TEMPLATE = qq{

  <tr class=freqsline_promo[% PROMO %]>
    <td>[% MSECS %]</td>
    <td><a class=ftd>[% SPAMPC %]<span>[% SPAMPCDETAIL %]</span></a>
    <td><a class=ftd>[% HAMPC %]<span>[% HAMPCDETAIL %]</span></a>
    <td>[% SO %]</td>
    <td>[% RANK %]</td>
    <td>[% SCORE %]</td>
    <td style='text-align: left'><a href="[% NAMEREF %]">[% NAME %]</a></td>
    <td>[% USERNAME %]</td>
    <td>[% AGE %]</td>
    <!--
      <rule><test>[% NAME %]</test><promo>[% PROMO %]</promo> <spc>[% SPAMPC %]</spc><hpc>[% HAMPC %]</hpc><so>[% SO %]</so> <detailhref esc='1'>[% NAMEREFENCD %]</detailhref></rule>
    -->
  </tr>

  };

  $FREQS_EXTRA_TEMPLATE = qq{

  <tr class=freqsextra>
    <td colspan=7><pre class=perruleextra>[% EXTRA %]</pre></td>
  </tr>

  };

  $FREQS_LINE_TEMPLATE =~ s/^\s+//gm;
  $FREQS_EXTRA_TEMPLATE =~ s/^\s+//gm;
}

sub extract_freqs_head_info {
  my $headstr = shift;
  my $ctx = { };

  # extract the "real" numbers of mails for particular classes, for
  # some of the report types:
  #   0     1000     1000    0.500   0.00    0.00  (all messages):mc-fast
  #   0     4983     4995    0.499   0.00    0.00  (all messages):mc-med
  #   0     9974     9995    0.499   0.00    0.00  (all messages):mc-slow
  #   0    19972    19994    0.500   0.00    0.00  (all messages):mc-slower
  # or just:
  #   0    35929    35984    0.500   0.00    0.00  (all messages)
  while ($headstr =~ m/^
        \s+\d+\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\(all\smessages\)(|:\S+)\s*
        $/gmx)
  {
    $ctx->{'message_count'.$3} = {
          nspam => $1,
          nham => $2
        };
  }

  return $ctx;
}

sub create_spampc_detail {
  my ($percent, $isspam, $ctx, $line) = @_;

  # optimization: no need to look anything up if it's 0.0000%
  if ($percent == 0.0) { return qq{ 0\&nbsp;messages }; }

  my $who = $line->{username} || $line->{age};
  my $obj;
  if ($who) {
    $obj = $ctx->{'message_count:'.$who};
  } else {
    $obj = $ctx->{'message_count'};
  }

  if (!$obj) {
    return "???";      # no data found for that submitter, stop here!
  }

  my $outof = ($isspam ? $obj->{nspam} : $obj->{nham});
  my $count = int (($percent/100.0) * $outof);
  return qq{
    $count\&nbsp;of\&nbsp;$outof\&nbsp;messages
  };
}

sub output_freqs_data_line {
  my ($obj, $header_context) = @_;

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

    $ttk->process(\$FREQS_LINE_TEMPLATE, {
        RULEDETAIL => $detailurl,
        MSECS => $line->{msecs},
        SPAMPC => $line->{spampc},
        HAMPC => $line->{hampc},
        SPAMPCDETAIL => create_spampc_detail($line->{spampc}, 1,
                 $header_context, $line),
        HAMPCDETAIL => create_spampc_detail($line->{hampc}, 0,
                 $header_context, $line),
        SO => $line->{so},
        RANK => $line->{rank},
        SCORE => $score,
        NAME => $line->{name},
        NAMEREF => create_detail_url($line->{name}),
        NAMEREFENCD => uri_encode(create_detail_url($line->{name})),
        USERNAME => $line->{username} || '',
        AGE => $line->{age} || '',
        PROMO => $line->{promotable},
    }, \$out) or die $ttk->error();

    $line_counter++;
  }

  # add scoremap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{scoremap}) {
    my $ovl = $obj->{scoremap} || '';
    #   scoremap spam: 16  12.11%  777 ****

    $ttk->process(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $ttk->error();
  }

  # add overlap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{overlap}) {
    my $ovl = $obj->{overlap} || '';

    $ovl =~ s/^(\s+overlap\s+(?:ham|spam):\s+\d+% )(\S.+?)$/
        my $str = "$1";
        foreach my $rule (split(' ', $2)) {
          $str .= gen_rule_link($rule,$rule)." ";
        }
        $str;
      /gem;

    $ttk->process(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $ttk->error();
  }

  return $out;
}

sub create_detail_url {
  my ($rulename) = @_;
  my @parms = (
        get_params_except(qw(
          rule s_age s_overlap s_all s_detail daterev
        )), 
        "daterev=".$daterev, "rule=".uri_escape($rulename), "s_detail=1",
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
  my @orig = @_;

  # e.g. http://buildbot.spamassassin.org/ruleqa?
  #     daterev=20060120-r370897-b&rule=T_PH_SEC&s_detail=1

  # we support special treatment for 'daterev' and 'rule'
  my %path = ();
  my @parms = ();
  $path{daterev} = '';
  $path{rule} = '';
  foreach my $p (@orig) {
    # some ignored parameter noise, from the form
    if (!$p) { next; }
    elsif ($p =~ /^keywords=$/) { next; }
    elsif ($p =~ /^g=Change$/) { next; }
    # the ones we can put in the path
    elsif ($p =~ /^rule=(.*)$/) { $path{rule} = $1; }
    elsif ($p =~ /^daterev=(.*)$/) { $path{daterev} = $1; }
    elsif ($p =~ /^s_detail=1$/) { $path{s_detail} = 1; }
    # and all the rest
    else { push (@parms, $p); }
  }

  # ensure "/FOO" rule greps are encoded as "%2FFOO"
  $path{rule} =~ s,^/,\%2F,;

  my $url = $cgi_url.
        ($path{daterev}  ? '/'.$path{daterev} : '').
        ($path{rule}     ? '/'.$path{rule}    : '').
        ($path{s_detail} ? '/detail'          : '').
        '?'.join('&', sort @parms);

  # no need for a trailing ? if there were no parms
  $url =~ s/\?$//;

  # ensure local URL (not starting with "//", which confuses Firefox)
  $url =~ s,^/+,/,;

  # now, a much more readable
  # http://ruleqa.spamassassin.org/
  #      20060120-r370897-b/T_PH_SEC/detail

  return $url;
}

sub precache_params {
  use URI::Escape;

  @cgi_params = $q->param();
  foreach my $k (@cgi_params) {
    next unless defined ($k);
    my $v = $q->param($k);
    if (!defined $v) { $v = ''; }
    $cgi_params{$k} = "$k=".uri_escape($v);
  }
}

sub add_cgi_path_param {
  my ($k, $v) = @_;
  if (!defined $cgi_params{$k}) {
    $cgi_params{$k} = "$k=$v";
    push (@cgi_params, $k);
  }
  $q->param(-name=>$k, -value=>$v);
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
      $drtitle =~ s/[\"\'\&\>\<]/ /gs;
      $drtitle =~ s/\s+/ /gs;
      $drtitle =~ s/^(.{0,160}).*$/$1/gs;

      my $mds_as_text = '';
      if (defined $fastinfo->{mclogmds} && $fastinfo->{mclogmds}->{mclogmd}) {
        # $mds_as_text = XMLout($fastinfo->{mclogmds});
        # use Data::Dumper; $mds_as_text = Dumper($fastinfo->{mclogmds});

        # 'mclogmd' => [
        #    {
        #      'daterev' => '20060430/r398298-n',
        #      'mcstartdate' => '20060430T122405Z',
        #      'mtime' => '1146404744',
        #      'rev' => '398298',
        #      'file' => 'ham-cthielen.log',
        #      'fsize' => '3036336'
        #    }, [...]

        my $all = '';
        foreach my $f (@{$fastinfo->{mclogmds}->{mclogmd}}) {
          my $started = $f->{mcstartdate};
          my $subtime = strftime "%Y%m%dT%H%M%SZ", gmtime $f->{mtime};

          $all .= qq{
          
            <p> <b>$f->{file}</b>:
                started: $started;
                submitted: $subtime;
                size: $f->{fsize} bytes
            </p>

          };
        }

        $mds_as_text = qq{ <span class="mclogmds"> $all </span> };
      }

      $txt = qq{

          <td class=daterevtd>
            <a name="$dranchor" title="$drtitle"
                href="!drhref!"><span class="date">$fastinfo->{date}</span></a>
          </td>
          <td class=daterevtd>
            <a title="$drtitle" href="!drhref!">$fastinfo->{rev}</a>
          </td>
          <td class=daterevtd>
            <a title="$drtitle" href="!drhref!">$cdate</a>
          </td>
          <td class=daterevtd>
            <a title="$drtitle" href="!drhref!">$info->{checkin_rev}</a>
          </td>
          <td class=daterevtd>
            <em><mcauthor>$info->{author}</mcauthor></em>
            <em><mcwasnet>$net</mcwasnet></em>
          </td>
          <!-- tag=$fastinfo->{tag} -->

        </tr>
        <tr class=daterevdesc>

          <td></td>
          <td class=daterevtd colspan=4>
              <em>($drtitle)</em>
          </td>
          <td class=daterevtd colspan=1>
              <em><mcsubmitters>$fastinfo->{submitters}</mcsubmitters></em>
              <!--
              $mds_as_text
              -->
          </td>

      };
    };

    if ($@) {
      warn "daterev info.xml: $@";
    }

    if ($txt) { return $txt; }
  }

  # if that failed, just use the daterev itself.
  $dr =~ /^(\d+)-r(\d+)-(\S+)$/;
  my $date = $1;
  my $rev = $2;
  my $tag = $3;
  my $drtitle = "(no info)";

  $txt = qq{

        <td class=daterevtd>
       <a title="$drtitle" href="!drhref!">$date</a></td>
        <td class=daterevtd>
       <a title="$drtitle" href="!drhref!">$rev</a></td>
        <td class=daterevtd colspan=3>
       <a title="$drtitle" href="!drhref!">(no info on this commit yet)</a></td>

  };

  return $txt;
}

sub show_daterev_selector_page {
  my $title = "Rule QA: all recent mass-check results";
  print show_default_header($title);

  my @drs_net = ();
  my @drs_nightly = ();
  my @drs_preflight = ();

  foreach my $dr (@daterevs) {
    next unless $dr;

    my $obj = {
        dr => $dr,
        text => get_daterev_description($dr) || ''
      };

    # now match against the microformat data in the HTML, to select
    # the desired subsets of certain types
    if ($obj->{text} =~ / tag=b /) {
      push @drs_preflight, $obj;
    }
    elsif ($obj->{text} =~ /<mcwasnet>\s*.net/) {
      push @drs_net, $obj;
    }
    else {
      push @drs_nightly, $obj;
    }
  }

  # remove all but the most recent 100.  (TODO: need a "full" view?)
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

sub uri_encode {
  my ($str) = @_;
  return uri_escape($str);
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


