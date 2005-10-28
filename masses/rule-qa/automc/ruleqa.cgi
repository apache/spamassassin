#!/local/perl586/bin/perl -w
my $automcdir = "/home/automc/svn/spamassassin/masses/rule-qa/automc";

###!/usr/bin/perl -w
##my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";

use CGI;
use Template;
use Date::Manip;

use strict;
use bytes;
use POSIX qw(strftime);

my $myperl = $^X;

open (CF, "<$automcdir/config");
my %conf; while(<CF>) { /^(\S+)=(\S+)/ and $conf{$1} = $2; }
close CF;

our %freqs_filenames = (
    'DETAILS.age' => 'set 0, broken down by message age',
    'DETAILS.all' => 'set 0, broken down by contributor',
    'DETAILS.new' => 'set 0, in aggregate',
    'HTML.age' => 'set 0, by message age, HTML messages only',
    'HTML.all' => 'set 0, by contributor, HTML messages only',
    'HTML.new' => 'set 0, in aggregate, HTML messages only',
    'NET.age' => 'set 1 (network), by message age',
    'NET.all' => 'set 1 (network), by contributor',
    'NET.new' => 'set 1 (network), in aggregate',
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

# note: age, new, overlap are all now synonyms for detail ;)
if ($s{age} || $s{overlap} || $s{detail}) {
  $s{age} = 1;
  $s{all} = 1;
  $s{new} = 1;
  $s{overlap} = 1;
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
$daterev =~ /(\d+\/r\d+)/;
$daterev = $1;

# all known date/revision combos.  warning: could get slow in future
my @daterevs = get_all_daterevs();
# turn possibly-empty $daterev into a real date/rev combo (that exists)
$daterev = date_in_direction($daterev, 0);

my $rule = $q->url_param('rule') || '';

$s{graph} = $q->url_param('graph') || '';
if ($s{graph} eq 'ruleshit') {
  graph_ruleshit();
  die "oops! should not get here";  # prev method should exit
}

my $nicerule = $rule; if (!$nicerule) { $nicerule = 'all rules'; }
my $title = "Mass-check: $daterev $nicerule";

print $q->header;
print q{<html><head>

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
      padding: 10px 20px 10px 20px;
    }
    tr.freqshead {
      background: #ddd;
    }
    tr.freqsline td {
      text-align: right;
      padding: 0.1em 0.2em 0.1em 0.2em;
    }

    h3 {
      border: 1px solid;
      padding: 10px 20px 10px 20px;
      margin: 20px -20px -10px -20px;
      background: #fe8;
    }

    td.daterevtd {
      font-size: 75%;
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

  <title>}.$title.q{</title>

  </head><body>

};

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
      <th>
        &lt;&lt;
      </th><th>
        Past
      </th><th>
      </th><th>
        Displaying
      </th><th>
      </th><th>
        Future
      </th><th>
        &gt;&gt;
      </th>
    </tr><tr>
           <td class=daterevtd> !daylinkneg3!
      </td><td class=daterevtd> !daylinkneg2!
      </td><td class=daterevtd> !daylinkneg1!
      </td><td class=daterevtd> !todaytext!
      </td><td class=daterevtd> !daylinkpls1!
      </td><td class=daterevtd> !daylinkpls2!
      </td><td class=daterevtd> !daylinkpls3!
      </td>
    </tr>

  </table>
  Date/Rev to display (UTC timezone):
  <input type=textfield name=daterev value="!daterev!"><br/>
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
    $tmpl =~ s/!daylink${key}!/
        (no logs<br\/>available)
    /gs;
  }
  else {
    $dr = gen_switch_url("daterev", $dr);
    $drtext =~ s,/,/<br/>,gs;         # allow line-break

    $tmpl =~ s/!daylink${key}!/
        <a href="$dr">$drtext<\/a>
    /gs;
  }
}

$daterev = date_in_direction($daterev, 0);
my $todaytext = $daterev;
$todaytext =~ s,/,/<br/>,gs;         # allow line-break
$tmpl =~ s/!todaytext!/$todaytext/gs;


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

my $datadir;
my %freqs_head = ();
my %freqs_data = ();
my %freqs_ordr = ();

show_all_sets_for_daterev($daterev, $daterev);

if ($s{detail}) {
  my $url_rh = gen_switch_url("s_graph", "ruleshit");
  print qq{

    <h3 class=graph_title>graphs</h3>
    <ul>
      <li><a href="$url_rh">rules hit over time</a></li>
    </ul>

  };

  my @parms =get_params_except(qw(
          rule s_age s_overlap s_all s_detail
        ));
  $url = $cgi_url.'?'.join('&', sort @parms);

  print qq{

    <p><a href="$url">&lt; Back</a> to overview.</p>

  };
}

print qq{

  </body></html>

  };

exit;

sub get_all_daterevs {
  return sort map {
      s/^.*\/(\d+\/r\d+)$/$1/; $_;
    } grep { /\/(\d+\/r\d+)$/ && -d $_ } (<$conf{html}/2*/r*>);
}

sub date_in_direction {
  my ($origdaterev, $dir) = @_;

  my $orig;
  if ($origdaterev && $origdaterev =~ /^\d+\/r\d+$/) {
    $orig = $origdaterev;
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

  if ($new && -d $conf{html}."/".$new) {
    return $new;
  }

  return undef;       # couldn't find one
}

sub show_all_sets_for_daterev {
  my ($path, $strdate) = @_;

  $strdate = "mass-check date/rev: $path";
  $datadir = $conf{html}."/".$path."/";

  $s{defcorpus} and showfreqset('DETAILS', $strdate);
  $s{html} and showfreqset('HTML', $strdate);
  $s{net} and showfreqset('NET', $strdate);

  # special case: we only build this for one set, as it's quite slow
  # to generate
  $s{overlap} and showfreqsubset("OVERLAP.new", $strdate);
}

###########################################################################

sub graph_ruleshit {
  $datadir = $conf{html}."/".$daterev."/";

  # logs are named e.g.
  # /home/automc/corpus/html/20051028/r328993/LOGS.all-ham-mc-fast.log.gz

  # untaint
  $rule =~ /([_0-9a-zA-Z]+)/; my $saferule = $1;
  $datadir =~ /([-\.\,_0-9a-zA-Z]+)/; my $safedatadir = $1;

  exec ("$myperl $automcdir/../../rule-hits-over-time ".
        "--cgi --rule='$saferule' ".
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
  get_freqs_for_rule($filename, $strdate, $rule);
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
    if (/(?: \(all messages| results used:|was at r\d+)/) {
      $freqs_head{$key} .= $_;
    }
    elsif (/OVERALL\%/) {
      next;	# just ignored for now
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
        overallpc => $vals[0],
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
      href="javascript:show_header('$headers_id')">(more info)</a></p>

    <table class=freqs><tr class=freqshead>
      <th>
    <a name='$titleplink'></a><a href='#$titleplink' class=title_permalink>#</a>
      </th>
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

    <tr class=freqsline>
      <td>
      [% IF RULEDETAIL != '' %]
	<a href="[% RULEDETAIL %]">&gt;</a>
      [% END %]
      </td>
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
      my $ov = $line->{overallpc};
      if (!$ov || $ov !~ /^\s*\d/ || $ov+0 == 0) {
        next;       # skip this line, it's a 0-hitter
      }
    }

    my $detailurl = '';
    if (!$s{detail}) {	# not already in "detail" mode
      $detailurl = create_detail_url($line->{name});
    }

    $ttk->process(\$LINE_TEMPLATE, {
        RULEDETAIL => $detailurl,
        OVERALLPC => $line->{overallpc},
        SPAMPC => $line->{spampc},
        HAMPC => $line->{hampc},
        SO => $line->{so},
        RANK => $line->{rank},
        SCORE => $line->{score},
        NAME => $line->{name},
        NAMEREF => create_detail_url($line->{name}),
        USERNAME => $line->{username} || '',
        AGE => $line->{age} || '',
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
  my $url = $cgi_url.'?'.join('&', sort @parms);
  return $url;
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

=cut

to install, add this line to httpd.conf:

  ScriptAlias /ruleqa "/path/to/spamassassin/automc/ruleqa.cgi"

