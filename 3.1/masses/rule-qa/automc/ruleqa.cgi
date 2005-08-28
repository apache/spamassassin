#!/usr/bin/perl -w

# my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";
my $automcdir = "/home/automc/svn/spamassassin/masses/rule-qa/automc";

use CGI;
use strict;
use bytes;

open (CF, "<$automcdir/config");
my %conf; while(<CF>) { /^(\S+)=(\S+)/ and $conf{$1} = $2; }
close CF;

our %freqs_filenames = (
    'DETAILS.age' => 'set 0, by message age',
    'DETAILS.all' => 'set 0, by contributor',
    'DETAILS.new' => 'set 0, summary',
    'HTML.age' => 'set 0, by message age, HTML messages only',
    'HTML.all' => 'set 0, by contributor, HTML messages only',
    'HTML.new' => 'set 0, summary, HTML messages only',
    'NET.age' => 'set 1 (network), by message age',
    'NET.all' => 'set 1 (network), by contributor',
    'NET.new' => 'set 1 (network), summary',
    'OVERLAP.new' => 'set 0, overlaps between rules',
);

my $q = new CGI;
print $q->header;

my $cgi_url;
my @cgi_params;
my %cgi_params = ();
precache_params();

my %s = ();
# selection of what will be displayed.
$s{details} = get_url_switch('s_details', 0);
$s{html} = get_url_switch('s_html', 0);
$s{net} = get_url_switch('s_net', 0);
$s{overlap} = get_url_switch('s_overlap', 0);

$s{new} = get_url_switch('s_new', 0);
$s{age} = get_url_switch('s_age', 0);
$s{all} = get_url_switch('s_all', 0);
$s{overlap} = get_url_switch('s_overlap', 0);

$s{headers} = get_url_switch('s_headers', 0);

if (!grep { $_ } values %s) {
  $s{details} = 1;      # set the defaults
  $s{new} = 1;
}

sub get_url_switch {
  my ($name, $defval) = @_;
  my $val = $q->url_param($name);

  if (!defined $val) { return $defval; }
  return ($val) ? 1 : 0;
}

# when and what
my $date = $q->url_param('date');
my $rule = $q->url_param('rule');

my $nicerule = $rule; if ($nicerule eq '') { $nicerule = 'all rules'; }
my $title = "Nightly corpus mass-check: $date $nicerule";

print q{<html><head>

  <style type="text/css" media="all">
    body {
      padding: 1em 1em 1em 1em;
    }
    pre.freqs {
      font-family: monospace;
      font-size: 14px;
      margin-left: 1em;
      border: 1px dashed #ddb;
      padding: 10px 20px 10px 20px;
    }
    div.updateform {
      border: 3px solid #aaa;
      background: #eee;
      margin: 1em 0em 1em 0em;
      padding: 1em 1em 1em 3em;
    }
  </style>

  <title>}.$title.q{</title>

  </head><body>

};

my $tmpl = q{

<div class=updateform>
<form action="!THISURL!" method=GET>
  <input type=checkbox name=s_headers !s_headers!> Show headers<br/>
  <br/>
  <input type=checkbox name=s_details !s_details!> Show details<br/>
  <input type=checkbox name=s_html !s_html!> Show freqs on HTML mail<br/>
  <input type=checkbox name=s_net !s_net!> Show network test freqs<br/>
  <br/>
  <input type=checkbox name=s_new !s_new!> Show combined freqs<br/>
  <input type=checkbox name=s_age !s_age!> Show freqs by message age<br/>
  <input type=checkbox name=s_all !s_all!> Show freqs by contributor<br/>
  <br/>
  <input type=checkbox name=s_overlap !s_overlap!> Show overlaps between rules<br/>
  <br/>
  Date to display: <input type=textfield name=date value="!date!"><br/>
  <br/>
  Show only these rules (space separated, or regexp with '/' prefix):<br/>
  <input type=textfield size=60 name=rule value="!rule!"><br/>

  <input type=submit name=g value="Change"><br/>
</form>
</div>

};

$tmpl =~ s/!THISURL!/$cgi_url/gs;
$tmpl =~ s/!date!/$date/gs;
$tmpl =~ s/!rule!/$rule/gs;
foreach my $opt (keys %s) {
  if ($s{$opt}) {
    $tmpl =~ s/!s_$opt!/checked /gs;
  } else {
    $tmpl =~ s/!s_$opt!/ /gs;
  }
}

print $tmpl;

# fill in current date if unspecified
if (!$date) {
  use POSIX qw(strftime);
  $date = strftime("%Y%m%d", localtime);
}

my $datadir = $conf{html}."/".$date."/";
my %freqs_head = ();
my %freqs_data = ();
my %freqs_ordr = ();

$s{details} and showfreqset('DETAILS');
$s{html} and showfreqset('HTML');
$s{net} and showfreqset('NET');

# special case: we only build this for one set, as it's quite slow
# to generate
$s{overlap} and showfreqsubset("OVERLAP.new");

print "

  </body></html>

";

exit;

###########################################################################

sub showfreqset {
  my ($type) = @_;
  $s{new} and showfreqsubset("$type.new");
  $s{age} and showfreqsubset("$type.age");
  $s{all} and showfreqsubset("$type.all");
}

sub showfreqsubset {
  my ($filename) = @_;
  read_freqs_file($filename);
  get_freqs_for_rule($filename, $rule);
}

sub read_freqs_file {
  my ($key) = @_;

  my $file = $datadir.$key;
  open (IN, "<$file") or warn "cannot read $file";

  $freqs_head{$key}=<IN>;
  $freqs_data{$key} = { };
  $freqs_ordr{$key} = [ ];
  my $lastrule;

  while (<IN>) {
    if (/(?: \(all messages| results used:|OVERALL\% )/) {
      $freqs_head{$key} .= $_;
    }
    elsif (/\s+overlap (.*)$/) {
      $freqs_data{$key}{$lastrule} .= $_;
    }
    elsif (/\s+(\S+?)(?:\:\S+)?\s*$/) {
      $lastrule = $1;
      if (!exists $freqs_data{$key}{$1}) {
        push (@{$freqs_ordr{$key}}, $1);
        $freqs_data{$key}{$1} = '';
      }
      $freqs_data{$key}{$1} .= $_;
    }
  }
  close IN;
}

sub get_freqs_for_rule {
  my ($key, $ruleslist) = @_;

  my $desc = $freqs_filenames{$key};
  my $file = $datadir.$key;

  my $comment = "
  
    <h3>freqs from \"$key\" ($freqs_filenames{$key}):</h3>

    <pre class=freqs>";

  if ($s{headers}) {
    $comment .= sub_freqs_head_line($freqs_head{$key});
  }

  $ruleslist ||= '';
  my @rules = split (' ', $ruleslist);
  if (scalar @rules == 0) { @rules = (''); }

  my $first_round_in_loop = 1;

  foreach my $rule (@rules) {
    if (!$first_round_in_loop) {
      $comment .= "<pre class=freqs>";
      $first_round_in_loop = 0;
    }
    if ($rule && defined $freqs_data{$key}{$rule}) {
      $comment .= rule_anchor($key,$rule);
      $comment .= sub_freqs_data_line($freqs_data{$key}{$rule});

      $comment .= "</pre><p>"
        .gen_rule_in_context_link($key, $rule, "(See rule in context)")
        ."</p>";
    }
    elsif ($rule eq '') {
      # all rules please...
      foreach my $r (@{$freqs_ordr{$key}}) {
        $comment .= rule_anchor($key,$r);
        $comment .= sub_freqs_data_line($freqs_data{$key}{$r});
      }
    }
    elsif ($rule =~ /^\/(.*)$/) {
      my $regexp = $1;
      foreach my $r (@{$freqs_ordr{$key}}) {
        next unless ($r =~/${regexp}/i);
        $comment .= rule_anchor($key,$r);
        $comment .= sub_freqs_data_line($freqs_data{$key}{$r});
      }
    }
    else {
      $comment .= rule_anchor($key,$rule);
      $comment .= "
        (could not find freqs for rule '$rule' on selected date)
      ";
    }
  }
  
  print $comment;
  print "</pre>";
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

sub sub_freqs_data_line {
  my ($str) = @_;

  # normal freqs lines, with optional subselector after rule name
  $str =~ s/(  )(\S+?)(:\S+)?$/
        $1.gen_rule_link($2,$2).$3;
    /gem;

  # overlap lines
  $str =~ s/^(\s+overlap\s+(?:ham|spam):\s+\d+% )(\S+?)$/
        $1.gen_rule_link($2,$2);
    /gem;

  return $str;
}

sub gen_rule_link {
  my ($rule, $linktext) = @_;

  my @parms = get_params_except('rule');
  push (@parms, "rule=".uri_escape($rule));
  my $url = $cgi_url.'?'.join('&', @parms);

  return "<a href='$url'>$linktext</a>";
}

sub gen_rule_in_context_link {
  my ($key, $rule, $linktext) = @_;

  my $anchor = uri_escape($key."_".$rule);
  my @parms = get_params_except('rule');
  my $url = $cgi_url.'?'.join('&', @parms)."\#".$anchor;

  return "<a href='$url'>$linktext</a>";
}

sub gen_switch_url {
  my ($switch, $newval) = @_;

  my @parms = get_params_except($switch);
  push (@parms, "$switch=$newval");
  my $url = $cgi_url.'?'.join('&', @parms);
  return $url;
}

sub precache_params {
  use URI::Escape;
  $cgi_url = $q->url(-relative=>1);
  @cgi_params = $q->url_param();
  foreach my $k (@cgi_params) {
    next unless defined ($k);
    my $v = $q->url_param($k);
    $cgi_params{$k} = "$k=".uri_escape($v);
  }
}

sub get_params_except {
  my ($skip) = @_;
  my @str = ();
  foreach my $p (@cgi_params) {
    next if ($p eq $skip || $cgi_params{$p} =~ /^\Q$skip\E=/);
    push (@str, $cgi_params{$p});
  }
  @str;
}

=cut

to install, add this line to httpd.conf:

  ScriptAlias /ruleqa "/path/to/spamassassin/automc/ruleqa.cgi"

