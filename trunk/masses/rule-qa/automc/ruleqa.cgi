#!/local/perl586/bin/perl
my $automcdir = "/home/automc/svn/spamassassin/masses/rule-qa/automc";

###!/usr/bin/perl
##my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";

use strict;
use warnings;
use bytes;

my $self = Mail::SpamAssassin::CGI::RuleQaApp->new();

my $PERL_INTERP = $^X;

our %FREQS_FILENAMES = (
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

$self->ui_parse_url_base();
$self->ui_get_url_switches();
$self->ui_get_daterev();
$self->ui_get_rules();
$self->show_view();
exit;

# ---------------------------------------------------------------------------

package Mail::SpamAssassin::CGI::RuleQaApp;
use CGI;
use CGI::Carp 'fatalsToBrowser';
use Template;
use Date::Manip;
use XML::Simple;
use URI::Escape;
use Time::Local;
use POSIX qw();

# daterevs -- e.g. "20060429/r239832-r" -- are aligned to just before
# the time of day when the mass-check tagging occurs; that's 0850 GMT,
# so align the daterev to 0800 GMT.
#
use constant DATEREV_ADJ => - (8 * 60 * 60);

my $FREQS_LINE_TEMPLATE;
my $FREQS_LINE_TEXT_TEMPLATE;
my $FREQS_EXTRA_TEMPLATE;
our %AUTOMC_CONF;

our @ISA = qw();

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = { };

  $self->{q} = CGI->new();
  $self->{ttk} = Template->new();

  $self->{id_counter} = 0;
  $self->{include_embedded_freqs_xml} = 1;
  $self->{cgi_param_order} = [ ];
  $self->{cgi_params} = { };

  bless ($self, $class);

  # some global configuration
  $self->set_freqs_templates();
  $self->read_automc_global_conf();

  $self->precache_params();

  return $self;
}

# ---------------------------------------------------------------------------

sub read_automc_global_conf {
  my ($self) = @_;

  open (CF, "<$automcdir/config") or return;
  while(<CF>) { /^(\S+)=(\S+)/ and $AUTOMC_CONF{$1} = $2; }
  close CF;
}

# ---------------------------------------------------------------------------

sub ui_parse_url_base {
  my ($self) = @_;

# Allow path info to become CGI-ish parameters.
# the two parts of path info double as (a) daterev, (b) rulename,
# (c) "s_detail=1".
# CGI parameters "daterev", "rule", "s_detail" override them though
#
  $self->{url_abs} = $self->{q}->url(-absolute=>1);
  $self->{url_with_path} = $self->{q}->url(-absolute=>1, -path_info=>1);

# if we have a valid, full URL (non-cgi use), use that instead of
# the "path_info" one, since CGI.pm will unhelpfully remove duplicate
# slashes.  this screws up "/FOO" rule grep searches.   Also,
# fix $self->{url_abs} to be correct for the "entire website is web app" case,
# as CGI.pm gets that wrong, too!

  if ($self->{url_abs} =~ m,^/(?:20\d|last-preflight|last-night|today),) {
    $self->{url_with_path} = $self->{url_abs};
    $self->{url_abs} = "/";
  } else {
    $self->{url_with_path} =~ s,^\Q$self->{url_abs}\E,,;
  }

  if ($self->{url_with_path} =~ s,^/*([^/]+),,) { $self->add_cgi_path_param("daterev", $1); }
  if ($self->{url_with_path} =~ s,^/(/?[^/]+),,) { $self->add_cgi_path_param("rule", $1); }
  if ($self->{url_with_path} =~ s,^/detail,,) { $self->add_cgi_path_param("s_detail", "1"); }

# cgi_url: used in hrefs from the generated document
  $self->{cgi_url} = $self->{url_abs};
  $self->{cgi_url} =~ s,/ruleqa/ruleqa$,/ruleqa,s;
  $self->{cgi_url} ||= '/';
}

# ---------------------------------------------------------------------------

sub ui_get_url_switches {
  my ($self) = @_;

  $self->{s} = { };

# selection of what will be displayed.
  $self->{s}{detail} = $self->get_url_switch('s_detail', 0);
  $self->{s}{g_over_time} = $self->get_url_switch('s_g_over_time', 0);

  $self->{s}{xml} = $self->get_url_switch('xml', 0);
  $self->{include_embedded_freqs_xml} = $self->{s}{xml};

# note: age, new, overlap are all now synonyms for detail ;)
  if ($self->{s}{age} || $self->{s}{overlap} || $self->{s}{detail}) {
    $self->{s}{age} = 1;
    $self->{s}{all} = 1;
    $self->{s}{new} = 1;
    $self->{s}{overlap} = 1;
    $self->{s}{scoremap} = 1;
  }

  # always show "new" set, though
  $self->{s}{new} = 1;
}

sub get_url_switch {
  my ($self, $name, $defval) = @_;
  my $val = $self->{q}->param($name);
  if (!defined $val) { return $defval; }
  return ($val) ? 1 : 0;
}

# ---------------------------------------------------------------------------

sub ui_get_daterev {
  my ($self) = @_;

  # when and what
  $self->{daterev} = $self->{q}->param('daterev') || '';

  # all known date/revision combos.  warning: could get slow in future
  @{$self->{daterevs}} = $self->get_all_daterevs();

  # sanitise daterev string
  if (defined $self->{daterev}) {

    # all of these ignore "b" preflight mass-checks, btw
    if ($self->{daterev} eq 'last-night') {
      $self->{daterev} = $self->get_last_night_daterev();
      $self->{q}->param('daterev', $self->{daterev});  # make it absolute
    }
    elsif ($self->{daterev} eq 'last-preflight') {
      $self->{daterev} = undef;
    }
    elsif ($self->{daterev} eq 'today') {
      $self->{daterev} = $self->get_daterev_by_date(
            POSIX::strftime "%Y%m%d", gmtime ((time + DATEREV_ADJ)));
      $self->{q}->param('daterev', $self->{daterev});  # make it absolute
    }
    elsif ($self->{daterev} =~ /^(20\d\d[01]\d\d\d)$/) {
      # a date
      $self->{daterev} = $self->get_daterev_by_date($1);
      $self->{q}->param('daterev', $self->{daterev});  # make it absolute
    }
    elsif ($self->{daterev} =~ /(\d+)[\/-](r\d+)-(\S+)/ && $2) {
      $self->{daterev} = "$1-$2-$3";
    } else {
      # default: last-night's
      $self->{daterev} = $self->get_last_night_daterev();
    }
  }

  # turn possibly-empty $self->{daterev} into a real date/rev combo (that exists)
  $self->{daterev} = $self->date_in_direction($self->{daterev}, 0);

  $self->{daterev_md} = $self->get_daterev_metadata($self->{daterev});
}

# ---------------------------------------------------------------------------

sub ui_get_rules {
  my ($self) = @_;

  # which rules?
  $self->{rule} = $self->{q}->param('rule') || '';
  $self->{rules_all} = 0;
  $self->{rules_grep} = 0;
  $self->{nicerule} = $self->{rule};
  if (!$self->{nicerule}) {
    $self->{rules_all}++; $self->{nicerule} = 'all rules';
  }
  if ($self->{rule} =~ /^\//) {
    $self->{rules_grep}++; $self->{nicerule} = 'regexp '.$self->{rule};
  }

  $self->{srcpath} = $self->{q}->param('srcpath') || '';
  $self->{mtime} = $self->{q}->param('mtime') || '';

  $self->{freqs_head} = { };
  $self->{freqs_data} = { };
  $self->{freqs_ordr} = { };
  $self->{line_counter} = 0;
}

# ---------------------------------------------------------------------------
# supported views

sub show_view {
  my ($self) = @_;

  if ($self->{q}->param('mclog')) {
    $self->show_mclog($self->{q}->param('mclog'));
  }

  my $graph = $self->{q}->param('graph');
  if ($graph) {
    if ($graph eq 'over_time') { $self->graph_over_time(); }
    else { die "graph '$graph' unknown"; }
  }
  elsif ($self->{q}->param('longdatelist')) {
    print $self->{q}->header();
    $self->show_daterev_selector_page();
  }
  elsif ($self->{q}->param('shortdatelist')) {
    $self->{s_shortdatelist} = 1;
    print $self->{q}->header();
    $self->show_default_view();
  }
  else {
    print $self->{q}->header();

    # $self->get_rule_metadata(428771);
    $self->show_default_view();
  }
}

# ---------------------------------------------------------------------------

sub show_default_header {
  my ($self, $title) = @_;

  my $hdr = q{<html><head>
  <title>}.$title.q{</title>

  <link href="/ruleqa.css" rel="stylesheet" type="text/css">
  <script src="http://ruleqa.spamassassin.org/sorttable.js"></script>
  <script type="text/javascript"><!--

    function hide_header(id) {document.getElementById(id).style.display="none";}
    function show_header(id) {document.getElementById(id).style.display="block";}

    //-->
  </script>

  </head><body>

  };
  return $hdr;
}

sub show_default_view {
  my ($self) = @_;

  my $title;
  if ($self->{s}{detail}) {
    $title = "Rule QA: details for $self->{nicerule} (in $self->{daterev})";
  } else {
    $title = "Rule QA: overview of all rules (in $self->{daterev})";
  }
  print $self->show_default_header($title);

  my $tmpl = q{

  <div class='updateform'>
  <form action="!THISURL!" method="GET">
    <table style="padding-left: 0px" class='datetable'>

        <tr>
        <th> Commit </th>
        <th> Preflight Mass-Checks </th>
        <th> Nightly Mass-Checks </th>
        <th> Network Mass-Checks </th>
        </tr>

        !daylinkstable!

    </table>

  <table width='100%'>
  <tr>
  <td width='90%'>
  <div class='ui_label'>
    <a href="http://wiki.apache.org/spamassassin/DateRev">DateRev</a>
    to display (UTC timezone):</div><input
            type='textfield' name='daterev' value="!daterev!">
    <br/>
  <div class='ui_label'>
    (Select a recent nightly mass-check by date:
    <a href='!daterev=last-night!'>last-night</a>,
    <a href='!daterev=today!'>today</a>, or
    enter 'YYYYMMDD' in the DateRev text field for a specific date;
    or <a href='!daterev=last-preflight!'>last-preflight</a> for
    the most recent 'preflight' mass-check.)
  </div>
  </td>
  <td width='10%'><div align='right' class='ui_label'>
    <a href="!shortdatelist!">(Nearby&nbsp;List)</a><br/>
    <a href="!longdatelist!">(Full&nbsp;List)</a><br/>
  </div></td>
  </tr>
  </table>

    <br/>

    <h4> Which Rules?</h4>
  <div class='ui_label'>
    Show only these rules (space separated, or regexp with '/' prefix):<br/>
  </div>
    <input type='textfield' size='60' name='rule' value="!rule!"><br/>
    <br/>
  <div class='ui_label'>
    Show only rules from files whose paths contain this string:<br/>
  </div>
    <input type='textfield' size='60' name='srcpath' value="!srcpath!"><br/>
    <br/>
    <input type='checkbox' name='s_detail' id='s_detail' !s_detail!><label
        for='s_detail' class='ui_label'>Display full details: message age in weeks, by contributor, as score-map, overlaps with other rules, freshness graphs
        </label><br/>
    <br/>

<p>
  <div class='ui_label'>
    Show only rules from files modified in the
    <a href='!mtime=1!'>last day</a>, <a href='!mtime=7!'>last week</a>
  </div>
</p>

    <div align='right'><input type='submit' name='g' value="Change"></div>
  </form>
  </div>

  };

  my @drs = ();
  {
    my $origdr = $self->{daterev} || $self->{daterevs}->[-1];
    $origdr =~ /^(\d+)[\/-]/;
    my $date = $1;

    # include *just* the current day
    my $dr_after = $date;
    my $dr_before = $date;

    # unless 'shortdatelist' is set; in that case, +/- 2 days
    if ($self->{s_shortdatelist}) {
      $dr_after = date_offset($date, -2);
      $dr_before = date_offset($date, 2);
    }

    foreach my $dr (@{$self->{daterevs}}) {
      next unless ($dr =~ /^(\d+)[\/-]/);
      my $date = $1;

      next unless ($date >= $dr_after);
      next unless ($date <= $dr_before);
      push @drs, $dr;
    }
  }

  $tmpl =~ s{!daylinkstable!}{
          $self->get_daterev_html_table(\@drs, 0, 0);
        }ges;

  my $dranchor = "r".$self->{daterev}; $dranchor =~ s/[^A-Za-z0-9]/_/gs;
  my $ldlurl = $self->gen_switch_url("longdatelist", 1)."#".$dranchor;
  my $sdlurl = $self->gen_switch_url("shortdatelist", 1)."#".$dranchor;

  $tmpl =~ s/!longdatelist!/$ldlurl/gs;
  $tmpl =~ s/!shortdatelist!/$sdlurl/gs;
  $tmpl =~ s/!THISURL!/$self->{cgi_url}/gs;
  $tmpl =~ s/!daterev!/$self->{daterev}/gs;
  $tmpl =~ s/!mtime=(.*?)!/
               $self->gen_switch_url("mtime", $1);
       /eg;
  $tmpl =~ s/!daterev=(.*?)!/
               $self->gen_switch_url("daterev", $1);
       /eg;
  $tmpl =~ s/!rule!/$self->{rule}/gs;
  $tmpl =~ s/!srcpath!/$self->{srcpath}/gs;
  foreach my $opt (keys %{$self->{s}}) {
    if ($self->{s}{$opt}) {
      $tmpl =~ s/!s_$opt!/checked /gs;
    } else {
      $tmpl =~ s/!s_$opt!/ /gs;
    }
  }

  print $tmpl;

  if (!$self->{s}{detail}) {

    print qq{

      <p class='intro'> <strong>Instructions</strong>: click
      the rule name to view details of a particular rule. </p>

    };
  }

  # debug: log the chosen sets parameters etc.
  print "<!-- ",
               "{s}{new} = $self->{s}{new}\n",
               "{s}{age} = $self->{s}{age}\n",
               "{s}{all} = $self->{s}{all}\n",
               "{s}{overlap} = $self->{s}{overlap}\n",
               "{s}{scoremap} = $self->{s}{scoremap}\n",
               "{s}{xml} = $self->{s}{xml}\n",
       "-->\n";

  $self->show_all_sets_for_daterev($self->{daterev}, $self->{daterev});

# don't show "graph" link unless only a single rule is being displayed
  if ($self->{s}{detail} && !($self->{rules_all} || $self->{rules_grep}))
  {
    {
      my $graph_on = qq{

        <p><a id="over_time_anchor"></a><a id="overtime" 
          href="}.$self->gen_switch_url("s_g_over_time", "0").qq{#overtime"
          >Hide Graph</a></p>
        <img src="}.$self->gen_switch_url("graph", "over_time").qq{" 
          width='800' height='815' />

      };

      my $graph_off = qq{

        <p><a id="over_time_anchor"></a><a id="overtime" 
          href="}.$self->gen_switch_url("s_g_over_time", "1").qq{#overtime"
          >Show Graph</a></p>

      };

      print qq{

        <h3 class='graph_title'>Graph, hit-rate over time</h3>
        }.($self->{s}{g_over_time} ? $graph_on : $graph_off).qq{

        </ul>

      };
    }

    my @parms = $self->get_params_except(qw(
            rule s_age s_overlap s_all s_detail
          ));
    my $url_back = $self->assemble_url(@parms);

    print qq{

      <div class='ui_label'>
      <p><a href="$url_back">&lt; Back</a> to overview.</p>
      </div>

    };
  }

  print qq{

      <div class='ui_label'>
      <p>Note: the freqs tables are sortable.  Click on the headers to resort them
      by that column.  <a
      href="http://www.kryogenix.org/code/browser/sorttable/">(thanks!)</a></p>
      </div>

  </body></html>

  };

}

sub date_offset {
  my ($yyyymmdd, $offset_days) = @_;
  $yyyymmdd =~ /^(....)(..)(..)$/;
  my $time = timegm(0,0,0,$3,$2-1,$1);
  $time += (24 * 60 * 60) * $offset_days;
  return POSIX::strftime "%Y%m%d", gmtime $time;
}

sub get_all_daterevs {
  my ($self) = @_;

  die "no directory set in automc config for 'html'" unless $AUTOMC_CONF{html};

  return sort map {
      s/^.*\/(\d+)\/(r\d+-\S+)$/$1-$2/; $_;
    } grep { /\/\d+\/r\d+-\S+$/ && -d $_ } (<$AUTOMC_CONF{html}/2*/r*>);
}

sub date_in_direction {
  my ($self, $origdaterev, $dir) = @_;

  my $orig;
  if ($origdaterev && $origdaterev =~ /^(\d+)[\/-](r\d+-\S+)$/) {
    $orig = "$1-$2";
  } else {
    $orig = $self->{daterevs}->[-1];      # the most recent
  }

  if (!$orig) {
    die "no daterev found for $origdaterev, with these options: ".
               join(' ', @{$self->{daterevs}});
  }

  my $cur;
  for my $i (0 .. scalar(@{$self->{daterevs}})) {
    if ($self->{daterevs}->[$i] eq $orig) {
      $cur = $i; last;
    }
  }

  # if it's not in the list, $cur should be the last entry
  if (!defined $cur) { $cur = scalar(@{$self->{daterevs}})-1; }

  my $new;
  if ($dir < 0) {
    if ($cur+$dir >= 0) {
      $new = $self->{daterevs}->[$cur+$dir];
    }
  }
  elsif ($dir == 0) {
    $new = $self->{daterevs}->[$cur];
  }
  else {
    if ($cur+$dir <= scalar(@{$self->{daterevs}})-1) {
      $new = $self->{daterevs}->[$cur+$dir];
    }
  }

  if ($new && -d $self->get_datadir_for_daterev($new)) {
    return $new;
  }

  return undef;       # couldn't find one
}

sub get_last_night_daterev {
  my ($self) = @_;

  # don't use a daterev after (now - 12 hours); that's too recent
  # to be "last night", for purposes of rule-update generation.

  my $notafter = POSIX::strftime "%Y%m%d",
        gmtime ((time + DATEREV_ADJ) - (12*60*60));
  return $self->get_daterev_by_date($notafter);
}

sub get_daterev_by_date {
  my ($self, $notafter) = @_;

  foreach my $dr (reverse @{$self->{daterevs}}) {
    my $t = $self->get_daterev_metadata($dr);
    next unless $t;

    next if ($t->{date} + 0 > $notafter);
    return $dr if ($t->{tag} eq 'n');
  }
  return undef;
}

sub show_all_sets_for_daterev {
  my ($self, $path, $strdate) = @_;

  $strdate = "mass-check date/rev: $path";

  $self->{datadir} = $self->get_datadir_for_daterev($path);

  $self->showfreqset('DETAILS', $strdate);

  # special case: we only build this for one set, as it's quite slow
  # to generate
  $self->{s}{scoremap} and $self->showfreqsubset("SCOREMAP.new", $strdate);
  $self->{s}{overlap} and $self->showfreqsubset("OVERLAP.new", $strdate);
}

###########################################################################

sub graph_over_time {
  my ($self) = @_;

  $self->{datadir} = $self->get_datadir_for_daterev($self->{daterev});

  # logs are named e.g.
  # /home/automc/corpus/html/20051028/r328993/LOGS.all-ham-mc-fast.log.gz

  # untaint
  $self->{rule} =~ /([_0-9a-zA-Z]+)/; my $saferule = $1;
  $self->{datadir} =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  # outright block possibly-hostile stuff here:
  # no "../" path traversal
  die "forbidden: $safedatadir .." if ($safedatadir =~ /\.\./);

  exec ("$PERL_INTERP $automcdir/../rule-hits-over-time ".
        "--cgi --scale_period=200 --rule='$saferule' ".
        "--ignore_older=180 ".
        "$safedatadir/LOGS.*.log.gz")
    or die "exec failed";
}

###########################################################################

sub show_mclog {
  my ($self, $name) = @_;

  print "Content-Type: text/plain\r\n\r\n";

  $self->{datadir} = $self->get_datadir_for_daterev($self->{daterev});

  # logs are named e.g.
  # /home/automc/corpus/html/20051028/r328993/LOGS.all-ham-mc-fast.log.gz

  # untaint
  $name =~ /^([-\.a-zA-Z0-9]+)/; my $safename = $1;
  $self->{rule} =~ /([_0-9a-zA-Z]+)/; my $saferule = $1;
  $self->{datadir} =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  # outright block possibly-hostile stuff here:
  # no "../" path traversal
  die "forbidden: $safedatadir .." if ($safedatadir =~ /\.\./);
  die "forbidden: $safename .." if ($safename =~ /\.\./);

  my $gzfile = "$safedatadir/LOGS.all-$safename.log.gz";
  if (!-f $gzfile) {
    print "cannot open $gzfile\n";
    die "cannot open $gzfile";
  }

  open (GZ, "gunzip -cd < $gzfile |")
        or die "cannot gunzip '$gzfile'";
  while (<GZ>) {
    /^[\.Y]\s+\S+\s+\S+\s+(?:\S*,|)\Q$saferule\E[, ]/ or next;

    # sanitise privacy-relevant stuff
    s/,mid=<.*>,/,mid=<REMOVED_BY_RULEQA>,/gs;

    print;
  }

  close GZ;
  exit;
}

###########################################################################

sub showfreqset {
  my ($self, $type, $strdate) = @_;
  $self->{s}{new} and $self->showfreqsubset("$type.new", $strdate);
  $self->{s}{age} and $self->showfreqsubset("$type.age", $strdate);
  $self->{s}{all} and $self->showfreqsubset("$type.all", $strdate);
}

sub showfreqsubset {
  my ($self, $filename, $strdate) = @_;
  $self->read_freqs_file($filename);

  if ($filename eq 'DETAILS.new') {
    # report which sets we used
    $self->summarise_head($self->{freqs_head}{$filename},
                    $filename, $strdate, $self->{rule});
  }

  $self->get_freqs_for_rule($filename, $strdate, $self->{rule});
}

sub summarise_head {
  my ($self, $head, $filename, $strdate, $rule) = @_;

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
  my ($self, $key) = @_;

  my $file = $self->{datadir}.$key;
  if (!open (IN, "<$file")) {
    warn "cannot read $file";
    return;
  }

  $self->{freqs_head}{$key}=<IN>;
  $self->{freqs_data}{$key} = { };
  $self->{freqs_ordr}{$key} = [ ];
  my $lastrule;

  my $subset_is_user = 0;
  my $subset_is_age = 0;
  if ($file =~ /\.age/) { $subset_is_age = 1; }
  if ($file =~ /\.all/) { $subset_is_user = 1; }

  while (<IN>) {
    if (/(?: \(all messages| results used|OVERALL\%|<mclogmd|was at r\d+)/) {
      $self->{freqs_head}{$key} .= $_;
    }
    elsif (/MSEC/) {
      next;	# just ignored for now
    }
    elsif (/\s+scoremap (.*)$/) {
      $self->{freqs_data}{$key}{$lastrule}{scoremap} .= $_;
    }
    elsif (/\s+overlap (.*)$/) {
      $self->{freqs_data}{$key}{$lastrule}{overlap} .= $_;
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
      if (!exists $self->{freqs_data}{$key}{$lastrule}) {
        push (@{$self->{freqs_ordr}{$key}}, $lastrule);
        $self->{freqs_data}{$key}{$lastrule} = {
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
      push @{$self->{freqs_data}{$key}{$lastrule}{lines}}, $line;
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
  my ($self, $key, $strdate, $ruleslist) = @_;

  my $desc = $FREQS_FILENAMES{$key};
  my $file = $self->{datadir}.$key;

  my $titleplinkold = "$key.$strdate";
  $titleplinkold =~ s/[^A-Za-z0-9]+/_/gs;

  my $titleplinknew = "t".$key;
  $titleplinknew =~ s/[^A-Za-z0-9]+/_/gs;
  $titleplinknew =~ s/^tDETAILS_//;

  my $titleplinkhref = $self->gen_this_url()."#".$titleplinknew;

  my $comment = qq{
  
    <!-- freqs start $key -->
    <h3 class='freqs_title'>$desc</h3>
    <!-- <h4>$strdate</h4> -->

  };

  my $heads = $self->sub_freqs_head_line($self->{freqs_head}{$key});
  my $header_context = $self->extract_freqs_head_info($self->{freqs_head}{$key});

  my $headers_id = $key; $headers_id =~ s/[^A-Za-z0-9]/_/gs;

  $comment .= qq{ 
    
    <div id="$headers_id" class='headdiv' style='display: none'>
    <p class='headclosep' align='right'><a
          href="javascript:hide_header('$headers_id')">[close]</a></p>
    <pre class='head'>$heads</pre>
    </div>

    <div id="txt_$headers_id" class='headdiv' style='display: none'>
    <p class='headclosep' align='right'><a
          href="javascript:hide_header('txt_$headers_id')">[close]</a></p>
    <pre class='head'><<<TEXTS>>></pre>
    </div>

    <br clear="all"/>
    <p class='showfreqslink'><a
      href="javascript:show_header('txt_$headers_id')">(pasteable)</a> <a
      href="javascript:show_header('$headers_id')">(source details)</a>
      <a name='$titleplinknew' href='$titleplinkhref' class='title_permalink'>(#)</a>
      <a name='$titleplinkold'><!-- backwards compat --></a>
    </p>

    <table class='sortable' id='freqs_${headers_id}' class='freqs'>
      <tr class='freqshead'>
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

  if (ref $self->{freqs_ordr}{$key} ne 'ARRAY') {
    print qq(
      <h3 class='freqs_title'>$desc</h3>
      <table><p><i>('$key' not yet available)</i></p></table>
    );
    return;
  }

  if ($self->{rules_all}) {
    push @rules, @{$self->{freqs_ordr}{$key}};
  }
  elsif ($self->{rules_grep} && $ruleslist =~ /^\/(.*)$/) {
    my $regexp = $1;
    foreach my $r (@{$self->{freqs_ordr}{$key}}) {
      next unless ($r =~/${regexp}/i);
      push @rules, $r;
    }
  }

  my $srcpath = $self->{srcpath};
  my $mtime = $self->{mtime};
  my $no_net_rules = (!$self->{daterev_md}->{includes_net});

  if ($srcpath || $mtime) {
    my $rev = $self->get_rev_for_daterev($self->{daterev});
    my $md = $self->get_rule_metadata($rev);
    $md = $md->{rulemds};

    # use Data::Dumper; print Dumper $md;

    if ($srcpath) {    # bug 4984
      @rules = grep {
           # !$md->{$_} or !$md->{$_}->{src} or
          $md->{$_}->{src} and
             ($md->{$_}->{src} =~ /\Q$srcpath\E/);
         } @rules;
    }

    if ($mtime) {      # bug 4985
      my $target = time - ($mtime * 24 * 60 * 60);
      @rules = grep {
           # !$md->{$_} or !$md->{$_}->{srcmtime} or
          $md->{$_}->{srcmtime} and
             ($md->{$_}->{srcmtime} >= $target);
         } @rules;
    }

    if ($no_net_rules) {    # bug 5047
      @rules = grep {
          !$md->{$_}->{tf} or
             ($md->{$_}->{tf} !~ /\bnet\b/);
         } @rules;
    }
  }

  if ($self->{include_embedded_freqs_xml} == 0) {
    $FREQS_LINE_TEMPLATE =~ s/<!--\s+<rule>.*?-->//gs;
  }

  my $texts = '';
  foreach my $rule (@rules) {
    if ($rule && defined $self->{freqs_data}{$key}{$rule}) {
      $comment .= $self->rule_anchor($key,$rule);
      $comment .= $self->output_freqs_data_line($self->{freqs_data}{$key}{$rule},
                \$FREQS_LINE_TEMPLATE,
                $header_context);
      $texts .= $self->output_freqs_data_line($self->{freqs_data}{$key}{$rule},
                \$FREQS_LINE_TEXT_TEMPLATE,
                $header_context);
    }
    else {
      $comment .= $self->rule_anchor($key,$rule);
      $comment .= "
      <tr><td colspan=9>
        (no data found)
      </td></tr>
      ";
      $texts .= "(no data found)\n";
    }
  }

  # insert the text into that template
  $comment =~ s/<<<TEXTS>>>/$texts/gs;
  
  print $comment;
  print "</table>";
}

sub rule_anchor {
  my ($self, $key, $rule) = @_;
  return "<a name='".uri_escape($key."_".$rule)."'></a>".
            "<a name='$rule'></a>";
}

sub sub_freqs_head_line {
  my ($self, $str) = @_;
  $str = "<em><tt>".($str || '')."</tt></em><br/>";
  return $str;
}

sub set_freqs_templates {
  my ($self) = @_;

  $FREQS_LINE_TEMPLATE = qq{

  <tr class='freqsline_promo[% PROMO %]'>
    <td>[% MSECS %]</td>
    <td><a class='ftd'>[% SPAMPC %]<span>[% SPAMPCDETAIL %]</span></a>[% SPAMLOGLINK %]
    <td><a class='ftd'>[% HAMPC %]<span>[% HAMPCDETAIL %]</span></a>[% HAMLOGLINK %]
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

  $FREQS_LINE_TEXT_TEMPLATE =
       qq{[% USE format %][% fmt = format('%7s') %][% fm6 = format('%6s') %]}.
       qq{[% fmt(MSECS) %]  [% fmt(SPAMPC) %]  [% fmt(HAMPC) %]  }.
       qq{[% fm6(SO) %]  [% fm6(RANK) %]  [% fm6(SCORE) %]  }.
       qq{[% NAME %] [% USERNAME %] [% AGE %] }.
       "\n";

  $FREQS_EXTRA_TEMPLATE = qq{

  <tr class='freqsextra'>
    <td colspan=7><pre class='perruleextra'>[% EXTRA %]</pre></td>
  </tr>

  };

  $FREQS_LINE_TEMPLATE =~ s/^\s+//gm;
  $FREQS_EXTRA_TEMPLATE =~ s/^\s+//gm;

  $FREQS_LINE_TEMPLATE =~ s/\s+/ /gs;       # no <pre> stuff in this, shrink it
}

sub extract_freqs_head_info {
  my ($self, $headstr) = @_;
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
  my ($self, $percent, $isspam, $ctx, $line) = @_;

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
  my $count = int ((($percent/100.0) * $outof) + 0.99); # round up
  return qq{
    $count\&nbsp;of\&nbsp;$outof\&nbsp;messages
  };
}

sub create_mclog_link {
  my ($self, $percent, $isspam, $ctx, $line) = @_;

  # optimization: no need to look anything up if it's 0.0000%
  return '' if ($percent == 0.0);

  # also, does nothing unless there's a username
  my $who = $line->{username};
  return '' unless $who;

  my $href = $self->assemble_url(
            "mclog=".(($isspam ? "spam" : "ham")."-".$who),
            "rule=".$line->{name},
            $self->get_params_except(qw( mclog rule s_detail )));

  return qq{

     <br /><a href='$href' class='mcloghref'>[logs]</a>

  };
}

sub output_freqs_data_line {
  my ($self, $obj, $template, $header_context) = @_;

  # normal freqs lines, with optional subselector after rule name
  my $out = '';
  foreach my $line (@{$obj->{lines}}) {

    my $detailurl = '';
    if (!$self->{s}{detail}) {	# not already in "detail" mode
      $detailurl = $self->create_detail_url($line->{name});
    }

    my $score = $line->{score};
    if ($line->{name} =~ /^__/) {
      $score = '(n/a)';
    }

    $self->{ttk}->process($template, {
        RULEDETAIL => $detailurl,
        MSECS => $line->{msecs},
        SPAMPC => $line->{spampc},
        HAMPC => $line->{hampc},
        SPAMPCDETAIL => $self->create_spampc_detail(
                        $line->{spampc}, 1, $header_context, $line),
        HAMPCDETAIL => $self->create_spampc_detail(
                        $line->{hampc}, 0, $header_context, $line),
        SPAMLOGLINK => $self->create_mclog_link(
                        $line->{spampc}, 1, $header_context, $line),
        HAMLOGLINK => $self->create_mclog_link(
                        $line->{hampc}, 0, $header_context, $line),
        SO => $line->{so},
        RANK => $line->{rank},
        SCORE => $score,
        NAME => $line->{name},
        NAMEREF => $self->create_detail_url($line->{name}),
        NAMEREFENCD => uri_escape($self->create_detail_url($line->{name})),
        USERNAME => $line->{username} || '',
        AGE => $line->{age} || '',
        PROMO => $line->{promotable},
    }, \$out) or die $self->{ttk}->error();

    $self->{line_counter}++;
  }

  # add scoremap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{scoremap}) {
    my $ovl = $obj->{scoremap} || '';
    #   scoremap spam: 16  12.11%  777 ****

    $self->{ttk}->process(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $self->{ttk}->error();
  }

  # add overlap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{overlap}) {
    my $ovl = $obj->{overlap} || '';

    $ovl =~ s{^(\s+overlap\s+(?:ham|spam):\s+\d+% )(\S.+?)$}{
        my $str = "$1";
        foreach my $rule (split(' ', $2)) {
          if ($rule =~ /^(?:[a-z]{1,6}|\d+\%)$/) {    # "of", "hits" etc.
            $str .= $rule." ";
          } else {
            $str .= $self->gen_rule_link($rule,$rule)." ";
          }
        }
        $str;
      }gem;

    $self->{ttk}->process(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $ovl,
    }, \$out) or die $self->{ttk}->error();
  }

  return $out;
}

sub create_detail_url {
  my ($self, $rulename) = @_;
  my @parms = (
         $self->get_params_except(qw(
          rule s_age s_overlap s_all s_detail daterev
        )), 
        "daterev=".$self->{daterev}, "rule=".uri_escape($rulename), "s_detail=1",
      );
  return $self->assemble_url(@parms);
}

sub gen_rule_link {
  my ($self, $rule, $linktext) = @_;
  return "<a href='".$self->create_detail_url($rule)."'>$linktext</a>";
}

sub gen_switch_url {
  my ($self, $switch, $newval) = @_;

  my @parms =  $self->get_params_except($switch);
  $newval ||= '';
  if (!defined $switch) { warn "switch '$switch'='$newval' undef value"; }
  # if (!defined $newval) { warn "newval '$switch'='$newval' undef value"; }
  push (@parms, $switch."=".$newval);
  return $self->assemble_url(@parms);
}

sub gen_this_url {
  my ($self) = @_;
  my @parms =  $self->get_params_except("__nonexistent__");
  return $self->assemble_url(@parms);
}

sub get_rev_for_daterev {
  my ($self, $daterev) = @_;
  # '20060120-r370897-b'
  $daterev =~ /-r(\d+)-/ or return undef;
  return $1;
}

sub assemble_url {
  my ($self, @orig) = @_;

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
    # default values that can be omitted
    elsif ($p =~ /^srcpath=$/) { next; }
    elsif ($p =~ /^mtime=$/) { next; }
    # the ones we can put in the path
    elsif ($p =~ /^rule=(.*)$/) { $path{rule} = $1; }
    elsif ($p =~ /^daterev=(.*)$/) { $path{daterev} = $1; }
    elsif ($p =~ /^s_detail=(?:1|on)$/) { $path{s_detail} = 1; }
    # and all the rest
    else { push (@parms, $p); }
  }

  # ensure "/FOO" rule greps are encoded as "%2FFOO"
  $path{rule} =~ s,^/,\%2F,;

  my $url = $self->{cgi_url}.
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
  my ($self) = @_;

  @{$self->{cgi_param_order}} = $self->{q}->param();
  foreach my $k (@{$self->{cgi_param_order}}) {
    next unless defined ($k);
    my $v = $self->{q}->param($k);
    if (!defined $v) { $v = ''; }
    $self->{cgi_params}{$k} = "$k=".uri_escape($v);
  }
}

sub add_cgi_path_param {
  my ($self, $k, $v) = @_;
  if (!defined $self->{cgi_params}{$k}) {
    $self->{cgi_params}{$k} = "$k=$v";
    push (@{$self->{cgi_param_order}}, $k);
  }
  $self->{q}->param(-name=>$k, -value=>$v);
}

sub get_params_except {
  my ($self, @excepts) = @_;

  my @str = ();
  foreach my $p (@{$self->{cgi_param_order}}) {
    foreach my $skip (@excepts) {
      goto nextnext if
            ($skip eq $p || $self->{cgi_params}{$p} =~ /^\Q$skip\E=/);
    }
    push (@str, $self->{cgi_params}{$p});
nextnext: ;
  }
  @str;
}

sub get_datadir_for_daterev {
  my ($self, $npath) = @_;
  $npath =~ s/-/\//;
  return $AUTOMC_CONF{html}."/".$npath."/";
}

sub get_daterev_metadata {
  my ($self, $dr, $ignore_logmds) = @_;

  if ($self->{daterev_metadata}->{$dr}) {
    return $self->{daterev_metadata}->{$dr};
  }

  my $meta = $self->{daterev_metadata}->{$dr} = { };

  $meta->{daterev} = $dr;

  my $dranchor = "r".$dr; $dranchor =~ s/[^A-Za-z0-9]/_/gs;
  $meta->{dranchor} = $dranchor;

  my $fname = $self->get_datadir_for_daterev($dr)."/info.xml";
  my $fastfname = $self->get_datadir_for_daterev($dr)."/fastinfo.xml";

  $dr =~ /^(\d+)-r(\d+)-(\S+)$/;
  my $date = $1;
  my $rev = $2;
  my $tag = $3;

  if (-f $fname && -f $fastfname) {
    eval {
      my $info = XMLin($fname);
      my $fastinfo = XMLin($fastfname);
      # use Data::Dumper; print Dumper $info;

      my $mds_as_text;
      if ($fastinfo->{mclogmds} && !$ignore_logmds) {
        $mds_as_text = $self->get_mds_as_text($fastinfo->{mclogmds});
      }

      my $cdate = $info->{checkin_date};
      $cdate =~ s/T(\S+)\.\d+Z$/ $1/;

      my $drtitle = ($info->{msg} ? $info->{msg} : '');
      $drtitle =~ s/[\"\'\&\>\<]/ /gs;
      $drtitle =~ s/\s+/ /gs;
      $drtitle =~ s/^(.{0,160}).*$/$1/gs;

      if ($rev ne $fastinfo->{rev}) {
	warn "dr and fastinfo disagree: ($rev ne $fastinfo->{rev})";
      }

      $meta->{rev} = $rev;
      $meta->{cdate} = $cdate;
      $meta->{drtitle} = $drtitle;
      $meta->{mds_as_text} = $mds_as_text || '';
      $meta->{includes_net} = $fastinfo->{includes_net};
      $meta->{date} = $fastinfo->{date};
      $meta->{submitters} = $fastinfo->{submitters};
      $meta->{author} = $info->{author};
      $meta->{tag} = $tag;

      my $type;
      if ($meta->{tag} && $meta->{tag} eq 'b') {
        $type = 'preflight';
      } elsif ($meta->{includes_net}) {
        $type = 'net';
      } else {
        $type = 'nightly';
      }
      $meta->{type} = $type;

    };

    if ($@) {
      warn "daterev info.xml: $@";
    } else {
      return $meta;
    }
  }

  # if that failed, just use the info that can be gleaned from the
  # daterev itself.
  my $drtitle = "(no info)";

  {
      $meta->{rev} = $rev;
      $meta->{cdate} = $date;
      $meta->{drtitle} = '(no info available yet)';
      $meta->{mds_as_text} = "";
      $meta->{includes_net} = 0;
      $meta->{date} = $date;
      $meta->{submitters} = "";
      $meta->{author} = "nobody";
      $meta->{tag} = $tag;
      $meta->{type} = 'preflight';  # default
  }

  return $meta;
}

sub get_mds_as_text {
  my ($self, $mclogmds) = @_;

  # 'mclogmd' => [
  #    {
  #      'daterev' => '20060430/r398298-n',
  #      'mcstartdate' => '20060430T122405Z',
  #      'mtime' => '1146404744',
  #      'rev' => '398298',
  #      'file' => 'ham-cthielen.log',
  #      'fsize' => '3036336'
  #    }, [...]

  # $mds_as_text = XMLout($mclogmds);   # debug, as XML

  # use Data::Dumper; $mds_as_text = Dumper($mclogmds); # debug, as perl data

  my $all = '';
  if (ref $mclogmds && $mclogmds->{mclogmd}) {
    foreach my $f (@{$mclogmds->{mclogmd}}) {
      my $started = $f->{mcstartdate};
      my $subtime = POSIX::strftime "%Y%m%dT%H%M%SZ", gmtime $f->{mtime};

      $all .= qq{
      
        <p> <b>$f->{file}</b>:<br />
            started:&nbsp;$started;<br />
            submitted:&nbsp;$subtime;<br />
            size: $f->{fsize} bytes
        </p>

      };
    }
  }

  my $id = "mclogmds_".($self->{id_counter}++);

  return qq{

    <a href="javascript:show_header('$id')">[+]</a>
    <div id='$id' class='mclogmds' style='display: none'>
      <p class='headclosep' align='right'><a
          href="javascript:hide_header('$id')">[-]</a></p>

      $all
    </div>

  };
}

sub get_daterev_code_description {
  my ($self, $dr, $ignore_logmds) = @_;
  my $meta = $self->get_daterev_metadata($dr, $ignore_logmds);

  return qq{

    <td class="daterevcommittd" width='30%'>
    <span class="daterev_code_description">
      <p>
	<a title="$meta->{author}: $meta->{drtitle} ($meta->{cdate})"
          href="!drhref!"><strong>$meta->{rev}</strong>: $meta->{cdate}</a>
      </p>
      <p><div class='commitmsgdiv'>
	$meta->{author}: $meta->{drtitle}
      </div></p>
    </span>
    </td>

  };
}

sub get_daterev_masscheck_description {
  my ($self, $dr, $ignore_logmds) = @_;
  my $meta = $self->get_daterev_metadata($dr, $ignore_logmds);
  my $net = $meta->{includes_net} ? "[net]" : "";

  my $isvishtml = '';
  my $isvisclass = '';
  if ($self->{daterev} eq $dr) {
    $isvishtml = '<b>(Viewing)</b>';
    $isvisclass = 'mcviewing';
  }

  return qq{

    <td class="daterevtd $isvisclass" width='20%'>
    <span class="daterev_masscheck_description $isvisclass">
      <p>
        <a name="$meta->{dranchor}"
          href="!drhref!"><strong>
            <span class="dr">$dr</span>
          </strong></a> $isvishtml
      </p><p>
        <em><span class="mcsubmitters">$meta->{submitters}</span></em>
        $meta->{mds_as_text}</x>
      </p>
      <!-- <span class="mctype">$meta->{type}</span> -->
      <!-- <span class="mcwasnet">$net</span> -->
      <!-- <span class="mcauthor">$meta->{author}</span> -->
      <!-- <span class="date">$meta->{date}</span> -->
      <!-- tag=$meta->{tag} -->
    </span>
    </td>

  };
}

sub get_daterev_html_table {
  my ($self, $daterev_list, $ignore_logmds, $reverse) = @_;

  my $rows = { };
  foreach my $dr (@{$daterev_list}) {
    next unless $dr;
    my $meta = $self->get_daterev_metadata($dr, $ignore_logmds);

    my $colidx;
    my $type = $meta->{type};
    if ($type eq 'preflight') {
      $colidx = 0;
    } elsif ($type eq 'net') {
      $colidx = 2;
    } else {
      $colidx = 1;
    }

    # use the commit-date, rather than the mass-check date as the row key
    $rows->{$meta->{cdate}} ||= [ ];
    $rows->{$meta->{cdate}}->[$colidx] = $meta;
  }

  my @rowkeys = sort keys %{$rows};
  if ($reverse) { @rowkeys = reverse @rowkeys; }

  my @html = ();
  foreach my $rowdate (@rowkeys) {
    my $row = $rows->{$rowdate};

    my $meta;
    foreach my $col (0 .. 2) {
      if ($row->[$col]) {
	$meta = $row->[$col];
	last;
      }
    }

    next unless $meta;		# no entries in the row

    push @html, qq{

            <tr class='daterevtr'>

      }, $self->gen_daterev_html_commit_td($meta, $ignore_logmds);

    foreach my $col (0 .. 2) {
      $meta = $row->[$col];
      if ($meta) {
        push @html, $self->gen_daterev_html_table_td($meta, $ignore_logmds);
      }
      else {
        push @html, qq{

                <td class='daterevtdempty' width='20%'></td>

          };
      }
    }
    push @html, qq{

            </tr>

      };
  }

  return join '', @html;
}

sub gen_daterev_html_commit_td {
  my ($self, $meta, $ignore_logmds) = @_;

  my $dr = $meta->{daterev};
  my @parms = $self->get_params_except(qw(
          daterev longdatelist shortdatelist
        ));
  my $drhref = $self->assemble_url("daterev=".$dr, @parms);

  my $text = $self->get_daterev_code_description($dr, $ignore_logmds) || '';
  $text =~ s/!drhref!/$drhref/gs;

  return $text;
}

sub gen_daterev_html_table_td {
  my ($self, $meta, $ignore_logmds) = @_;

  my $dr = $meta->{daterev};
  my @parms = $self->get_params_except(qw(
          daterev longdatelist shortdatelist
        ));
  my $drhref = $self->assemble_url("daterev=".$dr, @parms);

  my $text = $self->get_daterev_masscheck_description($dr, $ignore_logmds) || '';
  $text =~ s/!drhref!/$drhref/gs;
  return $text;
}

sub show_daterev_selector_page {
  my ($self) = @_;

  my $title = "Rule QA: all recent mass-check results";
  print $self->show_default_header($title);

  my $max_listings = 300;
  my @drs = @{$self->{daterevs}};
  if (scalar @drs > $max_listings) {
    splice @drs, 0, -$max_listings;
  }

  print qq{

    <h3> All Mass-Checks </h3>
    <br/> <a href='#net' name='net'>#</a>

    <div class='updateform'>
      <table style="padding-left: 0px" class='datetable'>
      <tr>
      <th> Commit </th>
      <th> Preflight Mass-Checks </th>
      <th> Nightly Mass-Checks </th>
      <th> Network Mass-Checks </th>
      </tr>

  }.  $self->get_daterev_html_table(\@drs, 1, 1);
}


sub get_rule_metadata {
  my ($self, $rev) = @_;

  if ($self->{rule_metadata}->{$rev}) {
    return $self->{rule_metadata}->{$rev};
  }

  my $meta = $self->{rule_metadata}->{$rev} = { };
  $meta->{rev} = $rev;

  my $fname = $AUTOMC_CONF{html}."/rulemetadata/$rev/rulemetadata.xml";
  if (-f $fname) {
    eval {
      my $md = XMLin($fname);
      # use Data::Dumper; print Dumper $md;
      $meta->{rulemds} = $md->{rulemetadata};

      # '__CTYPE_HTML' => {
      # 'srcmtime' => '1154348696',
      # 'src' => 'rulesrc/core/20_ratware.cf'
      # },

    };

    if ($@) {
      warn "rev rulemetadata.xml: $@";
    } else {
      return $meta;
    }
  }

  # if that failed, just return empty
  $meta->{rulemds} = {};
  return $meta;
}

=cut

to install, add this line to httpd.conf:

  ScriptAlias /ruleqa "/path/to/spamassassin/automc/ruleqa.cgi"


