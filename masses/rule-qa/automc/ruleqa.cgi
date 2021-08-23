#!/usr/bin/perl
my $automcdir = "/usr/local/spamassassin/automc/svn/masses/rule-qa/automc";

###!/usr/bin/perl
##my $automcdir = "/home/jm/ftp/spamassassin/masses/rule-qa/automc";

use strict;
use warnings;

my $PERL_INTERP = $^X;

our %FREQS_FILENAMES = (
    'DETAILS.age' => 'set 0, broken down by message age in weeks',
    'DETAILS.all' => 'set 0, broken down by contributor',
    'DETAILS.new' => 'set 0, in aggregate',
    'NET.age' => 'set 1 (network), by message age in weeks',
    'NET.all' => 'set 1 (network), by contributor',
    'NET.new' => 'set 1 (network), in aggregate',
    'SCOREMAP.new' => 'set 0, score-map',
    'OVERLAP.new' => 'set 0, overlaps between rules',
);

my $refresh_cache = ($ARGV[0] and $ARGV[0] eq '-refresh');

my $self = Mail::SpamAssassin::CGI::RuleQaApp->new();
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
use Date::Manip;
use URI::Escape;
use Time::Local;
use POSIX qw();
use Storable qw(nfreeze thaw);
use Compress::LZ4 qw(compress decompress);

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

  $self->{id_counter} = 0;
  $self->{include_embedded_freqs_xml} = 1;
  $self->{cgi_param_order} = [ ];
  $self->{cgi_params} = { };
  $self->{now} = time();

  bless ($self, $class);

  # some global configuration
  $self->set_freqs_templates();
  $self->read_automc_global_conf();

  die "no directory set in automc config for 'html'" unless $AUTOMC_CONF{html};
  $self->{cachefile} = "$AUTOMC_CONF{html}/ruleqa.scache";

  $self->{scache_keep_time} = defined $AUTOMC_CONF{scache_keep_time} ?
    $AUTOMC_CONF{scache_keep_time} : 60*60*24*14; # default 2 weeks

  if ($refresh_cache) {
    $self->refresh_cache();
    exit;
  }

  $self->read_cache();
  $self->precache_params();
  return $self;
}

# ---------------------------------------------------------------------------

sub read_automc_global_conf {
  my ($self) = @_;

  open (CF, "<$automcdir/config") or return;
  while(<CF>) { /^(?!#)(\S+)=(\S+)/ and $AUTOMC_CONF{$1} = $2; }
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

  if ($self->{url_abs} =~ m,^/(?:20\d|last-net|last-preflight|last-night|\d+-days-ago|today),) {
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
  $self->{s}{corpus} = $self->get_url_switch('s_corpus', 0);

  # "?q=FOO" is a shortcut for "?rule=FOO&s_detail=1"; good for shortcuts
  my $q = $self->{q}->param("q");
  if ($q) {
    $self->add_cgi_param("rule", $q);
    $self->add_cgi_param("s_detail", 1);
    $self->{s}{detail} = 1;
  }

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

  $self->{daterevs} = $self->{cached}->{daterevs};

  # sanitise daterev string
  if (defined $self->{daterev}) {

    # all of these ignore "b" preflight mass-checks, btw
    if ($self->{daterev} eq 'last-night') {
      $self->{daterev} = $self->get_daterev_for_days_ago(1);
      $self->{q}->param('daterev', $self->{daterev});  # make it absolute
    }
    elsif ($self->{daterev} =~ /^(\d+)-days-ago$/) {
      $self->{daterev} = $self->get_daterev_for_days_ago($1);
      $self->{q}->param('daterev', $self->{daterev});
    }
    elsif ($self->{daterev} eq 'last-preflight') {
      $self->{daterev} = undef;
    }
    elsif ($self->{daterev} eq 'today') {
      $self->{daterev} = $self->get_daterev_by_date(
            POSIX::strftime "%Y%m%d", gmtime (($self->{now} + DATEREV_ADJ)));
      $self->{q}->param('daterev', $self->{daterev});
    }
    elsif ($self->{daterev} eq 'last-net') {
      $self->{daterev} = $self->get_last_net_daterev();
      $self->{q}->param('daterev', $self->{daterev});
    }
    elsif ($self->{daterev} =~ /^(20\d\d[01]\d\d\d)$/) {
      # a date
      $self->{daterev} = $self->get_daterev_by_date($1);
      $self->{q}->param('daterev', $self->{daterev});
    }
    elsif ($self->{daterev} =~ /(\d+)[\/-](r\d+)-(\S+)/ && $2) {
      $self->{daterev} = "$1-$2-$3";
    } else {
      # default: last-night's
      $self->{daterev} = $self->get_daterev_for_days_ago(1);
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
  $self->{rule} =~ s/[^_0-9a-zA-Z\/]//gs; # Sanitize
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
  $self->{srcpath} =~ s/[^.,_0-9a-zA-Z\/-]//gs; # Sanitize
  $self->{mtime} = $self->{q}->param('mtime') || '';
  $self->{mtime} =~ s/[^0-9]//gs; # Sanitize

  $self->{freqs}{head} = { };
  $self->{freqs}{data} = { };
  $self->{freqs}{ordr} = { };
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
    $self->show_default_view();
  }
}

# ---------------------------------------------------------------------------

sub show_default_header {
  my ($self, $title) = @_;

  # replaced with use of main, off-zone host:
  # <!-- <link href="/ruleqa.css" rel="stylesheet" type="text/css"> <script src="https://ruleqa.spamassassin.org/sorttable.js"></script> --> 

  my $hdr = q{<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
                    "https://www.w3.org/TR/html4/strict.dtd">
  <html xmlns="https://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head><meta http-equiv="Content-type" content="text/html; charset=utf-8">
  <link rel="icon" href="https://spamassassin.apache.org/images/favicon.ico">
  <title>}.$title.q{: SpamAssassin Rule QA</title>

  <link href="https://ruleqa.spamassassin.org/ruleqa.css" rel="stylesheet" type="text/css">
  <script src="https://ruleqa.spamassassin.org/sorttable.js"></script>

  <script type="text/javascript"><!--

    function hide_header(id) {document.getElementById(id).style.display="none";}
    function show_header(id) {document.getElementById(id).style.display="block";}

    //-->
  </script>

  </head><body>

        <table width="100%"> <tr> <td valign=top>
          <h1>SpamAssassin Rule QA</h1>
        </td> <td valign=top>
          <p align="right">
            <a href="https://wiki.apache.org/spamassassin/RuleQaApp">help</a>
          </p>
        </td> </tr> </table>

  };
  #<br> <a href="https://bbmass.spamassassin.org:8011/">preflight mass-check progress</a>
  return $hdr;
}

sub show_default_view {
  my ($self) = @_;

  my $title;
  if ($self->{s}{detail}) {
    $title = "Details for $self->{nicerule} in mass-check $self->{daterev}";
  } else {
    $title = "Overview of all rules in mass-check $self->{daterev}";
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

        <tr>
        <td colspan="4">
        <div class='ui_label'>
          List <a href="/">just current daterev</a> /
          <a href="!shortdatelist!">all daterevs within 2 days</a> /
          <a href="!longdatelist!">most recent 1000</a> /
          <a href="!fulldatelist!">full list</a>
        </div>
        </td>
        </tr>

        !daylinkstable!

    </table>

  <table width='100%'>
  <tr>
  <td width='100%'>
  <div class='ui_label'>
    Or, <a href="https://wiki.apache.org/spamassassin/DateRev">DateRev</a>
    to display: <input type='textfield' name='daterev' value="!daterev!">
  </div>
  <div class='ui_label'>
    Or, select a recent nightly mass-check by date by entering
    'YYYYMMDD' in the DateRev text field for a specific date,
    or <a href='!daterev=last-night!'>last night's nightly run</a>,
    <a href='!daterev=today!'>today's nightly run</a>,
    <a href='!daterev=last-net!'>the most recent --net run</a>, or
    <a href='!daterev=last-preflight!'>the most recent 'preflight' mass-check</a>.
  </div>
  </td>
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
    Show only rules from source files whose paths contain this string:<br/>
  </div>
    <input type='textfield' size='60' name='srcpath' value="!srcpath!"><br/>
    <br/>

    <!-- <input type='checkbox' name='s_detail' id='s_detail' !s_detail!><label
        for='s_detail' class='ui_label'>Display full details: message age in weeks, by contributor, as score-map, overlaps with other rules, freshness graphs
        </label><br/>
    <br/> -->

<p>
  <div class='ui_label'>
    Show only rules from files modified in the
    <a href='!mtime=1!'>last day</a>,
    <a href='!mtime=2!'>2</a>,
    <a href='!mtime=3!'>3</a>,
    <a href='!mtime=7!'>last week</a>
  </div>
</p>

    <div align='right'><input type='submit' name='g' value="Change"></div>
  </form>
  </div>

  };

  my @drs = ();
  {
    my $origdr = $self->{daterev} || $self->{daterevs}->[-1];
    $origdr =~ /^(\d+)[\/-](\S+)[\/-]/;
    my $date = $1;
    my $rev = $2;

    my $dr_after = date_offset($date, -2);
    my $dr_before = date_offset($date, 2);

    my $origidx;
    foreach my $dr (@{$self->{daterevs}}) {
      next unless ($dr =~ /^(\d+)[\/-]/);
      my $date = $1;

      next unless ($date >= $dr_after);
      next unless ($date <= $dr_before);
      push @drs, $dr;

      if ($dr eq $origdr) {
        $origidx = scalar @drs - 1;
      }
    }

    # if we're doing the default UI -- ie. looking at a mass-check --
    # cut it down to just a couple around it, for brevity
    if (!$self->{s_shortdatelist} && defined($origidx)) {
      my $i = $origidx;
      while ($i < @drs-1 && $drs[$i] =~ /^${date}-${rev}-/) { $i++; }
      my $nextrev = $drs[$i]; $nextrev =~ s/-[a-z]$//;
      while ($i < @drs-1 && $drs[$i] =~ /^${nextrev}-/) { $i++; }
      if ($i < @drs-1) { splice @drs, $i; }

      $i = $origidx;
      while ($i > 0 && $drs[$i] =~ /^${date}-${rev}-/) { $i--; }
      my $prevrev = $drs[$i]; $prevrev =~ s/-[a-z]$//;
      while ($i > 0 && $drs[$i] =~ /^${prevrev}-/) { $i--; }
      if ($i > 0) { splice @drs, 0, $i+1; }
    }
  }

  $tmpl =~ s{!daylinkstable!}{
          $self->get_daterev_html_table(\@drs, 0, 0);
        }ges;

  my $dranchor = "r".$self->{daterev}; $dranchor =~ s/[^A-Za-z0-9]/_/gs;
  my $sdlurl = $self->gen_toplevel_url("shortdatelist", 1)."#".$dranchor;
  my $ldlurl = $self->gen_toplevel_url("longdatelist", 1)."#".$dranchor;
  my $fdlurl = $self->gen_toplevel_url("longdatelist", 1).'&perpage=999999#'.$dranchor;

  $tmpl =~ s/!longdatelist!/$ldlurl/gs;
  $tmpl =~ s/!fulldatelist!/$fdlurl/gs;
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
  if (0) {
    print "<!-- ",
               "{s}{new} = $self->{s}{new}\n",
               "{s}{age} = $self->{s}{age}\n",
               "{s}{all} = $self->{s}{all}\n",
               "{s}{overlap} = $self->{s}{overlap}\n",
               "{s}{scoremap} = $self->{s}{scoremap}\n",
               "{s}{xml} = $self->{s}{xml}\n",
       "-->\n";
  }

  $|=1;                # turn off buffering from now on

  my $single_rule_displayed = ($self->{s}{detail} && !($self->{rules_all} || $self->{rules_grep}));

  # only display code if it's a single rule page
  if ($single_rule_displayed) {
    my $rev = $self->get_rev_for_daterev($self->{daterev});
    my $md = $self->get_rule_metadata($rev);
    my $src = eval { $md->{rulemds}->{$self->{rule}}->{src} } || '(not found)';
    my $srchref = "https://svn.apache.org/viewvc/spamassassin/trunk/$src?revision=$rev\&view=markup";

    my $lastmod = '(unknown)';
    if (defined $md->{rulemds}->{$self->{rule}}->{srcmtime}) {
      $lastmod = eval {
        POSIX::strftime "%Y-%m-%d %H:%M:%S UTC", gmtime $md->{rulemds}->{$self->{rule}}->{srcmtime}
      } || '(unknown)';
    }

    my $tflags = eval {
          $md->{rulemds}->{$self->{rule}}->{tf}
        } || '';

    # a missing string is now represented as {}, annoyingly
    if (ref $tflags =~ /HASH/ || $tflags =~ /^HASH/) { $tflags = ''; }

    $tflags = ($tflags =~ /\S/) ? ", tflags $tflags" : "";

    my $plinkhref = $self->gen_this_url()."#rulemetadata";

    print qq{
      <p class="srcinfo">
        Detailed results for rule
        <a id="rulemetadata"></a><a href="$plinkhref"><b>$self->{rule}</b></a>,
        from source file <a href="$srchref">$src</a>$tflags.
        Source file was last modified on $lastmod.
      </p>
    };
  }

  $self->show_all_sets_for_daterev($self->{daterev}, $self->{daterev});

  # don't show "graph" link unless only a single rule is being displayed
  if ($single_rule_displayed) {
    my $graph_on = qq{

      <p><a id="over_time_anchor"></a><a id="overtime" 
        href="}.$self->gen_switch_url("s_g_over_time", "0").qq{#overtime"
        >Hide graph</a></p>
      <img src="}.$self->gen_switch_url("graph", "over_time").qq{" 
        width='800' height='815' />

    };

    my $graph_off = qq{

      <p><a id="over_time_anchor"></a><a id="overtime" 
        href="}.$self->gen_switch_url("s_g_over_time", "1").qq{#overtime"
        >Show graph</a></p>

    };

    print qq{

      <h3 class='graph_title'>Graph, hit-rate over time</h3>
      }.($self->{s}{g_over_time} ? $graph_on : $graph_off).qq{

      </ul>

    };
    my $corpus_on = qq{

      <p><a id="corpus_anchor"></a><a id="corpus" 
        href="}.$self->gen_switch_url("s_corpus", "0").qq{#corpus"
        >Hide report</a></p>
	<table>
	  <tr class='freqsextra'>
	    <td><pre class='perruleextra'>}.read_corpus_file().qq{</pre></td>
	  </tr>
	<table>

    };

    my $corpus_off = qq{

      <p><a id="corpus_anchor"></a><a id="corpus" 
        href="}.$self->gen_switch_url("s_corpus", "1").qq{#corpus"
        >Show report</a></p>

    };

    print qq{

      <h3 class='corpus_title'>Corpus quality</h3>
      }.($self->{s}{corpus} ? $corpus_on : $corpus_off).qq{

      </ul>

    };

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
      href="https://www.kryogenix.org/code/browser/sorttable/">(thanks!)</a></p>
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
    if (defined $self->{daterevs}->[$i] && $self->{daterevs}->[$i] eq $orig) {
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

sub get_daterev_for_days_ago {
  my ($self, $days) = @_;

  # don't use a daterev after (now - 12 hours); that's too recent
  # to be "last night", for purposes of rule-update generation.

  my $notafter = POSIX::strftime "%Y%m%d",
        gmtime ((($self->{now} + DATEREV_ADJ) + (12*60*60)) - (24*60*60*$days));
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

sub get_last_net_daterev {
  my ($self) = @_;

  foreach my $dr (reverse @{$self->{daterevs}}) {
    my $t = $self->get_daterev_metadata($dr);
    next unless $t;
    return $dr if ($t->{includes_net});
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
  # .../20051028/r328993-n/LOGS.all-ham-mc-fast-20051028-r328993-n.log.gz

  # untaint
  $name =~ /^([-\.a-zA-Z0-9]+)/; my $safename = $1;
  $self->{rule} =~ /([_0-9a-zA-Z]+)/; my $saferule = $1;
  $self->{datadir} =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  # logs now include the daterev, too
  $self->{daterev} =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedaterev = $1;
  $safedaterev =~ s/\//-/gs;
  $safedaterev =~ s/^\d+-//; # no date in logfile
  $safedaterev =~ s/-n$//;

  # outright block possibly-hostile stuff here:
  # no "../" path traversal
  die "forbidden: $safedatadir .." if ($safedatadir =~ /\.\./);
  die "forbidden: $safedaterev .." if ($safedaterev =~ /\.\./);
  die "forbidden: $safename .." if ($safename =~ /\.\./);

  my $gzfile = "$safedatadir/LOGS.all-$safename.$safedaterev.log.gz";
  if (!-f $gzfile) {
    print "cannot open $gzfile\n";
    die "cannot open $gzfile";
  }

  my $lines = 0;
  open (GZ, "pigz -cd < $gzfile | grep -F '$saferule' |") or die "cannot gunzip '$gzfile'";
  while (<GZ>) {
    /^[\.Y]\s+\S+\s+\S+\s+(?:\S*,|)\Q$saferule\E[, ]/ or next;

    # sanitise privacy-relevant stuff
    s/,mid=<.*>,/,mid=<REMOVED_BY_RULEQA>,/gs;

    print;
    last if ++$lines >= 100;
  }

  close GZ;
  exit;
}

###########################################################################

sub read_corpus_file {
  return ''; # THERE IS NO CORPUS.all FILE GENERATED ATM

  $self->{datadir} = $self->get_datadir_for_daterev($self->{daterev});
  $self->{datadir} =~ /([-\.\,_0-9a-zA-Z\/]+)/; my $safedatadir = $1;

  # outright block possibly-hostile stuff here:
  # no "../" path traversal
  die "forbidden: $safedatadir .." if ($safedatadir =~ /\.\./);

  open IN, "<$safedatadir/CORPUS.all" or warn "cannot read $safedatadir/CORPUS.all";
  my $text = join('', <IN>);
  close IN;
  return $text;
}

###########################################################################

sub showfreqset {
  my ($self, $type, $strdate) = @_;
  $self->{s}{new} and $self->showfreqsubset("$type.new", $strdate);
  $self->{s}{all} and $self->showfreqsubset("$type.all", $strdate);
  $self->{s}{age} and $self->showfreqsubset("$type.age", $strdate);
}

sub showfreqsubset {
  my ($self, $filename, $strdate) = @_;
  $self->read_freqs_file($filename);

  if ($filename eq 'DETAILS.new') {
    # report which sets we used
    $self->summarise_head($self->{freqs}{head}{$filename},
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
    s/^ham-//; s/\.r[0-9]+\.log$//;
  } @mcfiles;

  my $who = join(', ', @mcfiles);

  print qq{

    <!-- <em>(Using mass-check data from: $who)</em> -->

  };
}

sub read_freqs_file {
  my ($self, $key, $refresh) = @_;

  $refresh ||= 0;
  my $file = $self->{datadir}.$key;

  # storable cache file
  my $scache = "$file.scache";

  if (!-f $file) {
    # try gz if not found
    if (-f "$file.gz") {
      $file = "$file.gz";
    } else {
      warn "missing file $file";
    }
  }

  if (-f $scache) {
    # is fresh?
    if (mtime($scache) >= mtime($file)) {
      return if $refresh; # just -refresh
      eval {
        $self->{freqs} = thaw(decompress(readfile($scache)));
      };
      if ($@ || !defined $self->{freqs}) {
        warn "cache retrieve failed $scache: $@ $!";
        # remove bad file
        unlink($scache);
      }
      else {
        return;
      }
    }
    else {
      # remove stale cache
      unlink($scache);
    }
  }

  if ($file =~ /\.gz$/) {
    $file =~ s/'//gs;
    if (!open (IN, "pigz -cd < '$file' |")) {
      warn "cannot read $file";
      return;
    }
  }
  elsif (!open (IN, "<$file")) {
    warn "cannot read $file";
  }

  $self->{freqs}{head}{$key}=<IN>;
  $self->{freqs}{data}{$key} = { };
  $self->{freqs}{ordr}{$key} = [ ];
  my $lastrule;

  my $subset_is_user = 0;
  my $subset_is_age = 0;
  if ($file =~ /\.age/) { $subset_is_age = 1; }
  if ($file =~ /\.all/) { $subset_is_user = 1; }

  while (<IN>) {
    if (/^#/ || / \(all messages/ || /OVERALL%/) {
      $self->{freqs}{head}{$key} .= $_;
    }
    elsif (/^\s*MSEC/) {
      next;	# just ignored for now
    }
    elsif (/^\s*scoremap (.*)$/) {
      $self->{freqs}{data}{$key}{$lastrule}{scoremap} .= $_;
    }
    elsif (/^\s*overlap (.*)$/) {
      $self->{freqs}{data}{$key}{$lastrule}{overlap} .= $_;
    }
    elsif (/ (?:([\+\-])\s+)?(\S+?)(\:\S+)?\s*$/) {
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
      if (!exists $self->{freqs}{data}{$key}{$lastrule}) {
        push (@{$self->{freqs}{ordr}{$key}}, $lastrule);
        $self->{freqs}{data}{$key}{$lastrule} = {
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
      push @{$self->{freqs}{data}{$key}{$lastrule}{lines}}, $line;
    }
    elsif (!/\S/) {
      # silently ignore empty lines
    }
    else {
      warn "warning: unknown freqs line in $file: '$_'";
    }
  }
  close IN;

  if ($refresh && !-f $scache) {
    eval {
      open (OUT, ">$scache.$$") or die "open failed: $@";
      print OUT compress(nfreeze(\%{$self->{freqs}}));
      close OUT;
    };
    if ($@ || !rename("$scache.$$", $scache)) {
      warn "cache store failed $scache: $@";
      unlink("$scache.$$");
    }
  }
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

  my $titleplinkhref = $self->{q}->url(-base=>1).$self->gen_this_url()."#".$titleplinknew;

  my $comment = qq{
  
    <!-- freqs start $key -->
    <h3 class='freqs_title'>$desc</h3>
    <!-- <h4>$strdate</h4> -->

  };

  my $heads = $self->sub_freqs_head_line($self->{freqs}{head}{$key});
  my $header_context = $self->extract_freqs_head_info($self->{freqs}{head}{$key});

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
      <th>S/O</th>
      <th>RANK</th>
      <th>SCORE</th>
      <th>NAME</th>
      <th>WHO/AGE</th>
    </tr>

  };

  $ruleslist ||= '';
  my @rules = split (' ', $ruleslist);

  if (ref $self->{freqs}{ordr}{$key} ne 'ARRAY') {
    print qq(
      <h3 class='freqs_title'>$desc</h3>
      <table><p><i>('$key' not yet available)</i></p></table>
    );
    return;
  }

  if ($self->{rules_all}) {
    push @rules, @{$self->{freqs}{ordr}{$key}};
  }
  elsif ($self->{rules_grep} && $ruleslist =~ /^\/(.*)$/) {
    my $regexp = $1;
    foreach my $r (@{$self->{freqs}{ordr}{$key}}) {
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
          $md->{$_}->{src} and
             ($md->{$_}->{src} =~ /\Q$srcpath\E/);
         } @rules;
    }

    if ($mtime) {      # bug 4985
      my $target = $self->{now} - ($mtime * 24 * 60 * 60);
      @rules = grep {
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

  my $texts = $titleplinkhref." :\n\n".
  	      "  MSECS    SPAM%     HAM%     S/O    RANK   SCORE  NAME   WHO/AGE\n";
             #       0   0.0216   0.0763   0.221    0.52    2.84  X_IP  
  
  foreach my $rule (@rules) {
    if ($rule && defined $self->{freqs}{data}{$key}{$rule}) {
      $comment .= $self->rule_anchor($key,$rule);
      $comment .= $self->output_freqs_data_line($self->{freqs}{data}{$key}{$rule},
                \$FREQS_LINE_TEMPLATE,
                $header_context);
      $texts .= $self->output_freqs_data_line($self->{freqs}{data}{$key}{$rule},
                \$FREQS_LINE_TEXT_TEMPLATE,
                $header_context);
    }
    else {
      $comment .= $self->rule_anchor($key,$rule);
      $comment .= "
      <tr><td colspan=8>
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
    <td><a class='ftd' [% SPAMLOGHREF %]>[% SPAMPC %]<span>[% SPAMPCDETAIL %]</span></a>
    <td><a class='ftd' [% HAMLOGHREF %]>[% HAMPC %]<span>[% HAMPCDETAIL %]</span></a>
    <td>[% SO %]</td>
    <td>[% RANK %]</td>
    <td>[% SCORE %]</td>
    <td style='text-align: left'><a href="[% NAMEREF %]">[% NAME %]</a></td>
    <td>[% USERNAME %][% AGE %][% CORPUSAHREF %]</td>
    <!--
      <rule><test>[% NAME %]</test><promo>[% PROMO %]</promo> <spc>[% SPAMPC %]</spc><hpc>[% HAMPC %]</hpc><so>[% SO %]</so> <detailhref esc='1'>[% NAMEREFENCD %]</detailhref></rule>
    -->
  </tr>

  };

  $FREQS_LINE_TEXT_TEMPLATE =
       qq{[% MSECS %]  [% SPAMPC %]  [% HAMPC %]  }.
       qq{[% SO %]  [% RANK %]  [% SCORE %]  }.
       qq{[% NAME %] [% USERNAME %][% AGE %] }.
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
  # disabled; this info may be pretty useful after all
  ## if ($percent == 0.0) { return qq{ 0\&nbsp;messages }; }

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
  my $count = int ((($percent/100.0) * $outof) + 0.5); # round to nearest int
  return qq{
    $count\&nbsp;of\&nbsp;$outof\&nbsp;messages
  };
}

sub create_mclog_href {
  my ($self, $percent, $isspam, $ctx, $line) = @_;

  # optimization: no need to look anything up if it's 0.0000%
  return '' if ($percent == 0.0);

  # also, does nothing unless there's a username
  my $who = $line->{username};
  return '' unless $who;

  #my $net = ($self->{daterev_md}->{includes_net}) ? '-net' : '';

  my $href = $self->assemble_url(
            "mclog=".(($isspam ? "spam" : "ham")."-$who"),
            "rule=".$line->{name},
           "daterev=".$self->{daterev},
            $self->get_params_except(qw( mclog rule s_detail )));

  return qq{
	href='$href'
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

    my $SPAMPCDETAIL = $self->create_spampc_detail(
                        $line->{spampc}, 1, $header_context, $line);
    my $HAMPCDETAIL = $self->create_spampc_detail(
                        $line->{hampc}, 0, $header_context, $line);
    my $SPAMLOGHREF = $self->create_mclog_href(
                        $line->{spampc}, 1, $header_context, $line);
    my $HAMLOGHREF = $self->create_mclog_href(
                        $line->{hampc}, 0, $header_context, $line);

    $self->process_template($template, {
        RULEDETAIL => $detailurl,
        MSECS =>  $line->{msecs}+0  ? sprintf("%7s", $line->{msecs})  : "      0",
        SPAMPC => $line->{spampc}+0 ? sprintf("%7s", $line->{spampc}) : "      0",
        HAMPC =>  $line->{hampc}+0  ? sprintf("%7s", $line->{hampc})  : "      0",
        SPAMPCDETAIL => $SPAMPCDETAIL,
        HAMPCDETAIL => $HAMPCDETAIL,
        SPAMLOGHREF => $SPAMLOGHREF,
        HAMLOGHREF => $HAMLOGHREF,
        SO => sprintf("%6s", $line->{so}),
        RANK => sprintf("%6s", $line->{rank}),
        SCORE => sprintf("%6s", $score),
        NAME => $line->{name},
        NAMEREF => $self->create_detail_url($line->{name}),
        NAMEREFENCD => uri_escape($self->create_detail_url($line->{name})),
        USERNAME => $line->{username} || '',
        CORPUSAHREF => $self->create_corpus_href($line->{name}, $line->{username}),
        AGE => $line->{age} || '',
        PROMO => $line->{promotable},
    }, \$out);

    $self->{line_counter}++;
  }

  # add scoremap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{scoremap}) {
    my $smap = $obj->{scoremap} || '';
    #   scoremap spam: 16  12.11%  777 ****

    $self->process_template(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $smap,
    }, \$out);

    $self->generate_scoremap_chart($smap, \$out);
  }

  # add overlap using the FREQS_EXTRA_TEMPLATE if it's present
  if ($obj->{overlap}) {
    $self->process_template(\$FREQS_EXTRA_TEMPLATE, {
        EXTRA => $self->format_overlap($obj->{overlap} || '')
    }, \$out);
  }

  return $out;
}

sub generate_scoremap_chart {
  my ($self, $smap, $outref) = @_;

  my %chart;
  foreach my $l (split (/^/m, $smap)) {
    #   scoremap spam: 16  12.11%  777 ****
    $l =~ /^\s*scoremap\s+(\S+):\s+(\S+)\s+(\S+)\%\s+\d+/
            or $$outref .= "chart: failed to parse scoremap line: $l<br>";

    my ($type, $idx, $pc) = ($1,$2,$3);
    next unless $type;

    $chart{$type}{$idx} = $pc;
  }

  my %uniq=();
  my $max_x = 0;
  my $max_y = 0;
  for my $i (keys %{$chart{'spam'}}, keys %{$chart{'ham'}}) {
    next if exists $uniq{$i}; undef $uniq{$i};
    if (($chart{'spam'}{$i}||0) > $max_y) { $max_y = $chart{'spam'}{$i}; }
    if (($chart{'ham'}{$i}||0)  > $max_y) { $max_y = $chart{'ham'}{$i}; }
    if ($i > $max_x) { $max_x = $i; }
  }
  $max_y ||= 0.001;

  # ensure 0 .. $max_x are always set
  foreach my $i (0 .. $max_x) { $uniq{$i} = undef; }

  my @idxes = sort { $a <=> $b } keys %uniq;
  if (!scalar @idxes) {
    $max_x = 1; @idxes = ( 0 );
  }
  my $min_x = $idxes[0];
  
  # normalize to [0,100] and set default to 0
  my @ycoords_s = map { sprintf "%.2f", (100/$max_y) * ($chart{'spam'}{$_}||0) } @idxes;
  my @ycoords_h = map { sprintf "%.2f", (100/$max_y) * ($chart{'ham'}{$_}||0) } @idxes;
  my @xcoords   = map { sprintf "%.2f", (100/($max_x||0.0001)) * $_ } @idxes;

  my $xgrid = (100/($max_x||0.0001)) * 5;
  my $ygrid = (100/($max_y||0.0001)) * 10;

  # https://code.google.com/apis/chart/ , woo
  my $chartsetup = 
      "cht=lxy"             # line chart with x- and y-axis coords
      ."\&amp;chs=400x200"
      ."\&amp;chd=t:".join(",", @xcoords)."|".join(",", @ycoords_h)
                 ."|".join(",", @xcoords)."|".join(",", @ycoords_s)
      ."\&amp;chts=ff0000,18"
      ."\&amp;chdl=Ham|Spam"
      ."\&amp;chco=ff0000,0000ff,00ff00"
      ."\&amp;chg=$xgrid,$ygrid"
      ."\&amp;chxl=0:|$min_x+points|$max_x+points|1:|0\%|$max_y\%"
      ."\&amp;chxt=x,y";

  $$outref .= "<div class='scoremap_chart'>
       <img src='https://chart.apis.google.com/chart?$chartsetup'
         class='scoremap_chart' width='400' height='200' align='right'
       /></div>\n";
}

sub format_overlap {
  my ($self, $ovl) = @_;

  # list the subrules last; they're noisy and typically nonuseful
  my $out_fullrules = '';
  my $out_subrules = '';

  foreach my $line (split(/^/m, $ovl)) {
    my $issubrule = ($line =~ /\d+\%\s+of __/
                    || $line =~ /\(meta rule and subrule\)/);

    $line =~ s{^(\s+overlap\s+(?:ham|spam):\s+\d+% )(\S.+?)$}{
        my $str = "$1";
        foreach my $rule (split(' ', $2)) {
          if ($rule =~ /^(?:[(]?[a-z]{1,6}[)]?|\d+\%[)]?)$/) {    # "of", "hits" etc.
            $str .= $rule." ";
          } else {
            my $post = '';
            $rule =~ s/(\;\s*)$// and $post = $1;
            $str .= $self->gen_rule_link($rule,$rule).$post." ";
          }
        }
        $str;
      }gem;

    if ($issubrule) {
      $out_subrules .= $line;
    } else {
      $out_fullrules .= $line;
    }
  }

  return "OVERLAP WITH FULL RULES:\n".$out_fullrules."\n".
        "OVERLAP WITH SUBRULES:\n".$out_subrules;
}

# get rid of slow, overengineered Template::Toolkit.  This replacement
# is extremely simple-minded, but doesn't call time() on every invocation,
# which makes things just a little bit faster
sub process_template {
  my ($self, $tmplref, $keys, $outref) = @_;
  my $buf = $$tmplref;
  foreach my $k (keys %{$keys}) {
    $buf =~ s/\[\% \Q$k\E \%\]/$keys->{$k}/gs;
  }
  $$outref .= $buf;
}

sub create_detail_url {
  my ($self, $rulename) = @_;

  if (!$self->{create_detail_url_template}) {
    my @parms = (
          $self->get_params_except(qw(
           rule s_age s_overlap s_all s_detail daterev
         )),
         "daterev=".$self->{daterev},
         "s_detail=1",
         "rule=__create_detail_url_template__",
       );
    $self->{create_detail_url_template} = $self->assemble_url(@parms);
  }

  my $ret = $self->{create_detail_url_template};
  $rulename = uri_escape($rulename);
  $ret =~ s/__create_detail_url_template__/${rulename}/gs;
  return $ret;
}

sub create_corpus_href {
  my ($self, $rulename, $username) = @_;

  if (!$self->{s}{detail} || !$username) {	# not already in "detail" mode
    return '';
  }
  my $url = $self->assemble_url(
	    "s_corpus=1",
	    "s_detail=1",
            "rule=".$rulename,
            "daterev=".$self->{daterev},
            $self->get_params_except(qw( mclog rule s_detail s_corpus daterev )))
	    ."#corpus";
  return "&nbsp;<a href='$url' class='mcloghref'>[corpus]</a>";
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
  push (@parms,
        $switch."=".$newval,
        "daterev=".$self->{daterev}
       );
  return $self->assemble_url(@parms);
}

sub gen_this_url {
  my ($self) = @_;
  my @parms =  $self->get_params_except("__nonexistent__");
  return $self->assemble_url(@parms);
}

sub gen_toplevel_url {
  my ($self, $switch, $newval) = @_;

  my @parms =  $self->get_params_except($switch, qw(
              rule s_age s_overlap s_all s_detail daterev
            ));
  $newval ||= '';
  if (!defined $switch) { warn "switch '$switch'='$newval' undef value"; }
  push (@parms, $switch."=".$newval);
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

  # e.g. https://buildbot.spamassassin.org/ruleqa?
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
  # https://ruleqa.spamassassin.org/
  #      20060120-r370897-b/T_PH_SEC/detail

  return $url;
}

sub precache_params {
  my ($self) = @_;

  @{$self->{cgi_param_order}} = $self->{q}->param();
  foreach my $k (@{$self->{cgi_param_order}}) {
    next unless defined ($k);
    next if ($k eq 'q');        # a shortcut, ignore for future refs
    my $v = $self->{q}->param($k);
    if (!defined $v) { $v = ''; }
    $k =~ s/[<>]//gs;
    $v =~ s/[<>]//gs;
    $self->{cgi_params}{$k} = uri_escape($k)."=".uri_escape($v);
  }
}

sub add_cgi_path_param {        # assumes already escaped unless $not_escaped
  my ($self, $k, $v, $not_escaped) = @_;
  $k =~ s/[<>]//gs;
  $v =~ s/[<>]//gs;
  if (!defined $self->{cgi_params}{$k}) {
    push (@{$self->{cgi_param_order}}, $k);
  }
  if ($not_escaped) {
    $self->{cgi_params}{$k} = uri_escape($k)."=".uri_escape($v);
    $self->{q}->param(-name=>$k, -value=>$v);
  } else {
    $self->{cgi_params}{$k} = $k."=".$v;
    $self->{q}->param(-name=>$k, -value=>uri_unescape($v));
  }
}

sub add_cgi_param {     # a variant for unescaped data
  my ($self, $k, $v) = @_;
  return $self->add_cgi_path_param($k, $v, 1);
}

sub get_params_except {
  my ($self, @excepts) = @_;

  my @str = ();
  foreach my $p (@{$self->{cgi_param_order}}) {
    foreach my $skip (@excepts) {
      next unless defined $skip && defined $self->{cgi_params}{$p};
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
  my ($self, $dr) = @_;
  return $self->{cached}->{daterev_metadata}->{$dr} || { };
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
  my ($self, $dr) = @_;
  my $meta = $self->get_daterev_metadata($dr);

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
  my ($self, $dr) = @_;
  my $meta = $self->get_daterev_metadata($dr);
  my $net = $meta->{includes_net} ? "[net]" : "";

  my $isvishtml = '';
  my $isvisclass = '';
  if ($self->{daterev} eq $dr) {
    $isvishtml = '<b>(Viewing)</b>';
    $isvisclass = 'mcviewing';
  }

  my $mds_as_text = '';
  if ($meta->{mclogmds}) {
    $mds_as_text = $self->get_mds_as_text($meta->{mclogmds}) || '';
  }

  my $submitters = $meta->{submitters};
  # remove daterevs, they're superfluous in this table
  $submitters =~ s/\.\d+-r\d+-[a-z]\b//gs;	

  return qq{

    <td class="daterevtd $isvisclass" width='20%'>
    <span class="daterev_masscheck_description $isvisclass">
      <p>
        <a name="$meta->{dranchor}"
          href="!drhref!"><strong>
            <span class="dr">$dr</span>
          </strong></a> $isvishtml
      </p><p>
        <em><span class="mcsubmitters">$submitters</span></em>
        $mds_as_text</x>
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
  my ($self, $daterev_list, $reverse) = @_;

  my $rows = { };
  foreach my $dr (@{$daterev_list}) {
    next unless $dr;
    my $meta = $self->get_daterev_metadata($dr);

    my $colidx;
    my $type = $meta->{type};
    if ($type eq 'preflight') {
      $colidx = 0;
    } elsif ($type eq 'net') {
      $colidx = 2;
    } else {
      $colidx = 1;
    }

    # use the daterev number as the row key
    $rows->{$meta->{daterev}} ||= [ ];
    $rows->{$meta->{daterev}}->[$colidx] = $meta;
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

      }, $self->gen_daterev_html_commit_td($meta);

    foreach my $col (0 .. 2) {
      $meta = $row->[$col];
      if ($meta) {
        push @html, $self->gen_daterev_html_table_td($meta);
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
  my ($self, $meta) = @_;

  my $dr = $meta->{daterev};
  my @parms = $self->get_params_except(qw(
          daterev longdatelist shortdatelist
        ));
  my $drhref = $self->assemble_url("daterev=".$dr, @parms);

  my $text = $self->get_daterev_code_description($dr) || '';
  $text =~ s/!drhref!/$drhref/gs;

  return $text;
}

sub gen_daterev_html_table_td {
  my ($self, $meta) = @_;

  my $dr = $meta->{daterev};
  my @parms = $self->get_params_except(qw(
          daterev longdatelist shortdatelist
        ));
  my $drhref = $self->assemble_url("daterev=".$dr, @parms);

  my $text = $self->get_daterev_masscheck_description($dr) || '';
  $text =~ s/!drhref!/$drhref/gs;
  return $text;
}

sub show_daterev_selector_page {
  my ($self) = @_;

  my $title = "Rule QA: all recent mass-check results";
  print $self->show_default_header($title);

  my $max_listings = $self->{q}->param('perpage') || 1000;	# def. 1000
  my @drs = @{$self->{daterevs}};
  if ($max_listings > 0 && scalar @drs > $max_listings) {
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
      $meta->{rulemds} = parse_rulemetadataxml($fname);
      #use Data::Dumper; print STDERR Dumper $meta->{rulemds};

      # '__CTYPE_HTML' => {
      # 'srcmtime' => '1154348696',
      # 'src' => 'rulesrc/core/20_ratware.cf'
      # },

    };

    if ($@ || !defined $meta->{rulemds}) {
      warn "rev rulemetadata.xml read failed: $@";
    } else {
      return $meta;
    }
  }

  # if that failed, just return empty
  if (1) {
    print "<!-- WARN: Failed to read rule metadata file: $fname -->\n";
  }

  $meta->{rulemds} = {};
  return $meta;
}

# ---------------------------------------------------------------------------

sub read_cache {
  my ($self) = @_;
  if (!-f $self->{cachefile}) {
    warn "missing $self->{cachefile}, run -refresh";
    return;
  }
  eval {
    $self->{cached} = thaw(decompress(readfile($self->{cachefile})));
  };
  if ($@ || !defined $self->{cached}) {
    warn "cannot read $self->{cachefile}: $@ $!";
  }
}

# ---------------------------------------------------------------------------

sub refresh_cache {
  my ($self) = @_;

  $self->{cached} = { };

  # all known date/revision combos.
  @{$self->{cached}->{daterevs}} = $self->get_all_daterevs();

  foreach my $dr (@{$self->{cached}->{daterevs}}) {
    $self->refresh_daterev_metadata($dr);
  }

  eval {
    open (OUT, ">".$self->{cachefile}.".$$") or die "open failed: $@";
    print OUT compress(nfreeze(\%{$self->{cached}}));
    close OUT;
  };
  if ($@ || !rename($self->{cachefile}.".$$", $self->{cachefile})) {
    unlink($self->{cachefile}.".$$");
    die "cannot write $self->{cachefile}: $@";
  }
}

sub refresh_daterev_metadata {
  my ($self, $dr) = @_;

  my $meta = $self->{cached}->{daterev_metadata}->{$dr} = { };
  $meta->{daterev} = $dr;

  my $dranchor = "r".$dr; $dranchor =~ s/[^A-Za-z0-9]/_/gs;
  $meta->{dranchor} = $dranchor;

  $dr =~ /^(\d+)-r(\d+)-(\S+)$/;
  my $date = $1;
  my $rev = $2;
  my $tag = $3;

  my $datadir = $self->get_datadir_for_daterev($dr);
  $self->{datadir} = $datadir;

  # update scache for all freqfiles
  foreach my $f (keys %FREQS_FILENAMES) {
    my $file = -f $datadir.$f ? $datadir.$f :
      -f $datadir."$f.gz" ? $datadir."$f.gz" : undef;
    if (defined $file) {
      if (time - mtime($file) <= $self->{scache_keep_time}) {
        $self->read_freqs_file($f, 1);
      }
      else {
        # remove too old cachefiles
        $file =~ s/\.gz$//;
        unlink("$file.scache");
      }
    }
  }

  my $fname = "$datadir/info.xml";
  my $fastfname = "$datadir/fastinfo.xml";

  if (-f $fname && -f $fastfname) {
    eval {
      my $fastinfo = parse_infoxml($fastfname);
      $meta->{rev} = $rev;
      $meta->{tag} = $tag;
      $meta->{mclogmds} = $fastinfo->{mclogmds};
      $meta->{includes_net} = $fastinfo->{includes_net};
      $meta->{date} = $fastinfo->{date};
      $meta->{submitters} = $fastinfo->{submitters};

      if ($rev ne $fastinfo->{rev}) {
	warn "dr and fastinfo disagree: ($rev ne $fastinfo->{rev})";
      }

      my $type;
      if ($meta->{tag} && $meta->{tag} eq 'b') {
        $type = 'preflight';
      } elsif ($meta->{includes_net}) {
        $type = 'net';
      } else {
        $type = 'nightly';
      }
      $meta->{type} = $type;


      my $info = parse_infoxml($fname);
      # use Data::Dumper; print Dumper $info;
      my $cdate = $info->{checkin_date};
      $cdate =~ s/T(\S+)\.\d+Z$/ $1/;

      my $drtitle = ($info->{msg} ? $info->{msg} : '');
      $drtitle =~ s/[\"\'\&\>\<]/ /gs;
      $drtitle =~ s/\s+/ /gs;
      $drtitle =~ s/^(.{0,160}).*$/$1/gs;

      $meta->{cdate} = $cdate;
      $meta->{drtitle} = $drtitle;
      $meta->{author} = $info->{author};
    };

    if ($@) {
      warn "daterev info.xml: $@";
    }

    return $meta;
  }

  # if that failed, just use the info that can be gleaned from the
  # daterev itself.
  my $drtitle = "(no info)";

  {
      $meta->{rev} = $rev;
      $meta->{cdate} = $date;
      $meta->{drtitle} = '(no info available yet)';
      $meta->{includes_net} = 0;
      $meta->{date} = $date;
      $meta->{submitters} = "";
      $meta->{author} = "nobody";
      $meta->{tag} = $tag;
      $meta->{type} = 'preflight';  # default
  }
}

# return file modification time
sub mtime {
  return (stat $_[0])[9];
}

# slurp'a'file
sub readfile {
  my $file = shift;
  my $str;
  eval {
    open(IN, $file) or die $@;
    { local($/); $str = <IN> }
    close(IN);
  };
  if ($@) {
    warn "read failed $file: $@";
    return undef;
  }
  return $str;
}

# fast simple xml parser, since we know what to expect
sub parse_rulemetadataxml {
  my $file = shift;
  my $xmlstr = readfile($file);
  my $md = {};
  while ($xmlstr =~ m!<rulemetadata>(.*?)</rulemetadata>!gs) {
    my $rmd = $1;
    my %attrs;
    while ($rmd =~ m!<([A-Za-z0-9_]{1,50})>(.*?)</\1>!gs) {
      $attrs{$1} = $2;
    }
    if (defined $attrs{name}) {
      foreach (keys %attrs) {
        next if $_ eq 'name';
        $md->{$attrs{name}}->{$_} = $attrs{$_};
      }
    }
  }
  if (!%$md) {
    warn "xml parse failed $file";
  }
  return $md;
}

sub parse_infoxml {
  my $file = shift;
  my $xmlstr = readfile($file);
  my $opt = {};
  if ($xmlstr =~ m!<opt ([^>]*?)>!s) {
    my $optstr = $1;
    my %attrs;
    while ($optstr =~ m!\b([A-Za-z0-9_]{1,50})="([^"]*)"!gs) {
      $opt->{$1} = $2;
    }
  }
  if (!%$opt) {
    warn "xml parse failed $file";
  }
  return $opt;
}

=cut

to install, add this line to httpd.conf:

  ScriptAlias /ruleqa "/path/to/spamassassin/automc/ruleqa.cgi"


