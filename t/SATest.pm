# common functionality for tests.
# imported into main for ease of use.

package main;

use Cwd;
use Config;
use File::Path;
use File::Copy;
use File::Basename;

# Set up for testing. Exports (as global vars):
# out: $home: $HOME env variable
# out: $cwd: here
# out: $scr: spamassassin script
#
sub sa_t_init {
  my $tname = shift;

  my $perl_path;
  if ($config{PERL_PATH}) {
    $perl_path = $config{PERL_PATH};
  }
  elsif ($^X =~ m|^/|) {
    $perl_path = $^X;
  }
  else {
    $perl_path = $Config{perlpath};
    $perl_path =~ s|/[^/]*$|/$^X|;
  }

  $perl_path .= " -T" if !defined($ENV{'TEST_PERL_TAINT'}) or $ENV{'TEST_PERL_TAINT'} ne 'no';
  $perl_path .= " -w" if !defined($ENV{'TEST_PERL_WARN'})  or $ENV{'TEST_PERL_WARN'}  ne 'no';

  $scr = $ENV{'SCRIPT'};
  $scr ||= "$perl_path ../spamassassin";

  $spamd = $ENV{'SPAMD_SCRIPT'};
  $spamd ||= "$perl_path ../spamd/spamd -x";

  $spamc = $ENV{'SPAMC_SCRIPT'};
  $spamc ||= "../spamd/spamc";

  $spamdport = $ENV{'SPAMD_PORT'};
  $spamdport ||= 48373;		# whatever
  $spamd_cf_args = "-C log/test_rules_copy";

  $scr_cf_args = "-C log/test_rules_copy";
  $scr_pref_args = "-p log/test_default.cf";
  $scr_test_args = "";
  $set_test_prefs = 0;
  $default_cf_lines = "
    bayes_path ./log/user_state/bayes
    auto_whitelist_path ./log/user_state/auto-whitelist
  ";

  (-f "t/test_dir") && chdir("t");        # run from ..
  rmtree ("log");
  mkdir ("log", 0755);
  mkdir ("log/test_rules_copy", 0755);
  for $file (<../rules/*.cf>) {
    $base = basename $file;
    copy ($file, "log/test_rules_copy/$base")
		or warn "cannot copy $file to log/test_rules_copy/$base";
  }

  copy ("../rules/user_prefs.template", "log/test_rules_copy/99_test_default.cf")
	or die "user prefs copy failed";

  open (PREFS, ">>log/test_rules_copy/99_test_default.cf");
  print PREFS $default_cf_lines;
  close PREFS;

  # create an empty .prefs file
  open (PREFS, ">>log/test_default.cf"); close PREFS;

  mkdir("log/user_state",0755);

  $home = $ENV{'HOME'};
  $home ||= $ENV{'WINDIR'} if (defined $ENV{'WINDIR'});
  $cwd = getcwd;

  $ENV{'TEST_DIR'} = $cwd;
  $testname = $tname;
}

sub sa_t_finish {
  # no-op currently
}

sub tstfile {
  my $file = shift;
  open (OUT, ">log/mail.txt") or die;
  print OUT $file; close OUT;
}

sub tstprefs {
  my $lines = shift;

  $set_test_prefs = 1;

  # TODO: should we use -p, or modify the test_rules_copy/99_test_default.cf?
  # for now, I'm taking the -p route, since we have to be able to test
  # the operation of user-prefs in general, itself.

  open (OUT, ">log/tst.cf") or die;
  print OUT $lines; close OUT;
  $scr_pref_args = "-p log/tst.cf";
}

# Run spamassassin. Calls back with the output.
# in $args: arguments to run with
# in $read_sub: callback for the output (should read from <IN>).
# This is called with no args.
#
# out: $sa_exitcode global: exitcode from sitescooper
# ret: undef if sitescooper fails, 1 for exit 0
#
sub sarun {
  my $args = shift;
  my $read_sub = shift;

  rmtree ("log/outputdir.tmp"); # some tests use this
  mkdir ("log/outputdir.tmp", 0755);

  %found = ();
  %found_anti = ();

  if (defined $ENV{'SA_ARGS'}) {
    $args = $ENV{'SA_ARGS'} . " ". $args;
  }
  $args = "$scr_cf_args $scr_pref_args $scr_test_args $args";

  # added fix for Windows tests from Rudif
  my $scrargs = "$scr $args";
  $scrargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);
  print ("\t$scrargs\n");
  system ("$scrargs > log/$testname.${Test::ntest}");
  $sa_exitcode = ($?>>8);
  if ($sa_exitcode != 0) { return undef; }
  &checkfile ("$testname.${Test::ntest}", $read_sub);
  1;
}

sub scrun {
  $spamd_never_started = 1;
  spamcrun (@_);
}

sub spamcrun {
  my $args = shift;
  my $read_sub = shift;

  if (defined $ENV{'SC_ARGS'}) {
    $args = $ENV{'SC_ARGS'} . " ". $args;
  }

  my $spamcargs;
  if($args !~ /\b(?:-p\s*[0-9]+|-o|-U)\b/)
  {
    $spamcargs = "$spamc -p $spamdport $args";
  }
  else
  {
    $spamcargs = "$spamc $args";
  }
  $spamcargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);

  print ("\t$spamcargs\n");
  system ("$spamcargs > log/$testname.out");

  $sa_exitcode = ($?>>8);
  if ($sa_exitcode != 0) { stop_spamd(); return undef; }

  %found = ();
  %found_anti = ();
  &checkfile ("$testname.out", $read_sub);
}

sub spamcrun_background {
  my $args = shift;
  my $read_sub = shift;

  if (defined $ENV{'SC_ARGS'}) {
    $args = $ENV{'SC_ARGS'} . " ". $args;
  }

  my $spamcargs;
  if($args !~ /\b(?:-p\s*[0-9]+|-o|-U)\b/)
  {
    $spamcargs = "$spamc -p $spamdport $args";
  }
  else
  {
    $spamcargs = "$spamc $args";
  }
  $spamcargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);

  print ("\t$spamcargs &\n");
  system ("$spamcargs > log/$testname.bg &") and return 0;

  1;
}

sub sdrun {
  my $sdargs = shift;
  my $args = shift;
  my $read_sub = shift;

  start_spamd ($sdargs);
  spamcrun ($args, $read_sub);
  stop_spamd ();

  1;
}

sub start_spamd {
  my $sdargs = shift;

  return if (defined($spamd_pid) && $spamd_pid > 0);

  rmtree ("log/outputdir.tmp"); # some tests use this
  mkdir ("log/outputdir.tmp", 0755);

  if (defined $ENV{'SD_ARGS'}) {
    $sdargs = $ENV{'SD_ARGS'} . " ". $sdargs;
  }

  my $spamdargs;
  if($sdargs !~ /(?:-C\s*[^-]\S+)/) {
    $sdargs = $spamd_cf_args . " ". $sdargs;
  }
  if($sdargs !~ /(?:-p\s*[0-9]+|-o|--socketpath)/)
  {
    $spamdargs = "$spamd -D -p $spamdport $sdargs";
  }
  else
  {
    $spamdargs = "$spamd -D $sdargs";
  }
  $spamdargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);

  if ($set_test_prefs) {
    warn "oops! SATest.pm: a test prefs file was created, but spamd isn't reading it\n";
  }

  print ("\t$spamdargs > log/$testname.spamd 2>&1 &\n");
  system ("$spamdargs > log/$testname.spamd 2>&1 &");

  # now find the PID
  $spamd_pid = 0;
  my $retries = 20;
  while ($spamd_pid <= 0) {
    my $spamdlog = '';

    if (open (IN, "<log/$testname.spamd")) {
      while (<IN>) {
	/Address already in use/ and $retries = 0;
	/server pid: (\d+)/ and $spamd_pid = $1;
	$spamdlog .= $_;
      }
      close IN;
      last if ($spamd_pid);
    }

    sleep 2;
    if ($retries-- <= 0) {
      warn "spamd start failed: log: $spamdlog";
      warn "\n\nMaybe you need to kill a running spamd process?\n\n";
      return 0;
    }
  }

  1;
}

sub stop_spamd {
  return 0 if defined($spamd_never_started);
  return 0 if defined($spamd_already_killed);

  $spamd_pid ||= 0;
  if ( $spamd_pid <= 1) {
    print ("Invalid spamd pid: $spamd_pid. Spamd not started/crashed?\n");
    return 0;
  } else {
    my $killed = kill (15, $spamd_pid);
    print ("Killed $killed spamd instances\n");

    # wait for it to exit, before returning.
    for my $waitfor (0 .. 5) {
      if (kill (0, $spamd_pid) == 0) { last; }
      print ("Waiting for spamd at pid $spamd_pid to exit...\n");
      sleep 1;
    }

    $spamd_pid = 0;
    undef $spamd_never_started;
    $spamd_already_killed = 1;
    return $killed;
  }
}

# ---------------------------------------------------------------------------

sub checkfile {
  my $filename = shift;
  my $read_sub = shift;

  # print "Checking $filename\n";
  if (!open (IN, "< log/$filename")) {
    warn "cannot open log/$filename"; return undef;
  }
  &$read_sub();
  close IN;
}

# ---------------------------------------------------------------------------

sub pattern_to_re {
  my $pat = shift;
  $pat = quotemeta($pat);

  # make whitespace irrelevant; match any amount as long as the
  # non-whitespace chars are OK.
  $pat =~ s/\\\s/\\s\*/gs;
  $pat;
}

# ---------------------------------------------------------------------------

sub patterns_run_cb {
  local ($_);
  my $string = shift;

  if (defined $string) {
    $_ = $string;
  } else {
    $_ = join ('', <IN>);
  }

  # create default names == the pattern itself, if not specified
  foreach my $pat (keys %patterns) {
    if ($patterns{$pat} eq '') {
      $patterns{$pat} = $pat;
    }
  }

  foreach my $pat (sort keys %patterns) {
    my $safe = pattern_to_re ($pat);
    # print "JMD $patterns{$pat}\n";
    if ($_ =~ /${safe}/s) {
      $found{$patterns{$pat}}++;
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $safe = pattern_to_re ($pat);
    # print "JMD $patterns{$pat}\n";
    if ($_ =~ /${safe}/s) {
      $found_anti{$anti_patterns{$pat}}++;
    }
  }
}

sub ok_all_patterns {
  foreach my $pat (sort keys %patterns) {
    my $type = $patterns{$pat};
    print "\tChecking $type\n";
    if (defined $found{$type}) {
      ok ($found{$type} == 1) or warn "Found more than once: $type\n";
    } else {
      warn "\tNot found: $type = $pat\n";
      ok (0);                     # keep the right # of tests
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type\n";
    if (defined $found_anti{$type}) {
      warn "\tFound anti-pattern: $type = $pat\n";
      ok (0);
    }
    else
    {
      ok (1);
    }
  }
}

sub skip_all_patterns {
  my $skip = shift;
  foreach my $pat (sort keys %patterns) {
    my $type = $patterns{$pat};
    print "\tChecking $type\n";
    if (defined $found{$type}) {
      skip ($skip, $found{$type} == 1) or warn "Found more than once: $type\n";
      warn "\tThis test should have been skipped: $skip\n" if $skip;
    } else {
      if ($skip) {
        warn "\tTest skipped: $skip\n";
      } else {
        warn "\tNot found: $type = $pat\n";
      }
      skip ($skip, 0);                     # keep the right # of tests
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type\n";
    if (defined $found_anti{$type}) {
      warn "\tFound anti-pattern: $type = $pat\n";
      skip ($skip, 0);
    }
    else
    {
      skip ($skip, 1);
    }
  }
}

sub clear_pattern_counters {
  %found = ();
  %found_anti = ();
}

1;
