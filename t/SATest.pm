# common functionality for tests.
# imported into main for ease of use.
package main;

# use strict;
# use warnings;
# use re 'taint';

use Cwd;
use Config;
use File::Basename;
use File::Copy;
use File::Path;
use File::Spec;
use POSIX qw(WIFEXITED WIFSIGNALED WIFSTOPPED WEXITSTATUS WTERMSIG WSTOPSIG);

use vars qw($RUNNING_ON_WINDOWS $SSL_AVAILABLE
            $SKIP_SPAMD_TESTS $SKIP_SPAMC_TESTS $NO_SPAMC_EXE
            $SKIP_SETUID_NOBODY_TESTS $SKIP_DNSBL_TESTS
            $have_inet4 $have_inet6 $spamdhost $spamdport);

BEGIN {
  require Exporter;
  use vars qw(@ISA @EXPORT @EXPORT_OK);
  @ISA = qw(Exporter);

  @EXPORT = qw($have_inet4 $have_inet6 $spamdhost $spamdport);

  # No spamd test in Windows unless env override says user figured out a way
  # If you want to know why these are vars and no constants, read this thread:
  #   <http://www.mail-archive.com/dev%40perl.apache.org/msg05466.html>
  #  -- mss, 2004-01-13
  $RUNNING_ON_WINDOWS = ($^O =~ /^(mswin|dos|os2)/oi);
  $SKIP_SPAMD_TESTS =
        $RUNNING_ON_WINDOWS ||
        ( $ENV{'SPAMD_HOST'} && !($ENV{'SPAMD_HOST'} eq '127.0.0.1' ||
                                  $ENV{'SPAMD_HOST'} eq '::1' ||
                                  $ENV{'SPAMD_HOST'} eq 'localhost') );
  $SKIP_SETUID_NOBODY_TESTS = 0;
  $SKIP_DNSBL_TESTS = 0;

  $have_inet4 = eval {
    require IO::Socket::INET;
    my $sock = IO::Socket::INET->new(LocalAddr => '0.0.0.0', Proto => 'udp');
    $sock->close or die "error closing inet socket: $!"  if $sock;
    $sock ? 1 : undef;
  };

  $have_inet6 = eval {
    require IO::Socket::INET6;
    my $sock = IO::Socket::INET6->new(LocalAddr => '::', Proto => 'udp');
    $sock->close or die "error closing inet6 socket: $!"  if $sock;
    $sock ? 1 : undef;
  };
}

# Set up for testing. Exports (as global vars):
# out: $home: $HOME env variable
# out: $cwd: here
# out: $scr: spamassassin script
# in: if --override appears at start of command line, next 2 args are used to set
# an environment variable to control test behaviour.
#
sub sa_t_init {
  my $tname = shift;

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

  $perl_cmd  = $perl_path;

  # propagate $PERL5OPT; seems to be necessary, at least for the common idiom of
  # "PERL5OPT=-MFoo::Bar ./test.t"
  if ($ENV{'PERL5OPT'}) {
    my $o = $ENV{'PERL5OPT'};
    if ($o =~ /(Devel::Cover)/) {
      warn "# setting TEST_PERL_TAINT=no to avoid lack of taint-safety in $1\n";
      $ENV{'TEST_PERL_TAINT'} = 'no';
    }
    $perl_cmd .= " \"$o\"";
  }

  $perl_cmd .= " -T" if !defined($ENV{'TEST_PERL_TAINT'}) or $ENV{'TEST_PERL_TAINT'} ne 'no';
  $perl_cmd .= " -w" if !defined($ENV{'TEST_PERL_WARN'})  or $ENV{'TEST_PERL_WARN'}  ne 'no';

  $scr = $ENV{'SPAMASSASSIN_SCRIPT'};
  $scr ||= "$perl_cmd ../spamassassin.raw";

  $spamd = "$perl_cmd ../spamd/spamd.raw";

  $spamc = $ENV{'SPAMC_SCRIPT'};
  $spamc ||= "../spamc/spamc";

  $salearn = $ENV{'SALEARN_SCRIPT'};
  $salearn ||= "$perl_cmd ../sa-learn.raw";

  $spamdlocalhost = $ENV{'SPAMD_LOCALHOST'};
  if (!$spamdlocalhost) {
    $spamdlocalhost = $have_inet4 || !$have_inet6 ? '127.0.0.1' : '::1';
  }
  $spamdhost = $ENV{'SPAMD_HOST'};
  $spamdhost ||= $spamdlocalhost;
  $spamdport = $ENV{'SPAMD_PORT'};
  $spamdport ||= probably_unused_spamd_port();

  # optimisation -- don't setup spamd test parameters unless we're
  # not skipping all spamd tests and this particular test is called
  # called "spamd_something" or "spamc_foo"
  # We still run spamc tests when there is an external SPAMD_HOST, but don't have to set up the spamd parameters for it
  if ($SKIP_SPAMD_TESTS or ($tname !~ /spam[cd]/)) {
    $NO_SPAMD_REQUIRED = 1;
  }

  $spamd_cf_args = "-C log/test_rules_copy";
  $spamd_localrules_args = " --siteconfigpath log/localrules.tmp";
  $scr_localrules_args =   " --siteconfigpath log/localrules.tmp";
  $salearn_localrules_args =   " --siteconfigpath log/localrules.tmp";

  $scr_cf_args = "-C log/test_rules_copy";
  $scr_pref_args = "-p log/test_default.cf";
  $salearn_cf_args = "-C log/test_rules_copy";
  $salearn_pref_args = "-p log/test_default.cf";
  $scr_test_args = "";
  $salearn_test_args = "";
  $set_test_prefs = 0;
  $default_cf_lines = "
    bayes_path ./log/user_state/bayes
    auto_whitelist_path ./log/user_state/auto-whitelist
  ";

  (-f "t/test_dir") && chdir("t");        # run from ..

  read_config();

  # if running as root, ensure "nobody" can write to it too
  if ($> == 0) {
    $tmp_dir_mode = 0777;
    umask 022;  # ensure correct permissions on files and dirs created here
    # Bug 5529 initial fix: For now don't run a test as root if it has a problem resuting from setuid nobody
    # FIXME: Eventually we can actually test setuid nobody and accessing ./log to make this test more fine grained
    #  and we can create an accessible temp dir that some of the tests can use. But for now just skip those tests.
    $SKIP_SETUID_NOBODY_TESTS = 1;
  } else {
    $tmp_dir_mode = 0755;
  }

  if (!$NO_SPAMD_REQUIRED) {
    $NO_SPAMC_EXE = ($RUNNING_ON_WINDOWS &&
                   !$ENV{'SPAMC_SCRIPT'} &&
                   !(-e "../spamc/spamc.exe"));
    $SKIP_SPAMC_TESTS = ($NO_SPAMC_EXE ||
                       ($RUNNING_ON_WINDOWS && !$ENV{'SPAMD_HOST'})); 
    $SSL_AVAILABLE = ((!$SKIP_SPAMC_TESTS) &&  # no SSL test if no spamc
                    (!$SKIP_SPAMD_TESTS) &&  # or if no local spamd
                    (`$spamc -V` =~ /with SSL support/) &&
                    (`$spamd --version` =~ /with SSL support/));
  }
  # do not remove prior test results!
  # rmtree ("log");

  unless (-d "log") {
    mkdir ("log", 0755) or die ("Error creating log dir: $!");
  }
  chmod (0755, "log"); # set in case log already exists with wrong permissions
  system("chacl -B log 2>/dev/null || setfacl -b log 2>/dev/null"); # remove acls that confuse test

  rmtree ("log/user_state");
  rmtree ("log/outputdir.tmp");

  rmtree ("log/test_rules_copy");
  mkdir ("log/test_rules_copy", 0755);

  for $tainted (<../rules/*.cf>, <../rules/*.pm>, <../rules/*.pre>) {
    $tainted =~ /(.*)/;
    my $file = $1;
    $base = basename $file;
    copy ($file, "log/test_rules_copy/$base")
      or warn "cannot copy $file to log/test_rules_copy/$base: $!";
  }

  copy ("data/01_test_rules.pre", "log/test_rules_copy/01_test_rules.pre")
    or warn "cannot copy data/01_test_rules.cf to log/test_rules_copy/01_test_rules.pre: $!";
  copy ("data/01_test_rules.cf", "log/test_rules_copy/01_test_rules.cf")
    or warn "cannot copy data/01_test_rules.cf to log/test_rules_copy/01_test_rules.cf: $!";

  rmtree ("log/localrules.tmp");
  mkdir ("log/localrules.tmp", 0755);

  for $tainted (<../rules/*.pm>, <../rules/*.pre>) {
    $tainted =~ /(.*)/;
    my $file = $1;
    $base = basename $file;
    copy ($file, "log/localrules.tmp/$base")
      or warn "cannot copy $file to log/localrules.tmp/$base: $!";
  }

  copy ("../rules/user_prefs.template", "log/test_rules_copy/99_test_default.cf")
    or die "user prefs copy failed: $!";

  open (PREFS, ">>log/test_rules_copy/99_test_default.cf")
    or die "cannot append to log/test_rules_copy/99_test_default.cf: $!";
  print PREFS $default_cf_lines
    or die "error writing to log/test_rules_copy/99_test_default.cf: $!";
  close PREFS
    or die "error closing log/test_rules_copy/99_test_default.cf: $!";

  # create an empty .prefs file
  open (PREFS, ">>log/test_default.cf")
    or die "cannot append to log/test_default.cf: $!";
  close PREFS
    or die "error closing log/test_default.cf: $!";

  mkdir("log/user_state",$tmp_dir_mode);
  chmod ($tmp_dir_mode, "log/user_state");  # unaffected by umask

  $home = $ENV{'HOME'};
  $home ||= $ENV{'WINDIR'} if (defined $ENV{'WINDIR'});
  $cwd = getcwd;

  $ENV{'TEST_DIR'} = $cwd;
  $testname = $tname;

  $spamd_run_as_user = ($RUNNING_ON_WINDOWS || ($> == 0)) ? "nobody" : (getpwuid($>))[0] ;
}

# a port number between 32768 and 65535; used to allow multiple test
# suite runs on the same machine simultaneously
sub probably_unused_spamd_port {
  return 0 if $NO_SPAMD_REQUIRED;

  my $port;
  my @nstat;
  local $ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';  # must not be tainted
  if (!open(NSTAT, "netstat -a -n 2>&1 |")) {
    # not too bad if failing on some architecture, with some luck should be alright
  } else {
    @nstat = grep(/^\s*tcp/i, <NSTAT>);
    close(NSTAT);
  }
  my $delta = ($$ % 32768) || int(rand(32768));
  for (1..10) {
    $port = 32768 + $delta;
    last unless (getservbyport($port, "tcp") || grep(/[:.]$port\s/, @nstat));
    $delta = int(rand(32768));
  }
  return $port;
}

sub locate_command {
  my ($command) = @_;

  my @path = File::Spec->path();
  push(@path, '/usr/bin') if ! grep { m@/usr/bin/?$@ } @path;
  for my $path (@path) {
    $location = "$path/$command";
    $location =~ s@//@/@g;
    return $location if -x $location;
  }
  return 0;
}

sub sa_t_finish {
  # no-op currently
}

sub tstfile {
  my $file = shift;
  open (OUT, ">log/mail.txt") or die;
  print OUT $file; close OUT;
}

sub tstlocalrules {
  my $lines = shift;

  $set_local_rules = 1;

  open (OUT, ">log/localrules.tmp/00test.cf") or die;
  print OUT $lines; close OUT;
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

# creates a .pre file in the localrules dir to be parsed alongside init.pre
# make it zz_* just to make sure it is parse last

sub tstpre {
  my $lines = shift;

  open (OUT, ">log/localrules.tmp/zz_tst.pre") or die;
  print OUT $lines; close OUT;
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

  my $post_redir = '';
  $args =~ s/ 2\>\&1$// and $post_redir = ' 2>&1';

  recreate_outputdir_tmp();
  clear_pattern_counters();

  if (defined $ENV{'SA_ARGS'}) {
    $args = $ENV{'SA_ARGS'} . " ". $args;
  }
  $args = "$scr_cf_args $scr_localrules_args $scr_pref_args $scr_test_args $args";

  # added fix for Windows tests from Rudif
  my $scrargs = "$scr $args";
  $scrargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);
  print ("\t$scrargs\n");
  (-d "log/d.$testname") or mkdir ("log/d.$testname", 0755);
  system ("$scrargs > log/d.$testname/${Test::ntest} $post_redir");
  $sa_exitcode = ($?>>8);
  if ($sa_exitcode != 0) { return undef; }
  &checkfile ("d.$testname/${Test::ntest}", $read_sub) if (defined $read_sub);
  1;
}

# Run salearn. Calls back with the output.
# in $args: arguments to run with
# in $read_sub: callback for the output (should read from <IN>).
# This is called with no args.
#
# out: $salearn_exitcode global: exitcode from sitescooper
# ret: undef if sitescooper fails, 1 for exit 0
#
sub salearnrun {
  my $args = shift;
  my $read_sub = shift;

  recreate_outputdir_tmp();

  %found = ();
  %found_anti = ();

  if (defined $ENV{'SA_ARGS'}) {
    $args = $ENV{'SA_ARGS'} . " ". $args;
  }
  $args = "$salearn_cf_args $salearn_localrules_args $salearn_pref_args $salearn_test_args $args";

  # added fix for Windows tests from Rudif
  my $salearnargs = "$salearn $args";
  $salearnargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);
  print ("\t$salearnargs\n");
  (-d "log/d.$testname") or mkdir ("log/d.$testname", 0755);
  system ("$salearnargs > log/d.$testname/${Test::ntest}");
  $salearn_exitcode = ($?>>8);
  if ($salearn_exitcode != 0) { return undef; }
  &checkfile ("d.$testname/${Test::ntest}", $read_sub) if (defined $read_sub);
  1;
}

sub scrun {
  spamcrun (@_, 0);
}
sub scrunwithstderr {
  spamcrun (@_, 1);
}
sub scrunwantfail {
  spamcrun (@_, 1, 1);
}

sub spamcrun {
  my $args = shift;
  my $read_sub = shift;
  my $capture_stderr = shift;
  my $expect_failure = shift;

  if (defined $ENV{'SC_ARGS'}) {
    $args = $ENV{'SC_ARGS'} . " ". $args;
  }

  my $spamcargs;
  if($args !~ /\b(?:-p\s*[0-9]+|-F|-U)\b/)
  {
    $args = "-d $spamdhost -p $spamdport $args";
  }

  if ($args !~ /-F/) {
    $spamcargs = "$spamc -F data/spamc_blank.cf $args";
  }
  else {
    $spamcargs = "$spamc $args";
  }

  $spamcargs =~ s!/!\\!g if ($^O =~ /^MS(DOS|Win)/i);

  print ("\t$spamcargs\n");
  (-d "log/d.$testname") or mkdir ("log/d.$testname", 0755);
  if ($capture_stderr) {
    system ("$spamcargs > log/d.$testname/out.${Test::ntest} 2>&1");
  } else {
    system ("$spamcargs > log/d.$testname/out.${Test::ntest}");
  }

  $sa_exitcode = ($?>>8);
  if (!$expect_failure) {
    if ($sa_exitcode != 0) { stop_spamd(); return undef; }
  }

  %found = ();
  %found_anti = ();
  &checkfile ("d.$testname/out.${Test::ntest}", $read_sub) if (defined $read_sub);

  if ($expect_failure) {
    ($sa_exitcode != 0);
  } else {
    ($sa_exitcode == 0);
  }
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
  (-d "log/d.$testname") or mkdir ("log/d.$testname", 0755);
  system ("$spamcargs > log/d.$testname/bg.${Test::ntest} &") and return 0;

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

sub recreate_outputdir_tmp {
  rmtree ("log/outputdir.tmp"); # some tests use this
  mkdir ("log/outputdir.tmp", $tmp_dir_mode);
  chmod ($tmp_dir_mode, "log/outputdir.tmp");  # unaffected by umask
}

# out: $spamd_stderr
sub start_spamd {
  return if $SKIP_SPAMD_TESTS;
  die "NO_SPAMD_REQUIRED in start_spamd! oops" if $NO_SPAMD_REQUIRED;

  my $spamd_extra_args = shift;

  return if (defined($spamd_pid) && $spamd_pid > 0);

  recreate_outputdir_tmp();

  if (defined $ENV{'SD_ARGS'}) {
    $spamd_extra_args = $ENV{'SD_ARGS'} . " ". $spamd_extra_args;
  }

  my @spamd_args = (
      $spamd,
      qq{-D},
      qq{-x}
    );

  if (!$spamd_inhibit_log_to_err) {
    push (@spamd_args, 
      qq{-s}, qq{stderr},
    );
  }

  if ($spamd_extra_args !~ /(?:-C\s*[^-]\S+)/) {
    push(@spamd_args, 
      $spamd_cf_args,
      $spamd_localrules_args,
    );
  }
  if ($spamd_extra_args !~ /(?:-p\s*[0-9]+|-o|--socketpath)/) {
    push(@spamd_args,
      qq{-p}, $spamdport,
    );
  }
  if ($spamd_extra_args !~ /(?:--socketpath)/) {
    push(@spamd_args,
      qq{-A}, $spamdhost, qq(-i), $spamdhost
    );
  }

  if ($set_test_prefs) {
    warn "oops! SATest.pm: a test prefs file was created, but spamd isn't reading it\n";
  }

  (-d "log/d.$testname") or mkdir ("log/d.$testname", 0755);
  my $spamd_stdout = "log/d.$testname/spamd.out.${Test::ntest}";
     $spamd_stderr = "log/d.$testname/spamd.err.${Test::ntest}";    #  global
  my $spamd_stdlog = "log/d.$testname/spamd.log.${Test::ntest}";

  my $spamd_forker = $ENV{'SPAMD_FORKER'}   ?
                       $ENV{'SPAMD_FORKER'} :
                     $RUNNING_ON_WINDOWS    ?
                       "start $perl_path"   :
                       $perl_path;
  my $spamd_cmd    = join(' ',
                       $spamd_forker,
                       qq{SATest.pl},
                       qq{-Mredirect},
                       qq{-O${spamd_stderr}},
                       qq{-o${spamd_stdout}},
                       qq{--},
                       @spamd_args,
                       $spamd_extra_args,
                       qq{-s ${spamd_stderr}.timestamped},
                       qq{&},
                    );

  # DEBUG instrumentation to trace spamd processes. See bug 5731 for history
  # if (-f "/home/jm/capture_spamd_straces") {
  # $spamd_cmd = "strace -ttt -fo log/d.$testname/spamd.strace.${Test::ntest} $spamd_cmd";
  # }

  unlink ($spamd_stdout, $spamd_stderr, $spamd_stdlog);
  print ("\t${spamd_cmd}\n");
  my $startat = time;
  system ($spamd_cmd);

  # now find the PID
  $spamd_pid = 0;
  # note that the wait period increases the longer it takes,
  # 20 retries works out to a total of 60 seconds
  my $retries = 30;
  my $wait = 0;
  while ($spamd_pid <= 0) {
    my $spamdlog = '';

    if (open (IN, "<${spamd_stderr}")) {
      while (<IN>) {
        # Yes, DO retry on this error. I'm getting test failures otherwise
        # /Address already in use/ and $retries = 0;
	/server pid: (\d+)/ and $spamd_pid = $1;

        if (/ERROR/) {
          warn "spamd error! $_";
          $retries = 0; last;
        }

	$spamdlog .= $_;
      }
      close IN;
      last if ($spamd_pid);
    }

    sleep (int($wait++ / 4) + 1) if $retries > 0;

    if ($retries-- <= 0) {
      warn "spamd start failed: log: $spamdlog";
      warn "\n\nMaybe you need to kill a running spamd process?\n";
      warn "started at $startat, gave up at ".time."\n\n";
      return 0;
    }
  }

  1;
}

sub stop_spamd {
  return 0 if ( defined($spamd_already_killed) || $SKIP_SPAMD_TESTS);
  die "NO_SPAMD_REQUIRED in stop_spamd! oops" if $NO_SPAMD_REQUIRED;

  $spamd_pid ||= 0;
  if ( $spamd_pid <= 1) {
    print ("Invalid spamd pid: $spamd_pid. Spamd not started/crashed?\n");
    return 0;
  } else {
    my $killed = kill (15, $spamd_pid);
    print ("Killed $killed spamd instances\n");

    # wait for it to exit, before returning.
    for my $waitfor (0 .. 5) {
      my $killstat;
      if (($killstat = kill (0, $spamd_pid)) == 0) { last; }
      print ("Waiting for spamd at pid $spamd_pid to exit...\n");
      sleep 1;
    }

    $spamd_pid = 0;
    $spamd_already_killed = 1;
    return $killed;
  }
}

sub create_saobj {
  my ($args) = shift; # lets you override/add arguments

  # YUCK, these file/dir names should be some sort of variable, at
  # least we keep their definition in the same file for the moment.
  my %setup_args = ( rules_filename => 'log/test_rules_copy',
		     site_rules_filename => 'log/localrules.tmp',
		     userprefs_filename => 'log/test_default.cf',
		     userstate_dir => 'log/user_state',
		     local_tests_only => 1,
                     # debug => 'all',
		   );

  # override default args
  foreach my $arg (keys %$args) {
    $setup_args{$arg} = $args->{$arg};
  }

  # We'll assume that the test has setup INC correctly
  require Mail::SpamAssassin;

  my $sa = Mail::SpamAssassin->new(\%setup_args);

  return $sa;
}

sub create_clientobj {
  my $args = shift;

  # We'll assume that the test has setup INC correctly
  require Mail::SpamAssassin::Client;

  my $client = Mail::SpamAssassin::Client->new($args);

  return $client;
}

# ---------------------------------------------------------------------------

sub checkfile {
  my $filename = shift;
  my $read_sub = shift;

  # print "Checking $filename\n";
  if (!open (IN, "< log/$filename")) {
    # could be it already contains the "log/" prefix?
    if (!open (IN, "< $filename")) {
      warn "cannot open log/$filename or $filename"; return undef;
    } else {
      push @files_checked, "$filename";
    }
  } else {
    push @files_checked, "log/$filename";
  }
  &$read_sub();
  close IN;
}

# ---------------------------------------------------------------------------

sub pattern_to_re {
  my $pat = shift;

  if ($pat =~ /^\/(.*)\/$/) {
    return $1;
  }

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
  $matched_output = $_;

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
  my ($dont_ok) = shift;
  my (undef, $file, $line) = caller();
  my $wasfailure = 0;
  foreach my $pat (sort keys %patterns) {
    my $type = $patterns{$pat};
    print "\tChecking $type\n";
    if (defined $found{$type}) {
      if (!$dont_ok) {
        ok ($found{$type} == 1) or warn "Found more than once: $type at $file line $line.\n";
      }
    } else {
      warn "\tNot found: $type = $pat at $file line $line.\n";
      if (!$dont_ok) {
        ok (0);                     # keep the right # of tests
      }
      $wasfailure++;
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type at $file line $line.\n";
    if (defined $found_anti{$type}) {
      warn "\tFound anti-pattern: $type = $pat at $file line $line.\n";
      if (!$dont_ok) { ok (0); }
      $wasfailure++;
    }
    else
    {
      if (!$dont_ok) { ok (1); }
    }
  }

  if ($wasfailure) {
    warn "Output can be examined in: ".
         join(' ', @files_checked)."\n"  if @files_checked;
    return 0;
  } else {
    return 1;
  }
}

sub skip_all_patterns {
  my $skip = shift;
  my (undef, $file, $line) = caller();
  foreach my $pat (sort keys %patterns) {
    my $type = $patterns{$pat};
    print "\tChecking $type\n";
    if (defined $found{$type}) {
      skip ($skip, $found{$type} == 1) or warn "Found more than once: $type at $file line $line.\n";
      warn "\tThis test should have been skipped: $skip at $file line $line.\n" if $skip;
    } else {
      if ($skip) {
        warn "\tTest skipped: $skip at $file line $line.\n";
      } else {
        warn "\tNot found: $type = $pat at $file line $line.\n";
      }
      skip ($skip, 0);                     # keep the right # of tests
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type\n";
    if (defined $found_anti{$type}) {
      warn "\tFound anti-pattern: $type = $pat at $file line $line.\n";
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
  @files_checked = ();
}

sub read_config {
  return if defined($already_read_config);
  $already_read_config = 1;

  # allow reading config from top-level dir, outside the test suite;
  # this is so read_config() will work even when called from
  # a "use constant" line at compile time.
  my $prefix = '';
  if (-f 't/test_dir') { $prefix = "t/"; }

  if (!open (CF, "<${prefix}config")) {
    if (!open (CF, "<${prefix}config.dist")) {   # fall back to defaults
      die "cannot open test suite configuration file 'config.dist': $!";
    }
  }

  while (<CF>) {
    s/#.*$//; s/^\s+//; s/\s+$//; next if /^$/;
    /^([^=]+)=(.*)$/ or next;
    $conf{$1} = $2;
  }

  # allow our xt test suite to override
  if (defined $ARGV[0] && $ARGV[0] eq '--override') {
    shift @ARGV;
    my $k = shift @ARGV;
    my $v = shift @ARGV;

    # Override only allows setting one variable.  Some xt tests need to set more
    # config variables.  Adding : as a delimeter for config variable and value 
    # parameters

    @k = split (/:/,$k);
    @v = split (/:/,$v);

    if (scalar(@k) != scalar(@v)) {
      print "Error: The number of override arguments for variables and values did not match\n!";
      exit;
    } else {
      print "\nProcessing Overrides:\n\n";
    }

    for (my $i = 0; $i < scalar(@k); $i++) {
      $conf{$k[$i]} = $v[$i];
      print "Overriding $k[$i] with value $v[$i]\n";
    }
  }
  close CF;
}

sub conf {
  read_config();
  return $conf{$_[0]};
}

sub conf_bool {
  my $val = conf($_[0]);
  return 0 unless defined($val);
  return 1 if ($val =~ /^y/i);              # y, YES, yes, etc.
  return ($val+0) if ($val =~ /^\d/);       # 1
  return 0;                                 # n or 0
}

sub mk_safe_tmpdir {
  return $safe_tmpdir if defined($safe_tmpdir);

  my $dir = File::Spec->tmpdir() || 'log';

  # be a little paranoid, since we're using a public tmp dir and
  # are exposed to race conditions
  my $retries = 10;
  my $tmp;
  while (1) {
    $tmp = "$dir/satest.$$.".rand(99999);
    if (!-d $tmp && mkdir ($tmp, 0755)) {
      if (-d $tmp && -o $tmp) {     # check we own it
        lstat($tmp);
        if (-d _ && -o _) {         # double-check, ignoring symlinks
          last;                     # we got it safely
        }
      }
    }

    die "cannot get tmp dir, giving up" if ($retries-- < 0);

    warn "failed to create tmp dir '$tmp' safely, retrying...";
    sleep 1;
  }

  $safe_tmpdir = $tmp;
  return $tmp;
}

sub cleanup_safe_tmpdir {
  if ($safe_tmpdir) {
    rmtree($safe_tmpdir) or warn "cannot rmtree $safe_tmpdir";
  }
}

sub wait_for_file_to_change_or_disappear {
  my ($f, $timeout, $action) = @_;

  my $lastmod = (-M $f);

  $action->();

  my $wait = 0;
  my $newlastmod;
  do {
    sleep (int($wait++ / 4) + 1) if $timeout > 0;
    $timeout--;
    $newlastmod = (-M $f);
  } while((-e $f) && defined($newlastmod) &&
                $newlastmod == $lastmod && $timeout);
}

sub wait_for_file_to_appear {
  my ($f, $timeout) = @_;

  # note that the wait period increases the longer it takes,
  # 20 retries works out to a total of 60 seconds
  my $wait = 0;
  do {
    sleep (int($wait++ / 4) + 1) if $timeout > 0;
    $timeout--;
  } while((!-e $f || -z $f) && $timeout);
}

sub read_from_pidfile {
  my $f = shift;
  my $npid = 0;
  my $retries = 5;

  do {
    if ($retries != 5) {
      sleep 1;
      warn "retrying read of pidfile $f, due to short/nonexistent read: ".
            "retry $retries";
    }
    $retries--;

    if (!open (PID, "<".$f)) {
      warn "Could not open pid file ${f}: $!\n";     # and retry
      next;
    }

    $npid = <PID>;
    if (defined $npid) { chomp $npid; }
    close(PID);

    if (!$npid || $npid < 1) {
      warn "failed to read anything sensible from $f, retrying read";
      $npid = 0;
      next;
    }
    if (!kill (0, $npid)) {
      warn "failed to kill -0 $npid, retrying read";
      $npid = 0;
    }

  } until ($npid > 1 or $retries == 0);

  return $npid;
}

sub system_or_die {
  my $cmd = $_[0];
  print ("\t$cmd\n");
  system($cmd);
  $? == 0  or die "'$cmd' failed: ".exit_status_str($?,0);
}

# (sub exit_status_str copied from Util.pm)
# map process termination status number to an informative string, and
# append optional mesage (dual-valued errno or a string or a number),
# returning the resulting string
#
sub exit_status_str($;$) {
  my($stat,$errno) = @_;
  my $str;
  if (WIFEXITED($stat)) {
    $str = sprintf("exit %d", WEXITSTATUS($stat));
  } elsif (WIFSTOPPED($stat)) {
    $str = sprintf("stopped, signal %d", WSTOPSIG($stat));
  } else {
    my $sig = WTERMSIG($stat);
    $str = sprintf("%s, signal %d (%04x)",
             $sig == 2 ? 'INTERRUPTED' : $sig == 6 ? 'ABORTED' :
             $sig == 9 ? 'KILLED' : $sig == 15 ? 'TERMINATED' : 'DIED',
             $sig, $stat);
  }
  if (defined $errno) {  # deal with dual-valued and plain variables
    $str .= ', '.$errno  if (0+$errno) != 0 || ($errno ne '' && $errno ne '0');
  }
  return $str;
}

sub dbgprint { print STDOUT "[".time()."] ".$_[0]; }

sub can_use_net_dns_safely {
  return unless eval { require Net::DNS; };

  # bug 3806:
  # Do not run this test with version of Sys::Hostname::Long older than 1.4
  # on non-Linux unices as root, due to a bug in Sys::Hostname::Long
  # (which is used by Net::DNS)

  return 1 if ($< != 0);
  return 1 if ($^O =~ /^(linux|mswin|dos|os2)/oi);

  my $has_unsafe_hostname =
    eval { require Sys::Hostname::Long && Sys::Hostname::Long->VERSION < 1.4 };
  return 1 if !$has_unsafe_hostname;

  return;
}

sub debug_hash {
  my ($hash) = @_;
  my ($string, $key, @keys, @sorted, $i);

  if (uc(ref($hash)) eq "HASH") {
    foreach $key (keys %$hash) {
      push (@keys, $key);
    }
    @sorted = sort @keys;
  
    for ($i=0; $i < scalar(@sorted); $i++) {
      if (uc(ref($hash->{$sorted[$i]})) eq 'HASH') {
        $string .= "$sorted[$i] = ".debug_hash($hash->{$sorted[$i]})."\n";
      } else {
        $string .= "$sorted[$i] = $hash->{$sorted[$i]}\n";
      }
    }
  } else {
    warn (uc(ref($hash)) . " is not a HASH\n");
  }
  return $string;
}

sub debug_array {
  my ($array) = @_;

  my ($string, $i);

  if (uc(ref($array)) eq "ARRAY") {
    for ($i =0; $i < scalar(@$array); $i++) {
      $string .= "Array Element $i = $array->[$i]\n";
    }
  }
  return $string;
}

1;
