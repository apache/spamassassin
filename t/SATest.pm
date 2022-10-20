# common functionality for tests.
# imported into main for ease of use.
package main;

require v5.14.0;

# use strict;
# use warnings;
# use re 'taint';

use Cwd;
use Config;
use File::Basename;
use File::Copy;
use File::Path;
use File::Spec;
use File::Temp qw(tempdir);

use Test::Builder ();
use Test::More    ();

use POSIX qw(WIFEXITED WIFSIGNALED WIFSTOPPED WEXITSTATUS WTERMSIG WSTOPSIG);

use vars qw($RUNNING_ON_WINDOWS $SSL_AVAILABLE
            $SKIP_SPAMD_TESTS $SKIP_SPAMC_TESTS $NO_SPAMC_EXE
            $SKIP_SETUID_NOBODY_TESTS $SKIP_DNSBL_TESTS
            $have_inet4 $have_inet6 $spamdhost $spamdport
            $workdir $siterules $localrules $userrules $userstate
            $keep_workdir $mainpid $spamd_pidfile);

my $sa_code_dir;
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
    my $sock = IO::Socket::INET->new(LocalAddr => '127.0.0.1', Proto => 'udp');
    $sock->close or die "error closing inet socket: $!"  if $sock;
    $sock ? 1 : undef;
  };

  $have_inet6 = eval {
    require IO::Socket::INET6;
    my $sock = IO::Socket::INET6->new(LocalAddr => '::1', Proto => 'udp');
    $sock->close or die "error closing inet6 socket: $!"  if $sock;
    $sock ? 1 : undef;
  };

  # Clean PATH so taint doesn't complain
  if (!$RUNNING_ON_WINDOWS) {
    $ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';
    # Remove tainted envs, at least ENV used in FreeBSD
    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
  } else {
    # Windows might need non-system directories in PATH to run a Perl installation
    # The best we can do is clean out obviously bad stuff such as relative paths or \..\
    my @pathdirs = split(';', $ENV{'PATH'});
    $ENV{'PATH'} =
      join(';', # filter for only dirs that are canonical absolute paths that exist
        map {
              my $pathdir = $_;
              $pathdir =~ s/\\*\z//;
              my $abspathdir = File::Spec->canonpath(Cwd::realpath($pathdir)) if (-d $pathdir);
              if (defined $abspathdir) {
                $abspathdir  =~ /^(.*)\z/s;
                $abspathdir = $1; # untaint it
              }
              ((defined $abspathdir) and (lc $pathdir eq lc $abspathdir))?($abspathdir):()
            }
          @pathdirs);
  }
  
  # Fix INC to point to absolute path of built SA
  if (-e 't/test_dir') { $sa_code_dir = 'blib/lib'; }
  elsif (-e 'test_dir') { $sa_code_dir = '../blib/lib'; }
  else { die "FATAL: not in or below test directory?\n"; }
  File::Spec->rel2abs($sa_code_dir) =~ /^(.*)\z/s;
  $sa_code_dir = $1;
  if (not -d $sa_code_dir) {
    die "FATAL: not in expected directory relative to built code tree?\n";
  }
}

# use is run at compile time, but after the variable has been computed in the BEGIN block
use lib $sa_code_dir;

# Set up for testing. Exports (as global vars):
# out: $home: $HOME env variable
# out: $cwd: here
# out: $scr: spamassassin script
# in: if --override appears at start of command line, next 2 args are used to set
# an environment variable to control test behaviour.
#
sub sa_t_init {
  my $tname = shift;
  $mainpid = $$;

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

  # Copy directories in PERL5LIB into -I options in perl_cmd because -T suppresses use of PERL5LIB in call to ./spamassassin
  # If PERL5LIB is empty copy @INC instead because on some platforms like FreeBSD MakeMaker clears PER5LIB and sets @INC
  # Filter out relative paths, and canonicalize so no symlinks or /../ will be left in untainted result as a nod to security
  # Since this is only used to run tests, the security considerations are not as strict as with more general situations.
  my @pathdirs = @INC;
  if ($ENV{'PERL5LIB'}) {
    @pathdirs = split($Config{path_sep}, $ENV{'PERL5LIB'});
  }
  my $inc_opts =
    join(' -I', # filter for only dirs that are absolute paths that exist, then canonicalize them
      map {
            my $pathdir = $_;
            my $canonpathdir = File::Spec->canonpath(Cwd::realpath($pathdir)) if ((-d $pathdir) and File::Spec->file_name_is_absolute($pathdir));
            if (defined $canonpathdir) {
               $canonpathdir =~ /^(.*)\z/s;
               $canonpathdir = $1; # untaint it
            }
            ((defined $canonpathdir))?($canonpathdir):()
          }
         @pathdirs);
  $perl_cmd .= " -I$inc_opts" if ($inc_opts);
  
  # To work in Windows, the perl scripts have to be launched by $perl_cmd and
  # the ones that are exe files have to be directly called in the command lines
  
  $scr = $ENV{'SPAMASSASSIN_SCRIPT'};
  $scr ||= "$perl_cmd ../spamassassin.raw";

  $spamd = $ENV{'SPAMD_SCRIPT'};
  $spamd ||= "$perl_cmd ../spamd/spamd.raw";

  $spamc = $ENV{'SPAMC_SCRIPT'};
  $spamc ||= "../spamc/spamc";

  $salearn = $ENV{'SALEARN_SCRIPT'};
  $salearn ||= "$perl_cmd ../sa-learn.raw";

  $saawl = $ENV{'SAAWL_SCRIPT'};
  $saawl ||= "$perl_cmd ../sa-awl";

  $sacheckspamd = $ENV{'SACHECKSPAMD_SCRIPT'};
  $sacheckspamd ||= "$perl_cmd ../sa-check_spamd";

  $spamdlocalhost = $ENV{'SPAMD_LOCALHOST'};
  if (!$spamdlocalhost) {
    $spamdlocalhost = $have_inet4 || !$have_inet6 ? '127.0.0.1' : '::1';
  }
  $spamdhost = $ENV{'SPAMD_HOST'};
  $spamdhost ||= $spamdlocalhost;

  # optimisation -- don't setup spamd test parameters unless we're
  # not skipping all spamd tests and this particular test is called
  # called "spamd_something" or "spamc_foo"
  # We still run spamc tests when there is an external SPAMD_HOST, but don't have to set up the spamd parameters for it
  if ($tname !~ /spam[cd]/) {
    $TEST_DOES_NOT_RUN_SPAMC_OR_D = 1;
  } else {
    $spamdport = $ENV{'SPAMD_PORT'};
    $spamdport ||= probably_unused_spamd_port();
  }

  (-f "t/test_dir") && chdir("t");        # run from ..
  -f "test_dir"  or die "FATAL: not in test directory?\n";

  unless (-d "log") {
    mkdir ("log", 0755) or die ("Error creating log dir: $!");
  }
  chmod (0755, "log"); # set in case log already exists with wrong permissions

  if (!$RUNNING_ON_WINDOWS) {
    untaint_system("chacl -B log 2>/dev/null || setfacl -b log 2>/dev/null"); # remove acls that confuse test
  }

  # clean old workdir if sa_t_init called multiple times
  if (defined $workdir) {
    if (!$keep_workdir) {
      rmtree($workdir);
    }
  }

  # individual work directory to make parallel tests possible
  $workdir = tempdir("$tname.XXXXXX", DIR => "log");
  die "FATAL: failed to create workdir: $!" unless -d $workdir;
  $keep_workdir = 0;
  # $siterules contains all stock *.pre files
  $siterules = "$workdir/siterules";
  # $localrules contains all stock *.cf files
  $localrules = "$workdir/localrules";
  # $userrules contains user rules
  $userrules = "$workdir/user.cf";
  # user_state directory
  $userstate = "$workdir/user_state";

  mkdir($siterules) or die "FATAL: failed to create $siterules\n";
  mkdir($localrules) or die "FATAL: failed to create $localrules\n";
  open(OUT, ">$userrules") or die "FATAL: failed to create $userrules\n";
  close(OUT);
  mkdir($userstate) or die "FATAL: failed to create $userstate\n";

  $spamd_pidfile = "$workdir/spamd.pid";
  $spamd_cf_args = "-C $localrules";
  $spamd_localrules_args = " --siteconfigpath $siterules";
  $scr_localrules_args =   " --siteconfigpath $siterules";
  $salearn_localrules_args =   " --siteconfigpath $siterules";

  $scr_cf_args = "-C $localrules";
  $scr_pref_args = "-p $userrules";
  $salearn_cf_args = "-C $localrules";
  $salearn_pref_args = "-p $userrules";
  $scr_test_args = "";
  $salearn_test_args = "";
  $set_user_prefs = 0;
  $default_cf_lines = "
    bayes_path ./$userstate/bayes
    auto_welcomelist_path ./$userstate/auto-welcomelist
  ";

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

  $NO_SPAMC_EXE = $TEST_DOES_NOT_RUN_SPAMC_OR_D ||
                  ($RUNNING_ON_WINDOWS &&
                   !$ENV{'SPAMC_SCRIPT'} &&
                   !(-e "../spamc/spamc.exe"));
  $SKIP_SPAMC_TESTS = ($NO_SPAMC_EXE ||
                     ($RUNNING_ON_WINDOWS && !$ENV{'SPAMD_HOST'})); 
  $SSL_AVAILABLE = (!$TEST_DOES_NOT_RUN_SPAMC_OR_D) &&
                  (!$SKIP_SPAMC_TESTS) &&  # no SSL test if no spamc
                  (!$SKIP_SPAMD_TESTS) &&  # or if no local spamd
                  (untaint_cmd("$spamc -V") =~ /with SSL support/) &&
                  (untaint_cmd("$spamd --version") =~ /with SSL support/);

  for $tainted (<../rules/*.pm>, <../rules/*.pre>, <../rules/languages>) {
    $tainted =~ /(.*)/;
    my $file = $1;
    $base = basename $file;
    copy ($file, "$siterules/$base")
      or warn "cannot copy $file to $siterules/$base: $!";
  }

  for $tainted (<../rules/*.cf>) {
    $tainted =~ /(.*)/;
    my $file = $1;
    $base = basename $file;
    copy ($file, "$localrules/$base")
      or warn "cannot copy $file to $localrules/$base: $!";
  }

  copy ("data/01_test_rules.pre", "$localrules/01_test_rules.pre")
    or warn "cannot copy data/01_test_rules.cf to $localrules/01_test_rules.pre: $!";
  copy ("data/01_test_rules.cf", "$localrules/01_test_rules.cf")
    or warn "cannot copy data/01_test_rules.cf to $localrules/01_test_rules.cf: $!";

  open (PREFS, ">>$localrules/99_test_default.cf")
    or die "cannot append to $localrules/99_test_default.cf: $!";
  print PREFS $default_cf_lines
    or die "error writing to $localrules/99_test_default.cf: $!";
  close PREFS
    or die "error closing $localrules/99_test_default.cf: $!";

  $home = $ENV{'HOME'};
  $home ||= $ENV{'WINDIR'} if (defined $ENV{'WINDIR'});
  $cwd = getcwd;

  $ENV{'TEST_DIR'} = $cwd;
  $testname = $tname;

  $spamd_run_as_user = ($RUNNING_ON_WINDOWS || ($> == 0)) ? "nobody" : (getpwuid($>))[0] ;
}

# remove all rules - $localrules/*.cf
# when you want to only use rules declared inside a specific *.t
sub clear_localrules {
  for $tainted (<$localrules/*.cf>) {
    $tainted =~ /(.*)/;
    my $file = $1;
    # Keep some useful, should not contain any rules
    next if $file =~ /10_default_prefs.cf$/;
    next if $file =~ /20_aux_tlds.cf$/;
    # Keep our own tstprefs() or tstlocalrules()
    next if $file =~ /99_test_prefs.cf$/;
    next if $file =~ /99_test_rules.cf$/;
    unlink $file;
  }
}

# a port number between 40000 and 65520; used to allow multiple test
# suite runs on the same machine simultaneously
sub probably_unused_spamd_port {
  return 0 if $SKIP_SPAMD_TESTS;

  my $port;
  my @nstat;
  if (!open(NSTAT, "netstat -a -n 2>&1 |")) {
    # not too bad if failing on some architecture, with some luck should be alright
  } else {
    @nstat = grep(/^\s*tcp/i, <NSTAT>);
    close(NSTAT);
  }
  for (1..20) {
    $port = 40000 + int(rand(65500-40000));
    last unless (getservbyport($port, "tcp") || grep(/[:.]$port\s/, @nstat));
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
  open (OUT, ">$workdir/mail.txt") or die;
  print OUT $file; close OUT;
}

sub tstprefs {
  my $lines = shift;

  open (OUT, ">$localrules/99_test_prefs.cf") or die;
  print OUT $lines; close OUT;
}

sub tstlocalrules {
  my $lines = shift;

  open (OUT, ">$localrules/99_test_rules.cf") or die;
  print OUT $lines; close OUT;
}

sub tstuserprefs {
  my $lines = shift;

  $set_user_prefs = 1;

  # TODO: should we use -p, or modify the test_rules_copy/99_test_default.cf?
  # for now, I'm taking the -p route, since we have to be able to test
  # the operation of user-prefs in general, itself.

  open (OUT, ">$userrules") or die;
  print OUT $lines; close OUT;
}

# creates a .pre file in the localrules dir to be parsed alongside init.pre
# make it zz_* just to make sure it is parse last

sub tstpre {
  my $lines = shift;

  open (OUT, ">$siterules/zz_test.pre") or die;
  print OUT $lines; close OUT;
}

# remove default compatibility option
sub disable_compat {
  my $compat = shift;
  return unless defined $compat;
  open (IN, "$siterules/init.pre") or die;
  open (OUT, ">$siterules/init.pre.new") or die;
  while (<IN>) {
    next if $_ =~ /^\s*enable_compat\s+\Q$compat\E(?:\s|$)/i;
    print OUT $_;
  }
  close OUT or die;
  close IN or die;
  rename("$siterules/init.pre.new", "$siterules/init.pre");
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
  (-d "$workdir/d.$testname") or mkdir ("$workdir/d.$testname", 0755);
  
  my $test_number = test_number();
  $current_checkfile = "$workdir/d.$testname/$test_number";
#print STDERR "RUN: $scrargs\n";
  untaint_system("$scrargs > $workdir/d.$testname/$test_number $post_redir");
  $sa_exitcode = ($?>>8);
  if ($sa_exitcode != 0) { return undef; }
  &checkfile ("$workdir/d.$testname/$test_number", $read_sub) if (defined $read_sub);
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
  (-d "$workdir/d.$testname") or mkdir ("$workdir/d.$testname", 0755);

  my $test_number = test_number();
  $current_checkfile = "$workdir/d.$testname/$test_number";

  untaint_system("$salearnargs > $workdir/d.$testname/$test_number");
  $salearn_exitcode = ($?>>8);
  if ($salearn_exitcode != 0) { return undef; }
  &checkfile ("$workdir/d.$testname/$test_number", $read_sub) if (defined $read_sub);
  1;
}

sub saawlrun {
  my $args = shift;

  untaint_system("$saawl $args");
}

sub sacheckspamdrun {
  my $args = shift;

  untaint_system("$sacheckspamd $args");
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
  (-d "$workdir/d.$testname") or mkdir ("$workdir/d.$testname", 0755);

  my $test_number = test_number();

  if ($capture_stderr) {
    untaint_system ("$spamcargs > $workdir/d.$testname/out.$test_number 2>&1");
  } else {
    untaint_system ("$spamcargs > $workdir/d.$testname/out.$test_number");
  }

  $sa_exitcode = ($?>>8);
  if (!$expect_failure) {
    if ($sa_exitcode != 0) { stop_spamd(); return undef; }
  }

  %found = ();
  %found_anti = ();
  &checkfile ("$workdir/d.$testname/out.$test_number", $read_sub) if (defined $read_sub);

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
  (-d "$workdir/d.$testname") or mkdir ("$workdir/d.$testname", 0755);
  
  my $test_number = test_number();
  untaint_system ("$spamcargs > $workdir/d.$testname/bg.$test_number &") and return 0;

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
  rmtree ("$workdir/outputdir.tmp"); # some tests use this
  mkdir ("$workdir/outputdir.tmp", $tmp_dir_mode);
  chmod ($tmp_dir_mode, "$workdir/outputdir.tmp");  # unaffected by umask
}

# out: $spamd_stderr
sub start_spamd {
  return if $SKIP_SPAMD_TESTS;
  die "TEST_DOES_NOT_RUN_SPAMC_OR_D; in start_spamd! oops" if $TEST_DOES_NOT_RUN_SPAMC_OR_D;

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

  (-d "$workdir/d.$testname") or mkdir ("$workdir/d.$testname", 0755);
  
  my $test_number = test_number();
  my $spamd_stdout = "$workdir/d.$testname/spamd.out.$test_number";
     $spamd_stderr = "$workdir/d.$testname/spamd.err.$test_number";    #  global
  my $spamd_stdlog = "$workdir/d.$testname/spamd.log.$test_number";
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
                       qq{-r ${spamd_pidfile}},
                       qq{&},
                    );

  # DEBUG instrumentation to trace spamd processes. See bug 5731 for history
  # if (-f "/home/jm/capture_spamd_straces") {
  # $spamd_cmd = "strace -ttt -fo $workdir/d.$testname/spamd.strace.$test_number $spamd_cmd";
  # }

  unlink ($spamd_stdout, $spamd_stderr, $spamd_stdlog, $spamd_pidfile);
  print ("\t${spamd_cmd}\n");
  my $startat = time;
  untaint_system ($spamd_cmd);

  $spamd_pid = 0;
  # Find the PID, either in the pidfile or the log... 
  # note that the wait period increases the longer it takes,
  # 20 retries works out to a total of 60 seconds
  my $retries = 30;
  my $wait = 7;
  sleep $wait ;
  while ($spamd_pid <= 0) {
    my $spamdlog = '';
    my $pidstr;
    if (open(PID, $spamd_pidfile)) {
      $pidstr = <PID>;
      close PID;
    }
    if ($pidstr) {
       chomp $pidstr;
       $spamd_pid = $pidstr;
       dbgprint("Found PID $spamd_pid in pidfile\n");
       last
    }
    if (open (IN, "<${spamd_stderr}")) {
      while (<IN>) {
        # Yes, DO retry on this error. I'm getting test failures otherwise
        # /Address already in use/ and $retries = 0;
	/server pid: (\d+)/ and $spamd_pid = "$1" and dbgprint("Found PID $spamd_pid in stderr logfile\n");

        if ( !(/dbg: config: .*rulename/) && (/\bERROR/) ){
          warn "spamd start failed - spamd error! $_\nExiting test with debug output";
          $retries = 0; last;
        }

	$spamdlog .= $_;
      }
      close IN;
      last if ($spamd_pid);
    }

    my $sleep = (int($wait++ / 4) + 1);
    warn "spam_pid not found: Sleeping $sleep - Retry # $retries\n" if $retries && $retries < 20;

    sleep $sleep if $retries > 0;

    if ($retries-- <= 0) {
      warn "spamd start failed - Could not find a valid PID.\nEnd Debug log -------------------\n$spamdlog\nEnd Debug log -------------------";
      warn "\n\nMaybe you need to kill a running spamd process?\n";
      warn "Or the start took too long. Started at $startat, gave up at ".time."\n\n";
      return 0;
    }
  }

  1;
}

sub stop_spamd {
  return 0 if ( defined($spamd_already_killed) || $SKIP_SPAMD_TESTS);
  die "TEST_DOES_NOT_RUN_SPAMC_OR_D; in stop_spamd! oops" if $TEST_DOES_NOT_RUN_SPAMC_OR_D;

  $spamd_pid ||= 0;
  $spamd_pid = untaint_var($spamd_pid);
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
  my %setup_args = ( rules_filename => $localrules,
		     site_rules_filename => $siterules,
		     userprefs_filename => $userrules,
		     userstate_dir => $userstate,
		     local_tests_only => 1,
                     # debug => 'all',
		   );

  # override default args
  foreach my $arg (keys %$args) {
    $setup_args{$arg} = $args->{$arg};
  }

  require Mail::SpamAssassin;

  my $sa = Mail::SpamAssassin->new(\%setup_args);

  return $sa;
}

sub create_clientobj {
  my $args = shift;

  require Mail::SpamAssassin::Client;

  my $client = Mail::SpamAssassin::Client->new($args);

  return $client;
}

# ---------------------------------------------------------------------------

sub checkfile {
  my $filename = shift;
  my $read_sub = shift;

  # print "Checking $filename\n";
  if (!open (IN, "< $filename")) {
    warn "cannot open $filename";
    return undef;
  } else {
    push @files_checked, "$filename";
  }
  &$read_sub();
  close IN;
}

# ---------------------------------------------------------------------------

sub patterns_run_cb {
  my $string = shift;

  if (!defined $string) {
    $string = join ('', <IN>);
  }
  $matched_output = $string;

  # create default names == the pattern itself, if not specified
  my %seen;
  foreach my $pat (keys %patterns) {
    if ($patterns{$pat} eq '') {
      $patterns{$pat} = $pat;
    }
    if ($seen{$patterns{$pat}}++) {
      die "ERROR: duplicate pattern name found: '$patterns{$pat}'\n";
    }
  }
  %seen = ();
  foreach my $pat (keys %anti_patterns) {
    if ($anti_patterns{$pat} eq '') {
      $anti_patterns{$pat} = $pat;
    }
    if ($seen{$anti_patterns{$pat}}++) {
      die "ERROR: duplicate anti_pattern name found: '$anti_patterns{$pat}'\n";
    }
  }

  foreach my $pat (sort keys %patterns) {
    if (index($pat, '(?^') == 0) { # Detect qr// regex, it's a string now
      if ($string =~ $pat) {
        $found{$patterns{$pat}}++;
      }
    } else {
      my $re = $pat;
      $re =~ s/([^A-Za-z_0-9\s])/\\$1/gs; # quotemeta
      $re =~ s/\s+/\\s+/gs; # normalize whitespace
      eval { $re = qr/$re/; 1; };
      if ($@) { die "ERROR: failed to compile regex: '$re'\n"; }
      if ($string =~ $re) {
        $found{$patterns{$pat}}++;
      }
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    if (index($pat, '(?^') == 0) { # Detect qr// regex, it's a string now
      if ($string =~ $pat) {
        $found_anti{$anti_patterns{$pat}}++;
      }
    } else {
      my $re = $pat;
      $re =~ s/([^A-Za-z_0-9\s])/\\$1/gs; # quotemeta
      $re =~ s/\s+/\\s+/gs; # normalize whitespace
      eval { $re = qr/$re/; 1; };
      if ($@) { die "ERROR: failed to compile regex: '$re'\n"; }
      if ($string =~ $re) {
        $found_anti{$anti_patterns{$pat}}++;
      }
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
      my $typestr = $type eq $pat ? "" : "$type = ";
      warn "\tNot found: $typestr$pat at $file line $line.\n";
      if (!$dont_ok) {
        $keep_workdir = 1;
        ok (0);                     # keep the right # of tests
      }
      $wasfailure++;
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type at $file line $line.\n";
    if (defined $found_anti{$type}) {
      my $typestr = $type eq $pat ? "" : "$type = ";
      warn "\tFound anti-pattern: $typestr$pat at $file line $line.\n";
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
    $keep_workdir = 1;
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
        my $typestr = $type eq $pat ? "" : "$type = ";
        warn "\tNot found: $typestr$pat at $file line $line.\n";
      }
      skip ($skip, 0);                     # keep the right # of tests
    }
  }
  foreach my $pat (sort keys %anti_patterns) {
    my $type = $anti_patterns{$pat};
    print "\tChecking for anti-pattern $type\n";
    if (defined $found_anti{$type}) {
      my $typestr = $type eq $pat ? "" : "$type = ";
      warn "\tFound anti-pattern: $typestr$pat at $file line $line.\n";
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
    # config variables.  Adding : as a delimiter for config variable and value 
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

sub mk_socket_tempdir {
  my $dir = tempdir(CLEANUP => 1);
  die "FATAL: failed to create socket_tempdir: $!" unless -d $dir;
  return $dir;
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
    $npid = untaint_var($npid);

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
  untaint_system($cmd);
  $? == 0  or die "'$cmd' failed: ".exit_status_str($?,0);
}

# (sub exit_status_str copied from Util.pm)
# map process termination status number to an informative string, and
# append optional message (dual-valued errno or a string or a number),
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
  return 1 if ($^O =~ /^(linux|mswin|dos|os2|openbsd)/oi);

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

sub test_number {
  return Test::More->builder->current_test;
}

# Simple version of untaint_var for internal use
sub untaint_var {
    local($1);
    $_[0] =~ /^(.*)\z/s;
    return $1;
}

# untainted system()
sub untaint_system {
    my @args;
    push @args, untaint_var($_) foreach (@_);
    return system(@args);
}

# untainted version of `shell command`
sub untaint_cmd {
    if (open(CMD, untaint_var($_[0])."|")) {
      my $stdout = do { local($/); <CMD> };
      close CMD;
      return $stdout;
    } else {
      return "";
    }
}

END {
  # Cleanup workdir (but not if inside forked process)
  if (defined $workdir && !$keep_workdir && $$ == $mainpid) {
    rmtree($workdir);
  }
}

1;
