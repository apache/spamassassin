#!/usr/bin/perl

use lib '.'; use lib 't';
$ENV{'TEST_PERL_TAINT'} = 'no';  # so $perl_cmd doesn't have -T when used to call Makefile.PL 
use SATest; sa_t_init("make_install");

use Config;
use Test::More;
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan tests => 25;
# -------------------------------------------------------------------

use Cwd;
my $cwd = getcwd;
my $builddir = "$cwd/$workdir/d.$testname/build";
my $instbase = "$cwd/$workdir/d.$testname/inst";
$builddir = untaint_var($builddir);
$instbase = untaint_var($instbase);
rmtree($instbase, $builddir, { safe => 1 });
mkdirp($instbase);
mkdirp($builddir);

untaint_system("cd .. && make tardist >/dev/null");
$? == 0  or die "tardist failed: $?";
my $tarfile = untaint_cmd("cd .. && ls -tr Mail-SpamAssassin-*.tar* | tail -1");
chomp($tarfile);
system_or_die "cd $builddir && gunzip -cd $cwd/../$tarfile | tar xf -";
system_or_die "cd $builddir && mv Mail-SpamAssassin-* x";

# Figure out where 'bin' really is
my $binpath = $Config{sitebinexp};
$binpath =~ s|^\Q$Config{siteprefixexp}\E/||;

my $installarchlib = $Config{installarchlib};

#Fix for RH/Fedora using lib64 instead of lib - bug 6609
$x64_bit_lib_test = 0;
if (-e '/bin/rpm') {
  #More logic added from bug 6809
  #Are we running an RPM version of Perl?
  $command = "/bin/rpm -qf $^X";
 
  $output = untaint_cmd($command);
  if ($output =~ /not owned by any package/i) {
    #WE AREN'T RUNNING AN RPM VERSION OF PERL SO WILL ASSUME NO LIB64 DIR
    #is there a test we can run for this?
  } else {

    $command = '/bin/rpm --showrc';

    $output = untaint_cmd($command);

    foreach (split("\n", $output)) {
      if (/-\d+: _lib(dir)?\t(.*)$/) {
        if ($2 && $2 =~ /64/) {
          $x64_bit_lib_test++;
        }
      }
    }
  }
}

#Fix for x86/64 Gentoo
if (-e '/usr/bin/emerge' && -d '/usr/lib64') {
  $x64_bit_lib_test++;
}

if ($x64_bit_lib_test) {
  print "\nEnabling checks for 64 bit lib directories.\n";
} else {
  print "\nDisabling checks for 64 bit lib directories.\n";
}

# bug 8019 - substitute for File::Path:mkpath that can work in -T mode
sub mkdirp {
  my $dir = shift;
  return if (-d $dir);
  mkdirp(dirname($dir));
  mkdir $dir;
}

sub new_instdir {
  $instdir = $instbase.".".(shift);
  $instdir = untaint_var($instdir);
  print "\nsetting new instdir: $instdir\n";
  rmtree($instdir, { safe => 1 });
  mkdirp($instdir);
}

sub run_makefile_pl {
  my $args = $_[0];
  system_or_die "cd $builddir/x && $perl_cmd Makefile.PL ".
          "$args < /dev/null 2>&1";
  system_or_die "cd $builddir/x && make install 2>&1";
  print "current instdir: $instdir\n";
}

# -------------------------------------------------------------------
new_instdir(__LINE__);
my $prefix="$instdir/foo";
run_makefile_pl "PREFIX=$prefix";

ok -d "$prefix/$binpath";
if ($x64_bit_lib_test) {
  #print "testing for $prefix/lib64";
  ok -d "$prefix/lib64";
} elsif ( $installarchlib =~ '/libdata/' ) {
  ok -d "$prefix/libdata";
} else {
  ok -d "$prefix/lib";
}

ok -e "$prefix/share/spamassassin";
ok -e "$prefix/etc/mail/spamassassin";

# -------------------------------------------------------------------
new_instdir(__LINE__);
$prefix="$instdir/foo";
run_makefile_pl "PREFIX=$prefix LIB=$instdir/bar";

ok -d "$prefix/$binpath";
ok -e "$instdir/bar/Mail/SpamAssassin";
ok -e "$prefix/share/spamassassin";
ok -e "$prefix/etc/mail/spamassassin";

# -------------------------------------------------------------------
new_instdir(__LINE__);
$prefix="$instdir/foo";
run_makefile_pl "PREFIX=$prefix LIB=$instdir/bar DATADIR=$instdir/data";

ok -d "$prefix/$binpath";
ok -e "$instdir/bar/Mail/SpamAssassin";
ok -e "$instdir/data/sa-update-pubkey.txt";
ok !-e "$prefix/share/spamassassin";
ok -e "$prefix/etc/mail/spamassassin";

# -------------------------------------------------------------------
new_instdir(__LINE__);
$prefix="$instdir/foo";
run_makefile_pl "PREFIX=$prefix SYSCONFDIR=$instdir/sysconf";

ok -d "$prefix/$binpath";
ok -e "$instdir/sysconf/mail/spamassassin/local.cf";
ok -e "$prefix/share/spamassassin/sa-update-pubkey.txt";
ok !-e "$prefix/etc/mail/spamassassin";

# -------------------------------------------------------------------
new_instdir(__LINE__);
$prefix="$instdir/foo";
run_makefile_pl "PREFIX=$prefix CONFDIR=$instdir/conf";

ok -d "$prefix/$binpath";
ok -e "$instdir/conf/local.cf";
ok -e "$prefix/share/spamassassin/sa-update-pubkey.txt";
ok !-e "$prefix/etc/mail/spamassassin";

# -------------------------------------------------------------------
new_instdir(__LINE__);
$prefix="$instdir/dest/foo";
run_makefile_pl "DESTDIR=$instdir/dest PREFIX=/foo";

ok -d "$prefix/$binpath";
ok -d "$prefix/etc/mail/spamassassin";
if ($x64_bit_lib_test) {
  ok -d "$prefix/lib64";
} elsif ( $installarchlib =~ '/libdata/' ) {
  ok -d "$prefix/libdata";
} else {
  ok -d "$prefix/lib";
}
ok -e "$prefix/share/spamassassin/sa-update-pubkey.txt";

