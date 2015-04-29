#!/usr/bin/perl

use lib '.'; use lib 't';
$ENV{'TEST_PERL_TAINT'} = 'no';     # inhibit for this test
use SATest; sa_t_init("sa_compile");
use Test;
use Config;
use File::Basename;
use File::Path qw/mkpath/;

my $temp_binpath = $Config{sitebinexp};
$temp_binpath =~ s/^\Q$Config{prefix}\E//;

# called from BEGIN
sub re2c_version_new_enough {

  my $re2c_ver = `re2c -V 2>&1`;
  if (!defined $re2c_ver || $re2c_ver =~ /^$/) {
    print "re2c not found, or 're2c -V' not supported, skipping test\n";
    return;
  }

  chop $re2c_ver;
  my $newenough = ($re2c_ver+0 >= 001200);   # 0.12.0 seems safe enough as a baseline
  print "re2c version ($re2c_ver) new enough? ".($newenough ? "yes" : "no")."\n";
  return $newenough;
}

use constant TEST_ENABLED => conf_bool('run_long_tests')
                                && re2c_version_new_enough();

BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }
  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => ((TEST_ENABLED && !$RUNNING_ON_WINDOWS) ? 5 : 0);
};

exit unless (TEST_ENABLED && !$RUNNING_ON_WINDOWS);

# -------------------------------------------------------------------

my $INST_FROM_SCRATCH = 1;      # set to 0 to short-circuit
#my $INST_FROM_SCRATCH = 0;      # set to 0 to short-circuit

sub system_or_die;
use Cwd;
my $cwd = getcwd;
my $builddir = "$cwd/log/d.$testname/build";
my $instbase = "$cwd/log/d.$testname/inst";

if ($INST_FROM_SCRATCH) {
  system_or_die "cd .. && make tardist";
  system("rm -rf $builddir");
  system("mkdir -p $builddir");
  system_or_die "cd $builddir && gunzip -c $cwd/../Mail-SpamAssassin-*.tar.gz | tar xf -";
  system_or_die "cd $builddir && mv Mail-SpamAssassin-* x";
}

sub new_instdir {
  $instdir = $instbase.".".(shift);
  print "\nsetting new instdir: $instdir\n";
  $INST_FROM_SCRATCH and system("rm -rf $instdir; mkdir $instdir");
}

sub run_makefile_pl {
  my $args = $_[0];
  system_or_die "cd $builddir/x && $perl_cmd Makefile.PL ".
          "$args < /dev/null 2>&1";
  system_or_die "cd $builddir/x && make install 2>&1";
  print "current instdir: $instdir\n";
}

sub set_rules {
  my $rules = shift;

  #Create the dir for the cf file
  my $file = "$instdir/foo/share/spamassassin/20_testrules.cf";
  my $dir = dirname($file);
  mkpath($dir);

  open RULES, ">$file"
          or die "cannot write $file - $!";
  print RULES qq{

    use_bayes 0

    $rules

  };
  close RULES or die;

  #Create the dir for the pre file
  $file = "$instdir/foo/etc/mail/spamassassin/v330.pre";
  $dir = dirname($file);
  mkpath($dir);

  open RULES, ">$file"
          or die "cannot write $file - $!";
  print RULES qq{

    loadplugin Mail::SpamAssassin::Plugin::MIMEHeader
    loadplugin Mail::SpamAssassin::Plugin::ReplaceTags
    loadplugin Mail::SpamAssassin::Plugin::Check
    loadplugin Mail::SpamAssassin::Plugin::HTTPSMismatch
    loadplugin Mail::SpamAssassin::Plugin::URIDetail
    loadplugin Mail::SpamAssassin::Plugin::Bayes
    loadplugin Mail::SpamAssassin::Plugin::BodyEval
    loadplugin Mail::SpamAssassin::Plugin::DNSEval
    loadplugin Mail::SpamAssassin::Plugin::HTMLEval
    loadplugin Mail::SpamAssassin::Plugin::HeaderEval
    loadplugin Mail::SpamAssassin::Plugin::MIMEEval
    loadplugin Mail::SpamAssassin::Plugin::RelayEval
    loadplugin Mail::SpamAssassin::Plugin::URIEval
    loadplugin Mail::SpamAssassin::Plugin::WLBLEval
    loadplugin Mail::SpamAssassin::Plugin::Rule2XSBody

  };
  close RULES or die;
}

# -------------------------------------------------------------------

new_instdir("basic");
$INST_FROM_SCRATCH and run_makefile_pl "PREFIX=$instdir/foo";

# we now have an "installed" version we can run sa-compile with.  Ensure
# sarun() will use it appropriately
$scr = "$instdir/foo/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"

set_rules q{

  body FOO /You have been selected to receive/

};

# ensure we don't use compiled rules
system("rm -rf $instdir/foo/var/spamassassin/compiled");
%patterns = (

  q{ check: tests=FOO }, 'FOO'

);
ok sarun ("-D -Lt < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

# -------------------------------------------------------------------

system_or_die "$instdir/foo/$temp_binpath/sa-compile --keep-tmps";  # --debug
%patterns = (

  q{ able to use 1/1 'body_0' compiled rules }, 'able-to-use',
  q{ check: tests=FOO }, 'FOO'

);
$scr = "$instdir/foo/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"
ok sarun ("-D -Lt < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

# -------------------------------------------------------------------

