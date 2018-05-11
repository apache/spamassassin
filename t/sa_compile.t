#!/usr/bin/perl

use lib '.'; 
use lib 't';

$ENV{'TEST_PERL_TAINT'} = 'no';     # inhibit for this test
use SATest; 

sa_t_init("sa_compile");

use Config;
use File::Basename;
use File::Path qw/mkpath/;

my $temp_binpath = $Config{sitebinexp};
$temp_binpath =~ s|^\Q$Config{siteprefixexp}\E/||;

use Test::More;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan skip_all => "RE2C isn't new enough" unless re2c_version_new_enough();
plan tests => 5;

BEGIN {
  if (-e 't/test_dir') {
    chdir 't';
  }
  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }
}

# -------------------------------------------------------------------

use Cwd;
my $cwd = getcwd;
my $builddir = "$cwd/log/d.$testname/build";
my $instbase = "$cwd/log/d.$testname/inst";

print "\nMaking tar dist file and then untarring it.\n";

system_or_die "cd .. && make tardist 2>&1 > /dev/null";
system("rm -rf $builddir");
system("mkdir -p $builddir");
system_or_die "cd $builddir && gunzip -c $cwd/../Mail-SpamAssassin-*.tar.gz | tar xf - ";
system_or_die "cd $builddir && mv Mail-SpamAssassin-* x";

&new_instdir("basic");
&run_makefile_pl ("PREFIX=$instdir SYSCONFDIR=$instdir/etc DATADIR=$instdir/share/spamassassin LOCALSTATEDIR=$instdir/var/spamassassin CONFDIR=$instdir/etc/mail/spamassassin");

# we now have an "installed" version we can run sa-compile with.  Ensure
# sarun() will use it appropriately
$scr = "$instdir/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"

&set_rules("body FOO /You have been selected to receive/");

# ensure we don't use compiled rules
system("rm -rf $instdir/var/spamassassin/compiled");

%patterns = (

  q{ check: tests=FOO }, 'FOO'

);

print "\nRunning spam checks uncompiled\n";
ok sarun ("-D -Lt < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

clear_pattern_counters();

# -------------------------------------------------------------------

print "\nRunning spam checks compiled\n";
system_or_die "$instdir/$temp_binpath/sa-compile --keep-tmps 2>&1";  # --debug
%patterns = (

  q{ able to use 1/1 'body_0' compiled rules }, 'able-to-use',
  q{ check: tests=FOO }, 'FOO'

);
$scr = "$instdir/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"

ok sarun ("-D -Lt < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

# -------------------------------------------------------------------

sub re2c_version_new_enough {
  #check if re2c exiss and if it is 0.12.0 or greater

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

sub new_instdir {
  $instdir = $instbase.".".(shift);
  print "\nsetting new instdir: $instdir\n";
  system("rm -rf $instdir; mkdir $instdir");
}

sub run_makefile_pl {
  my $args = $_[0];

  foreach (sort keys %ENV) { 
    print "ENV: $_  =  $ENV{$_}\n"; 
  }

  print "DEBUG: Arguments are $args\n";
  &system_or_die("cd $builddir/x && $perl_cmd Makefile.PL $args < /dev/null 2>&1");
  print "DEBUG: making\n";
  &system_or_die("cd $builddir/x && MAKEFLAGS='' make 2>&1");
  print "DEBUG: Install\n";
  &system_or_die("cd $builddir/x && MAKEFLAGS='' make install 2>&1");

  
}

sub set_rules {
  my $rules = shift;

  #Create the dir for the cf file
  my $file = "$instdir/share/spamassassin/20_testrules.cf";
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

  $file = "$instdir/etc/mail/spamassassin/v330.pre";
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
