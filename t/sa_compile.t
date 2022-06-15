#!/usr/bin/perl -T

###
### UTF-8 CONTENT, edit with UTF-8 locale/editor
###

use lib '.'; use lib 't';
$ENV{'TEST_PERL_TAINT'} = 'no';     # inhibit for this test
use SATest; sa_t_init("sa_compile");

use Config;

my $temp_binpath = $Config{sitebinexp};
$temp_binpath =~ s|^\Q$Config{siteprefixexp}\E/||;

use Test::More;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan skip_all => "RE2C isn't new enough" unless re2c_version_new_enough();
plan tests => 24;

# -------------------------------------------------------------------

use Cwd;
my $cwd = getcwd;
my $builddir = untaint_var("$cwd/$workdir/d.$testname/build");
my $instbase = untaint_var("$cwd/$workdir/d.$testname/inst");
rmtree("$instbase", "$builddir", { safe => 1 });
mkpath("$instbase", "$builddir", { error  => \my $err_list });

untaint_system("cd .. && make tardist >/dev/null");
$? == 0  or die "tardist failed: $?";
my $tarfile = untaint_cmd("cd .. && ls -tr Mail-SpamAssassin-*.tar* | tail -1");
chomp($tarfile);
system_or_die "cd $builddir && gunzip -cd $cwd/../$tarfile | tar xf -";
system_or_die "cd $builddir && mv Mail-SpamAssassin-* x";

&new_instdir("basic");
&run_makefile_pl ("PREFIX=$instdir SYSCONFDIR=$instdir/etc DATADIR=$instdir/share/spamassassin LOCALSTATEDIR=$instdir/var/spamassassin CONFDIR=$instdir/etc/mail/spamassassin");

# we now have an "installed" version we can run sa-compile with.  Ensure
# sarun() will use it appropriately
$scr = "$instdir/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"

&set_rules('
body FOO1 /You have been selected to receive/
body FOO2 /You have bee[n] selected to receive/
body FOO3 /You have bee(?:xyz|\x6e) selected to receive/
body FOO4 /./
body FOO5 /金融機/
body FOO6 /金融(?:xyz|機)/
body FOO7 /\xe9\x87\x91\xe8\x9e\x8d\xe6\xa9\x9f/
body FOO8 /.\x87(?:\x91|\x00)[\xe8\x00]\x9e\x8d\xe6\xa9\x9f/
# Test that meta rules work for sa-compiled body rules
# (loosely related to Bug 7987)
meta META1 FOO1 && FOO2 && FOO3 && FOO4
meta META2 FOO5 && FOO6 && FOO7 && FOO8
');

# ensure we don't use compiled rules
rmtree("$instdir/var/spamassassin/compiled", { safe => 1 });

%patterns = (
  qr/ check: tests=FOO1,FOO2,FOO3,FOO4,META1\n/, '',
);
%anti_patterns = (
  'zoom: able to use', '',
);
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 1' < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 0' < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  qr/ check: tests=FOO4,FOO5,FOO6,FOO7,FOO8,META2\n/, '',
);
%anti_patterns = (
  'zoom: able to use', '',
);
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 1' < $cwd/data/spam/unicode1 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 0' < $cwd/data/spam/unicode1 2>&1", \&patterns_run_cb);
ok_all_patterns();

# -------------------------------------------------------------------

rmtree( glob "~/.spamassassin/sa-compile.cache". { safe => 1 }); # reset test
system_or_die "TMP=$instdir TMPDIR=$instdir $instdir/$temp_binpath/sa-compile --quiet -p $cwd/$workdir/user.cf --keep-tmps -D 2>$instdir/sa-compile.debug";  # --debug
$scr = "$instdir/$temp_binpath/spamassassin";
$scr_localrules_args = $scr_cf_args = "";      # use the default rules dir, from our "install"

%patterns = (
  ' zoom: able to use 5/5 \'body_0\' compiled rules ', '',
  qr/ check: tests=FOO1,FOO2,FOO3,FOO4,META1\n/, '',
);
%anti_patterns = ();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 1' < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 0' < $cwd/data/spam/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  ' zoom: able to use 5/5 \'body_0\' compiled rules ', '',
  qr/ check: tests=FOO4,FOO5,FOO6,FOO7,FOO8,META2\n/, '',
);
%anti_patterns = ();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 1' < $cwd/data/spam/unicode1 2>&1", \&patterns_run_cb);
ok_all_patterns();
ok sarun ("-D check,zoom -L -t --cf 'normalize_charset 0' < $cwd/data/spam/unicode1 2>&1", \&patterns_run_cb);
ok_all_patterns();

# -------------------------------------------------------------------

# Cleanup after testing (todo, sa-compile should have option for userstatedir)
rmtree( glob "~/.spamassassin/sa-compile.cache". { safe => 1 }); # reset test

# -------------------------------------------------------------------

sub re2c_version_new_enough {
  #check if re2c exiss and if it is 0.12.0 or greater

  my $re2c_ver = untaint_cmd("re2c -V 2>&1");
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
  $instdir = untaint_var($instbase.".".(shift));
  print "\nsetting new instdir: $instdir\n";
  rmtree("$instdir", { safe => 1 });
  mkpath($instdir, { error => \my $listerrs });
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
  print RULES "use_bayes 0";
  print RULES $rules;
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

