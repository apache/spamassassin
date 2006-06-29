#!/usr/bin/perl

use Data::Dumper;
use lib '.'; use lib 't';
use SATest; sa_t_init("recreate");
use Test;

BEGIN { 
  if (-e 't/test_dir') {
    chdir 't';
  }

  if (-e 'test_dir') {
    unshift(@INC, '../blib/lib');
  }

  plan tests => 9;
};

use strict;
use warnings;
use Mail::SpamAssassin;

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

our $warning = 0;

$SIG{'__WARN__'} = sub {
  print STDERR @_;

  # certain warnings can be ignored for this test
  if ($_[0] =~ m{plugin: failed to parse plugin.*: Can.t locate })
  {
    print STDERR "[ignored warning, not recreate-related]\n";
  } else {
    ++$warning; 
  }
};

my $spamtest = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});

# remove all plugin .pm files.  This should be ok as long as they are
# being loaded with 'tryplugin' instead of 'loadplugin'
unlink(<$prefix/t/log/test_rules_copy/*.pm>);

$spamtest->init(0); # parse rules
ok($spamtest);
open (IN, "<data/spam/009");
my $dataref = [<IN>];
close IN;
my $mail   = $spamtest->parse($dataref);
ok($mail);
my $status = $spamtest->check($mail);
ok($status);
my $output = $status->get_report();
ok($output);

$status->finish();
$mail->finish();
$spamtest->finish();

$spamtest = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});

$spamtest->init(0); # parse rules
ok($spamtest);
$mail   = $spamtest->parse($dataref);
ok($mail);
$status = $spamtest->check($mail);
ok($status);
$output = $status->get_report();
ok($output);

ok($warning == 0);
