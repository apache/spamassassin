#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint_without_plugins");

use Test::More;

plan tests => 4;

# ---------------------------------------------------------------------------

%patterns = (
  qr/^/, 'anything',
);
%anti_patterns = (
  q{ . }, 'should be silent on success',
);

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

# Comment out any loadplugin other than Check
foreach $tainted (<$workdir/*/*.pre>) {
  $tainted =~ /(.*)/;
  my $file = $1;
  open(IN, $file)  or die;
  open(OUT, ">$file.tmp")  or die;
  while (<IN>) {
    s/^loadplugin(?!.*::Check\b)/#loadplugin/;
    print OUT $_  or die;
  }
  close OUT  or die;
  close IN  or die;
  rename("$file.tmp", "$file")  or die;
}
# Just want to test sa-update rules
unlink("$localrules/01_test_rules.cf");
unlink("$localrules/99_test_default.cf");

sarun ("--lint", \&patterns_run_cb);
ok_all_patterns();
sarun ("--lint --net", \&patterns_run_cb);
ok_all_patterns();

