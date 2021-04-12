#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("check_implemented");

use Carp qw(croak);

use Test::More tests => 2;

# ---------------------------------------------------------------------------

use strict;
require Mail::SpamAssassin;

# kill all 'loadplugin' lines
foreach my $file 
        (<$localrules/*.pre>, <$siterules/*.pre>) #*/
{
  $file = main::untaint_var($file);
  rename $file, "$file.bak" or die "rename $file failed";
  open IN, "<$file.bak" or die "cannot read $file.bak";
  open OUT, ">$file" or die "cannot write $file";
  while (<IN>) {
    s/^\s*loadplugin/###loadplugin/g;
    print OUT;
  }
  close IN;
  close OUT;
}

my $sa = create_saobj({
  'dont_copy_prefs' => 1,
  'local_tests_only' => 1
});

$sa->init(1);
ok($sa);

open (IN, "<data/spam/009");
my $mail = $sa->parse(\*IN);
close IN;

$SIG{'__WARN__'} = sub {
  return if /no loaded plugin/;
  print STDERR @_;
};

eval {
  my $status = $sa->check($mail);
  ok 0;       # should never get this far
};

print "got warning: '$@'\n";
ok ($@ =~ /no loaded plugin implements/);

