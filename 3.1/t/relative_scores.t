#!/usr/bin/perl

# Leave this part, or else it'll use the live modules which is BAD!
BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib', '.');
  }
}

use SATest; sa_t_init("relative_scores");
use Test;
use strict;
use vars qw/ $error /;

tstlocalrules ("
	# test that a single relative score applies to all scoresets
	body FOO /foo/
	score FOO 1 2 3 4
	score FOO (1)

	# test that multiple relative scores apply to the scoresets
	# appropriately, also that # and #.0 are equal
	body BAR /bar/
	score BAR 1
	score BAR (1.0) (2) (3) (4.0)

	# verify that negative decimal versions work
	body BAZ /bar/
	score BAZ 1
	score BAZ (-1.0) (-2.1) (-3.2) (-4.3)
");

my $sa = create_saobj();

$sa->init(0); # parse rules

plan tests => 4;

ok($sa);

# FOO should have an escalating score 2..5
$error = 1;
foreach my $index (0..3) {
  my $shouldbe = 2+$index;
  if ($sa->{conf}->{scoreset}->[$index]->{'FOO'} != $shouldbe) {
    $error = 0;
    warn "scoreset $index should have FOO score of $shouldbe, actually ".
    	($sa->{conf}->{scoreset}->[$index]->{'FOO'})."\n";
  }
}
ok($error);

# BAR should have an escalating score 2..5
$error = 1;
foreach my $index (0..3) {
  my $shouldbe = 2+$index;
  if ($sa->{conf}->{scoreset}->[$index]->{'BAR'} != $shouldbe) {
    $error = 0;
    warn "scoreset $index should have BAR score of $shouldbe, actually ".
    	($sa->{conf}->{scoreset}->[$index]->{'BAR'})."\n";
  }
}
ok($error);

# BAZ should have an descenting score 0, -1.1, -2.2, -3.3
$error = 1;
foreach my $index (0..3) {
  my $shouldbe = 1 - ($index+1 + $index/10);
  if ($sa->{conf}->{scoreset}->[$index]->{'BAZ'} != $shouldbe) {
    $error = 0;
    warn "scoreset $index should have BAZ score of $shouldbe, actually ".
    	($sa->{conf}->{scoreset}->[$index]->{'BAZ'})."\n";
  }
}
ok($error);
