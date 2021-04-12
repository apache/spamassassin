#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("mass_check");

use Test::More tests => 1;

# ---------------------------------------------------------------------------

mkdir "$workdir/mc_test";
mkdir "$workdir/mc_test/ham";
writetofile ("$workdir/mc_test/ham/1", "foo");

untaint_system "( cd ../masses; ".
    "$perl_path ./mass-check -n -o ham:dir:../t/$workdir/mc_test/ham".
    ")";
ok (($? >> 8) == 0);

exit;


sub writetofile {
  my ($f, $data) = @_;
  open (O, ">$f") or die "open $f failed";
  print O $data;
  close O or die "close $f failed";
}

