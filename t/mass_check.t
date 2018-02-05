#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("mass_check");

use Test::More tests => 1;

# ---------------------------------------------------------------------------

mkdir "log/mc_test";
mkdir "log/mc_test/ham";
writetofile ("log/mc_test/ham/1", "foo");

system "( cd ../masses; ".
    "$perl_path ./mass-check -n -o ham:dir:../t/log/mc_test/ham".
    ")";
ok (($? >> 8) == 0);

exit;


sub writetofile {
  my ($f, $data) = @_;
  open (O, ">$f") or die "open $f failed";
  print O $data;
  close O or die "close $f failed";
}

