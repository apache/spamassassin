#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("cpp_comments_in_spamc");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------
# by simply reading the files directly in perl, we avoid all sorts
# of C-compilation portability issues...

my $ok = 1;
foreach my $f (<../spamc/*.c>, <../spamc/*.h>) {
  open (IN, "<$f");
  my $str = join('', <IN>);
  close IN;

  $str =~ s{/\*.*?\*/}{}gs;     # remove C comments
  $str =~ s{".*?"}{}gs;         # quoted strings

  if ($str =~ m{(.{0,99}//.{0,99})}s) {
    warn "found C-style comment: '$1' in $f";
    $ok = 0;
  }
}

ok ($ok);
