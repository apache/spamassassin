#!/usr/bin/perl

my @locales = qw( de es fr it nl pl pl pt_BR );

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint");
use Test; BEGIN { plan tests => (scalar @locales) };

use SATest; sa_t_init("lang_lint");
use Test;

# ---------------------------------------------------------------------------

%patterns = ( q{  }, 'anything', );

for $locale (@locales) {
  $ENV{'LANGUAGE'} = $locale;

  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}
