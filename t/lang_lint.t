#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("lang_lint");

use Test::More;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');
plan tests => 8;

# ---------------------------------------------------------------------------

my  @locales = qw( de es fr it nl pl pl pt_BR );
%patterns = ( q{  }, 'anything', );

for $locale (@locales) {
  $ENV{'LANGUAGE'} = $locale;

  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}
