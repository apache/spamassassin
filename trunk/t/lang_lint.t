#!/usr/bin/perl

use lib '.'; use lib 't';
use vars qw(@locales);
use SATest; sa_t_init("lang_lint");
use Test; BEGIN { @locales = qw( de es fr it nl pl pl pt_BR );
                  plan tests => scalar @locales };

# ---------------------------------------------------------------------------

%patterns = ( q{  }, 'anything', );

for $locale (@locales) {
  $ENV{'LANGUAGE'} = $locale;

  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}
