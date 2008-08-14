#!/usr/bin/perl

use lib '.'; use lib 't';
use vars qw(@locales);
use SATest; sa_t_init("lang_lint");

use constant TEST_ENABLED => conf_bool('run_long_tests');

use Test; BEGIN {
  @locales = qw( de es fr it nl pl pl pt_BR );
  plan tests => (TEST_ENABLED ? scalar(@locales) : 0);
};
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

%patterns = ( q{  }, 'anything', );

for $locale (@locales) {
  $ENV{'LANGUAGE'} = $locale;

  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}
