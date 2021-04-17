#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint");

@test_locales = qw(C);
# Test with few random additional locales if available
my $locales = untaint_cmd("locale -a");
while ($locales =~ /^((?:C|en_US|fr_FR|zh_CN)\.(?:utf|iso|gb).*)$/gmi) {
  push @test_locales, $1;
}

use Test::More;
plan tests => scalar(@test_locales);

# ---------------------------------------------------------------------------

%patterns = (
  q{  }, 'anything',
);

foreach my $locale (@test_locales) {
  my $language = $locale;
  $language =~ s/[._].*//;
  $ENV{'LANGUAGE'} = $language;
  $ENV{'LC_ALL'} = $locale;
  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}

