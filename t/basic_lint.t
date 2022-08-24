#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint");

use Test::More;

@test_locales = qw(C);

if (!$RUNNING_ON_WINDOWS) {
  # Test with few random additional locales if available
  my $locales = untaint_cmd("locale -a");
  while ($locales =~ /^((?:C|en_US|fr_FR|zh_CN)\.(?:utf|iso|gb).*)$/gmi) {
    push @test_locales, $1;
  }
}

plan tests => scalar(@test_locales);

# ---------------------------------------------------------------------------

%patterns = (
  qr/^/, 'anything',
);

foreach my $locale (@test_locales) {
  my $language = $locale;
  $language =~ s/[._].*//;
  $ENV{'LANGUAGE'} = $language;
  $ENV{'LC_ALL'} = $locale;
  sarun ("-L --lint", \&patterns_run_cb);
  ok_all_patterns();
}

