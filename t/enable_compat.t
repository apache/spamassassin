#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("enable_compat");
use Test::More tests => 6;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 ANY_RULE }, '',
  q{ 1.0 COMPAT_RULE }, '',
);
%anti_patterns = ();

tstprefs("
  enable_compat foo_testing
  body ANY_RULE /./
  if can(Mail::SpamAssassin::Conf::compat_foo_testing)
    body COMPAT_RULE /EVOLUTION/
  endif
");

ok (sarun ("-t -L < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 ANY_RULE }, '',
);
%anti_patterns = (
  q{ 1.0 COMPAT_RULE }, '',
);

tstprefs("
  body ANY_RULE /./
  if can(Mail::SpamAssassin::Conf::compat_foo_testing)
    body COMPAT_RULE /EVOLUTION/
  endif
");

ok (sarun ("-t -L < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

