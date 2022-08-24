#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("ifversion");
use Test::More tests => 4;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1000 GTUBE }, '',
  q{ 1.0 SHOULD_BE_CALLED }, ''
);

%anti_patterns = (
  q{ SHOULD_NOT_BE_CALLED }, ''
);

tstlocalrules ("
  if (version > 9.99999)
    body SHOULD_NOT_BE_CALLED /./
  endif
  if (version <= 9.99999)
    body SHOULD_BE_CALLED /./
  endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

