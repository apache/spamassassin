#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spf");
use Test;

use constant HAS_SPFQUERY => eval { require Mail::SPF::Query; };

BEGIN {
  
  plan tests => (HAS_SPFQUERY ? 2 : 0);

};

exit unless HAS_SPFQUERY;

# ---------------------------------------------------------------------------

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

tstprefs("
meta SPF_HELO_PASS __SPF_HELO_PASS
meta SPF_PASS __SPF_PASS
");

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

