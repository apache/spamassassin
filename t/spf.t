#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spf");
use Test;

use constant TEST_ENABLED => (-e 't/do_net');
use constant HAS_SPFQUERY => eval { require Mail::SPF::Query; };
# Do not run this test on non-Linux unices as root, due to a bug
# in Sys::Hostname::Long (which Mail::Query::SPF uses.)
use constant IS_LINUX   => $^O eq 'linux';
use constant AM_ROOT    => $< == 0;

use constant DO_RUN     => TEST_ENABLED && HAS_SPFQUERY &&
                                        !(AM_ROOT && !IS_LINUX);

BEGIN {
  
  plan tests => (DO_RUN ? 2 : 0);

};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

