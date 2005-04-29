#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spf");
use Test;

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_SPFQUERY => eval { require Mail::SPF::Query; };
# Do not run this test on non-Linux unices as root, due to a bug
# in Sys::Hostname::Long (which Mail::Query::SPF uses.)
# See <http://bugzilla.spamassassin.org/show_bug.cgi?id=3806>
use constant IS_LINUX   => $^O eq 'linux';
use constant IS_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);
use constant AM_ROOT    => $< == 0;

use constant DO_RUN     => TEST_ENABLED && HAS_SPFQUERY &&
                                        !(AM_ROOT &&
                                          !(IS_LINUX || IS_WINDOWS));

BEGIN {
  
  plan tests => (DO_RUN ? 8 : 0);

};

exit unless (DO_RUN);

# ---------------------------------------------------------------------------

%patterns = (
    q{ SPF_HELO_PASS }, 'helo_pass',
    q{ SPF_PASS }, 'pass',
);

sarun ("-t < data/nice/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
    q{ SPF_NEUTRAL }, 'neutral',
    q{ SPF_HELO_NEUTRAL }, 'helo_neutral',
);

sarun ("-t < data/spam/spf1", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
    q{ SPF_SOFTFAIL }, 'softfail',
    q{ SPF_HELO_SOFTFAIL }, 'helo_softfail',
);

sarun ("-t < data/spam/spf2", \&patterns_run_cb);
ok_all_patterns();
%patterns = (
    q{ SPF_FAIL }, 'fail',
    q{ SPF_HELO_FAIL }, 'helo_fail',
);

sarun ("-t < data/spam/spf3", \&patterns_run_cb);
ok_all_patterns();
