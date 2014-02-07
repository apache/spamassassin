#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_H");

# only run for localhost!
our $DO_RUN = conf_bool('run_net_tests')
                    && !$SKIP_SPAMD_TESTS
                    && ($spamdhost eq '127.0.0.1');

use Test; plan tests => ($DO_RUN ? 5 : 0);

exit unless $DO_RUN;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Flag: YES}, 'flag',
q{ TEST_ENDSNUMS}, 'endsinnums',

);

ok(start_spamd("-L"));

$spamdhost = 'multihomed.dnsbltest.spamassassin.org';
ok(spamcrun("--connect-retries=100 -H < data/spam/001",
            \&patterns_run_cb));
ok_all_patterns();
ok(stop_spamd());
