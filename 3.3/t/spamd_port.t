#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_port");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 4) };

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',


);

my $port = probably_unused_spamd_port();
ok(sdrun ("-L -p $port", "-p $port < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
