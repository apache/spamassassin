#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc");
use Test; plan tests => ($NO_SPAMC_EXE ? 0 : 2);

exit if $NO_SPAMC_EXE;
# ---------------------------------------------------------------------------

%patterns = (

q{ hello world }, 'spamc',

);

# connect on port 9 (discard): should always fail
ok (scrun ("-p 9 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

