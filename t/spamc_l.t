#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_l");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{ hello world }, 'spamc_l',
q{ spamc: connect(AF_INET) to spamd at 127.0.0.1 failed, retrying (#1 of 3): Connection refused }, 'connfailed',

);

# connect on port 9 (discard): should always fail
ok (scrunwithstderr ("-l -p 9 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

