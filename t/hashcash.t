#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("hashcash");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = (
q{ HASHCASH_24 }, 'hashcash24',
);

tstprefs ('
    hashcash_accept test@example.com
    hashcash_doublespend_path log/user_state/hashcash_seen
    ');

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
q{ HASHCASH_2SPEND }, '2spend',
);

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
