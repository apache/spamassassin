#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("hashcash");

# we need DB_File to support the double-spend db.
use constant HAS_DB_FILE => eval { require DB_File; };

use Test; BEGIN { plan tests => HAS_DB_FILE ? 4 : 0 };

exit unless HAS_DB_FILE;

# ---------------------------------------------------------------------------

%patterns = (
q{ HASHCASH_24 }, 'hashcash24',
);

tstprefs ('
    hashcash_accept test@example.com test1@example.com test2@example.com
    hashcash_doublespend_path log/user_state/hashcash_seen
    ');

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
q{ HASHCASH_20 }, 'hashcash20',
);

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
q{ HASHCASH_2SPEND }, '2spend',
);

sarun ("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

# try again with a mail with 2 tokens, one unspent.
%patterns = ();
%anti_patterns = (
q{ HASHCASH_2SPEND }, '2spend',
);
sarun ("-L -t < data/nice/016", \&patterns_run_cb);
ok_all_patterns();

