#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_plugin");

use constant numtests => 7;
use Test; BEGIN { plan tests => ((!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS) ?
                        numtests : 0) };

exit unless (!$SKIP_SPAMD_TESTS && !$RUNNING_ON_WINDOWS);

# ---------------------------------------------------------------------------

tstlocalrules ('
    hashcash_accept test@example.com test1@example.com test2@example.com
    hashcash_doublespend_path log/user_state/hashcash_seen
');

start_spamd("-D -L --socketpath=log/spamd.sock");

%patterns = (
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
);
ok (spamcrun ("-U log/spamd.sock < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
q{ HASHCASH_24 }, 'hashcash24',
);
ok (spamcrun ("-U log/spamd.sock < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
q{ HASHCASH_20 }, 'hashcash20',
);
ok (spamcrun ("-U log/spamd.sock < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

stop_spamd();


