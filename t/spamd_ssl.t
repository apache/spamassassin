#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_ssl");
use Test; plan tests => (($SKIP_SPAMD_TESTS || !$SSL_AVAILABLE) ? 0 : 7);

exit if ($SKIP_SPAMD_TESTS || !$SSL_AVAILABLE);

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, score=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ FROM_ENDS_IN_NUMS}, 'endsinnums',
q{ NO_REAL_NAME}, 'noreal',


);

ok (sdrun ("-L --ssl --server-key data/etc/testhost.key --server-cert data/etc/testhost.cert",
           "-S < data/spam/001",
           \&patterns_run_cb));
ok_all_patterns();

