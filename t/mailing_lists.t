#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (

    q{ KNOWN_MAILING_LIST }, 'known_mailing_list'

);

ok (sarun ("-L -t < data/nice/ezmlm_message.txt", \&patterns_run_cb));
ok_all_patterns();

ok (sarun ("-L -t < data/nice/mailman_message.txt", \&patterns_run_cb));
ok_all_patterns();

ok (sarun ("-L -t < data/nice/mailman_reminder.txt", \&patterns_run_cb));
ok_all_patterns();

