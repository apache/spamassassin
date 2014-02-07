#!/usr/bin/perl

use lib '.'; use lib 't';

use SATest; sa_t_init("db_based_whitelist_ips");
use Test;

use constant TEST_ENABLED => conf_bool('run_long_tests');
BEGIN { 
  plan tests => (TEST_ENABLED ? 8 : 0);
};
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

%is_nonspam_patterns = (
q{ Subject: Re: [SAtalk] auto-whitelisting}, 'subj',
);
%is_spam_patterns = (
q{ X-Spam-Status: Yes}, 'status',
);

%patterns = %is_nonspam_patterns;

ok (sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));

# 3 times, to get into the whitelist:
ok (sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok (sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok (sarun ("-L -t < data/nice/002", \&patterns_run_cb));

# Now check
ok (sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_spam_patterns;
ok (sarun ("-L -t < data/spam/007", \&patterns_run_cb));
ok_all_patterns();

