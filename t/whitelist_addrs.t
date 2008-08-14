#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_addrs");

use constant TEST_ENABLED => conf_bool('run_long_tests');

use Test;
BEGIN { plan tests => TEST_ENABLED ? 5 : 0 };
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

%no_patterns = ( );
%is_nonspam_patterns = (
q{X-Spam-Status: No}, 'spamno',
);
%is_spam_patterns = (
q{X-Spam-Status: Yes}, 'spamyes',
);


%patterns = %no_patterns;
sarun ("--add-addr-to-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb);
%patterns = %is_nonspam_patterns;
ok (sarun ("-L < data/nice/002", \&patterns_run_cb));
ok_all_patterns();
%patterns = %is_nonspam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

%patterns = %no_patterns;
sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb);
%patterns = %is_spam_patterns;
sarun ("-L < data/spam/004", \&patterns_run_cb);
ok_all_patterns();

%patterns = %no_patterns;
sarun ("--add-addr-to-blacklist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb);
%patterns = %is_spam_patterns;
sarun ("-L < data/nice/002", \&patterns_run_cb);
ok_all_patterns();

