#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("whitelist_addrs");

use constant HAS_DB_FILE => eval { require DB_File; };

use Test; BEGIN { plan tests => (HAS_DB_FILE ? 5 : 0); };
exit unless HAS_DB_FILE;

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


