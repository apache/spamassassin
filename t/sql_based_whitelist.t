#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest;

use constant TEST_ENABLED => (-e 't/sql_based_whitelist.cf'
                              || -e 'sql_based_whitelist.cf');

use Test;

BEGIN { plan tests => (TEST_ENABLED ? 10 : 0),
        onfail => sub {
            warn "\n\nNote: Failure may be due to an incorrect config";
        }
    };

exit unless TEST_ENABLED;

sa_t_init("sql_based_whitelist");

open(CONFIG,"<sql_based_whitelist.cf");
while (my $line = <CONFIG>) {
  $dbconfig .= $line;
}
close(CONFIG);

tstlocalrules ("
auto_whitelist_factory Mail::SpamAssassin::SQLBasedAddrList
$dbconfig
");

# ---------------------------------------------------------------------------

%is_nonspam_patterns = (
q{ Subject: Re: [SAtalk] auto-whitelisting}, 'subj',
);
%is_spam_patterns = (
q{Subject: 4000           Your Vacation Winning !}, 'subj',
);

%is_spam_patterns2 = (
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
ok (sarun ("-L -t < data/spam/004", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_spam_patterns2;
ok (sarun ("-L -t < data/spam/007", \&patterns_run_cb));
ok_all_patterns();
