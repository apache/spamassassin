#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest;

use constant TEST_ENABLED => conf_bool('run_awl_sql_tests');

use Test;

BEGIN { plan tests => (TEST_ENABLED ? 11 : 0),
        onfail => sub {
            warn "\n\nNote: Failure may be due to an incorrect config";
        }
    };

exit unless TEST_ENABLED;

sa_t_init("sql_based_whitelist");

my $dbconfig = '';
foreach my $setting (qw(
                  user_awl_dsn
                  user_awl_sql_username
                  user_awl_sql_password
                  user_awl_sql_table
                ))
{
  my $val = conf($setting);
  $dbconfig .= "$setting $val\n" if $val;
}

my $testuser = 'tstusr.'.$$.'.'.time();

tstlocalrules ("
use_auto_whitelist 1
auto_whitelist_factory Mail::SpamAssassin::SQLBasedAddrList
$dbconfig
user_awl_sql_override_username $testuser
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

ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));

# 3 times, to get into the whitelist:
ok(sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok(sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok(sarun ("-L -t < data/nice/002", \&patterns_run_cb));

# Now check
ok(sarun ("-L -t < data/nice/002", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_spam_patterns;
ok(sarun ("-L -t < data/spam/004", \&patterns_run_cb));
ok_all_patterns();

%patterns = %is_spam_patterns2;
ok(sarun ("-L -t < data/spam/007", \&patterns_run_cb));
ok_all_patterns();

ok(sarun ("--remove-addr-from-whitelist whitelist_test\@whitelist.spamassassin.taint.org", \&patterns_run_cb));
