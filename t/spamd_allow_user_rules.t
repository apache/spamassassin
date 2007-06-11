#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_allow_user_rules");
use Test;

BEGIN { 

  plan tests => ($SKIP_SPAMD_TESTS ? 0 : 5)

};

exit if $SKIP_SPAMD_TESTS;

# ---------------------------------------------------------------------------

%patterns = (

q{ 1.0 MYFOO }, 'myfoo',

);

%anti_patterns = (
q{  redefined at }, 'redefined_errors_in_spamd_log',
);

tstlocalrules ("
	allow_user_rules 1
");

rmtree ("log/virtualconfig/testuser", 0, 1);
mkpath ("log/virtualconfig/testuser", 0, 0755);
open (OUT, ">log/virtualconfig/testuser/user_prefs");
print OUT "
	header MYFOO Content-Transfer-Encoding =~ /quoted-printable/
";
close OUT;

ok (start_spamd ("--virtual-config-dir=log/virtualconfig/%u -L -u $current_user"));
ok (spamcrun ("-u testuser < data/spam/009", \&patterns_run_cb));
ok (stop_spamd ());

checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

