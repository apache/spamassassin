#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_allow_user_rules");
use Test; BEGIN { plan tests => 5 };

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

system ("rm -rf log/virtualconfig/testuser");
system ("mkdir -p log/virtualconfig/testuser");
open (OUT, ">log/virtualconfig/testuser/user_prefs");
print OUT "
	header MYFOO Content-Transfer-Encoding =~ /quoted-printable/
";
close OUT;

ok (start_spamd ("--virtual-config-dir=log/virtualconfig/%u -L"));
ok (spamcrun ("-u testuser < data/spam/009", \&patterns_run_cb));
ok (stop_spamd ());

checkfile ("spamd_allow_user_rules.spamd", \&patterns_run_cb);
ok_all_patterns();

