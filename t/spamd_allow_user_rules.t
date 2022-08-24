#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_allow_user_rules");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 5;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 MYFOO }, 'myfoo',
);

%anti_patterns = (
  'redefined at', 'redefined_errors_in_spamd_log',
);

tstprefs ("
  allow_user_rules 1
  loadplugin myTestPlugin ../../../data/testplugin.pm
");

rmtree ("$workdir/virtualconfig/testuser", 0, 1);
mkpath ("$workdir/virtualconfig/testuser", 0, 0755);
open (OUT, ">$workdir/virtualconfig/testuser/user_prefs");
print OUT q{

	header MYFOO Content-Transfer-Encoding =~ /quoted-printable/
        header MYHEADEVAL eval:check_return_2()

        # bug 5445
        urirhsbl  URIBL_DYNAMIC_MPRHS  dynamic.rhs.mailpolice.com.   A
        body      URIBL_DYNAMIC_MPRHS  eval:check_uridnsbl('URIBL_DYNAMIC_MPRHS')
        describe  URIBL_DYNAMIC_MPRHS  Contains a URL listed in the MailPolice dynamic domains list
        tflags    URIBL_DYNAMIC_MPRHS  net
        priority  URIBL_DYNAMIC_MPRHS  -100
        score     URIBL_DYNAMIC_MPRHS  0.5

        body MYBAR /bar/
        body MYBODYEVAL eval:check_return_2()
        rawbody MYRAWBAR /bar/
        rawbody MYRAWBODYEVAL eval:check_return_2()
        uri MYURI /uri/
        full MYFULLBAR /bar/
        full MYFULLEVAL eval:check_return_2()

        meta MYMETA (MYBAR && MYFULLBAR && MYHEADEVAL)

};
close OUT;

ok (start_spamd ("--virtual-config-dir=$workdir/virtualconfig/%u -L -u $spamd_run_as_user"));
ok (spamcrun ("-u testuser < data/spam/009", \&patterns_run_cb));
ok (stop_spamd ());

checkfile ($spamd_stderr, \&patterns_run_cb);
ok_all_patterns();

