#!/usr/bin/perl

use lib '.'; 
use lib 't';
use SATest; 
sa_t_init("razor2");

use constant HAS_RAZOR2 => eval { require Razor2::Client::Agent; };
use constant HAS_RAZOR2_IDENT => eval { -r $ENV{'HOME'}.'/.razor/identity'; };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Needs Razor2" unless HAS_RAZOR2;
plan skip_all => "Needs Razor2 Identity File Needed. razor-register / razor-admin -register has not been run, or identity file ($ENV{'HOME'}/.razor/identity) is unreadable." unless HAS_RAZOR2_IDENT;
plan tests => 2;

diag('Note: Failures may not be an SpamAssassin bug, as Razor tests can fail due to problems with the Razor servers.');

# ---------------------------------------------------------------------------

#report the email as spam so it fails below.  This process is not likely to work and I can't find a test point for razor. KAM 2018-08-20
#unless (HAS_RAZOR2 or HAS_RAZOR2_IDENT) {
#  system ("razor-report < data/spam/001");
#  if (($? >> 8) != 0) {
#    warn "'razor-report < data/spam/001' failed. This may cause this test to fail.\n";
#  }
#}

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Razor2
");

#RAZOR2 file was from real-world spam in August 2018

#TESTING FOR SPAM
%patterns = (
        q{ Listed in Razor2 }, 'spam',
            );

sarun ("-t < data/spam/razor2", \&patterns_run_cb);
ok_all_patterns();

#TESTING FOR HAM
%patterns = ();
%anti_patterns = (
	q{ Listed in Razor2 }, 'nonspam',
		 );

sarun ("-t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
