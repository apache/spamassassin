#!/usr/bin/perl -T

use lib '.'; 
use lib 't';
use SATest; 
sa_t_init("pyzor");

use constant HAS_PYZOR => eval { $_ = untaint_cmd("which pyzor"); chomp; -x };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Pyzor executable not found in path" unless HAS_PYZOR;
plan tests => 4;

diag('Note: Failures may not be an SpamAssassin bug, as Pyzor tests can fail due to problems with the Pyzor servers.');

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::Pyzor
pyzor_timeout 10
dns_available no
");

#PYZOR file was from real-world spam in October 2018

#TESTING FOR SPAM
%patterns = (
        q{ Listed in Pyzor }, 'spam',
            );

sarun ("-t < data/spam/pyzor", \&patterns_run_cb);
ok_all_patterns();
# Same with fork
sarun ("--cf='pyzor_fork 1' -t < data/spam/pyzor", \&patterns_run_cb);
ok_all_patterns();

#TESTING FOR HAM
%patterns = ();
%anti_patterns = (
	q{ Listed in Pyzor }, 'nonspam',
		 );

sarun ("-t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
# same with fork
sarun ("--cf='pyzor_fork 1' -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
