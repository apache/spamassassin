#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("pyzor");

use constant HAS_PYZOR => eval { $_ = untaint_cmd("which pyzor"); chomp; -x };

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Pyzor executable not found in path" unless HAS_PYZOR;
plan tests => 8;

diag('Note: Failures may not be an SpamAssassin bug, as Pyzor tests can fail due to problems with the Pyzor servers.');

# ---------------------------------------------------------------------------

tstprefs ("
  dns_available no
  use_pyzor 1
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
%patterns = (
  'pyzor: got response: public.pyzor.org' => 'response',
  'pyzor: result: COUNT=0' => 'zerocount',
);
%anti_patterns = (
  q{ Listed in Pyzor }, 'nonspam',
);

sarun ("-D pyzor -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
# same with fork
sarun ("-D pyzor --cf='pyzor_fork 1' -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

