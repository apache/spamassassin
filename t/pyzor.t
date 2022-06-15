#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("pyzor");

use Mail::SpamAssassin::Util;
use constant HAS_PYZOR =>  Mail::SpamAssassin::Util::find_executable_in_env_path('pyzor');

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Pyzor executable not found in path" unless HAS_PYZOR;
plan tests => 8;

diag('Note: Failures may not be an SpamAssassin bug, as Pyzor tests can fail due to problems with the Pyzor servers.');

# ---------------------------------------------------------------------------

tstprefs ("
  full PYZOR_CHECK	eval:check_pyzor()
  tflags PYZOR_CHECK	net autolearn_body
  dns_available no
  use_pyzor 1
  pyzor_count_min 1
  score PYZOR_CHECK 3.3
");

#PYZOR file was from real-world spam in October 2021

#TESTING FOR SPAM
%patterns = (
  q{ 3.3 PYZOR_CHECK }, 'spam',
);

# Windows cmd doesn't recognize ' character
sarun ("--cf=\"pyzor_fork 0\" -t < data/spam/pyzor", \&patterns_run_cb);
ok_all_patterns();
# Same with fork
sarun ("--cf=\"pyzor_fork 1\" -t < data/spam/pyzor", \&patterns_run_cb);
ok_all_patterns();

#TESTING FOR HAM
%patterns = (
  'pyzor: got response: public.pyzor.org' => 'response',
  'pyzor: result: COUNT=0' => 'zerocount',
);
%anti_patterns = (
  q{ 3.3 PYZOR_CHECK }, 'nonspam',
);

sarun ("-D pyzor --cf=\"pyzor_fork 0\" -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();
# same with fork
sarun ("-D pyzor --cf=\"pyzor_fork 1\" -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

