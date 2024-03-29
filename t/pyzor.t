#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("pyzor");

use Mail::SpamAssassin::Util;
use constant HAS_PYZOR =>  Mail::SpamAssassin::Util::find_executable_in_env_path('pyzor');

use Test::More;
plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');

my $tests = 6;
$tests += 14 if (HAS_PYZOR);
plan tests => $tests;

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

# Report the test spam to ensure it shows up when we check it
%patterns = (
  q{ spam reported to Pyzor }, 'pyzor report',
);

if (HAS_PYZOR) {
  # Windows cmd doesn't recognize ' character
  ok sarun ("--cf=\"pyzor_fork 0\" -t -D info -r < data/spam/pyzor 2>&1", \&patterns_run_cb);
  ok_all_patterns();
}

#TESTING FOR SPAM
%patterns = (
  q{ 3.3 PYZOR_CHECK }, 'spam',
);

if (HAS_PYZOR) {
  ok sarun ("--cf=\"pyzor_fork 0\" -t < data/spam/pyzor", \&patterns_run_cb);
  ok_all_patterns();
  # Same with fork
  ok sarun ("--cf=\"pyzor_fork 1\" -t < data/spam/pyzor", \&patterns_run_cb);
  ok_all_patterns();
}

# Same with Perl
ok sarun ("--cf=\"pyzor_fork 0\" --cf=\"pyzor_perl 1\" -t < data/spam/pyzor", \&patterns_run_cb);
ok_all_patterns();

#TESTING FOR HAM
%patterns = (
  'pyzor: got response: public.pyzor.org' => 'response',
  'pyzor: result: COUNT=0' => 'zerocount',
);
%anti_patterns = (
  q{ 3.3 PYZOR_CHECK }, 'nonspam',
);

if (HAS_PYZOR) {
  ok sarun ("-D pyzor --cf=\"pyzor_fork 0\" -t < data/nice/001 2>&1", \&patterns_run_cb);
  ok_all_patterns();
  # same with fork
  ok sarun ("-D pyzor --cf=\"pyzor_fork 1\" -t < data/nice/001 2>&1", \&patterns_run_cb);
  ok_all_patterns();
}

# same with Perl
ok sarun ("-D pyzor --cf=\"pyzor_fork 0\" --cf=\"pyzor_perl 1\" -t < data/nice/001 2>&1", \&patterns_run_cb);
ok_all_patterns();

