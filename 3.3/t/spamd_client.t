#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_client");

use constant TEST_ENABLED => conf_bool('run_long_tests');
use constant HAS_SDBM_FILE => eval { require SDBM_File; };

our $DO_RUN = !$SKIP_SPAMD_TESTS && TEST_ENABLED;

my $num_tests = 18;

# UNIX socket tests
if (!$RUNNING_ON_WINDOWS) {
  $num_tests += 13;
}

# learn tests
if (HAS_SDBM_FILE) {
  $num_tests += 21;
}

use Test; plan tests => ($DO_RUN ? $num_tests : 0);

exit unless $DO_RUN;

# ---------------------------------------------------------------------------

my $testmsg = getmessage("data/spam/gtube.eml");

ok($testmsg);

%patterns = (
q{ X-Spam-Flag: YES}, 'flag',
q{ BODY: Generic Test for Unsolicited Bulk Email }, 'gtube',
q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'gtube string',
);

ok(start_spamd("-L"));

my $client = create_clientobj({
                               port => $spamdport,
                               host => $spamdhost,
                              });

ok($client);

ok($client->ping());

my $result = $client->check($testmsg);

ok($result);

ok($result->{isspam} eq 'True');
ok(!$result->{message});

$result = $client->process($testmsg);

ok($result);

ok($result->{isspam} eq 'True');
ok($result->{message});

patterns_run_cb($result->{message});
ok_all_patterns();

clear_pattern_counters();
%patterns = (
q{ X-Spam-Flag: YES}, 'flag',
);

%anti_patterns = (
q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'gtube string',
);

$result = $client->headers($testmsg);

ok($result);

ok($result->{message});

patterns_run_cb($result->{message});
ok_all_patterns();

ok(stop_spamd());

if (!$RUNNING_ON_WINDOWS) {

  clear_pattern_counters();
  $spamd_already_killed = undef;

  %patterns = (
    q{ X-Spam-Flag: YES}, 'flag',
    q{ BODY: Generic Test for Unsolicited Bulk Email }, 'gtube',
    q{ XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X }, 'gtube string',
      );

  %anti_patterns = ();

  my $sockpath = mk_safe_tmpdir()."/spamd.sock";
  ok(start_spamd("-L --socketpath=$sockpath"));

  $client = create_clientobj({
                              socketpath => $sockpath,
                             });

  ok($client);

  ok($client->ping());

  $result = $client->check($testmsg);

  ok($result);

  ok($result->{isspam} eq 'True');
  ok(!$result->{message});

  $result = $client->process($testmsg);

  ok($result);
  
  ok($result->{isspam} eq 'True');
  ok($result->{message});

  patterns_run_cb($result->{message});
  ok_all_patterns();

  ok(stop_spamd());
  cleanup_safe_tmpdir();
}

if (HAS_SDBM_FILE) {

  clear_pattern_counters();
  $spamd_already_killed = undef;
  tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
  ");

  ok(start_spamd("-L --allow-tell"));

  my $client = create_clientobj({
                               port => $spamdport,
                               host => $spamdhost,
                              });

  ok($client);

  my $spammsg = getmessage("data/spam/001");
  ok($spammsg);

  ok($client->learn($spammsg, 0));

  ok(!$client->learn($spammsg, 0));

  %patterns = ( '1 0  non-token data: nspam' => 'spam in database' );
  ok(salearnrun("--dump magic", \&patterns_run_cb));
  ok_all_patterns();
  clear_pattern_counters();

  ok($client->learn($spammsg, 2));

  %patterns = ( '0 0  non-token data: nspam' => 'spam in database',
                '0 0  non-token data: nham' => 'ham in database' );
  ok(salearnrun("--dump magic", \&patterns_run_cb));
  ok_all_patterns();
  clear_pattern_counters();

  my $hammsg = getmessage("data/nice/001");
  ok($hammsg);

  ok($client->learn($spammsg, 1));

  ok(!$client->learn($spammsg, 1));

  %patterns = ( '1 0  non-token data: nham' => 'ham in database' );
  ok(salearnrun("--dump magic", \&patterns_run_cb));
  ok_all_patterns();
  clear_pattern_counters();

  ok($client->learn($spammsg, 2));

  %patterns = ( '0 0  non-token data: nspam' => 'spam in database',
                '0 0  non-token data: nham' => 'ham in database' );
  ok(salearnrun("--dump magic", \&patterns_run_cb));
  ok_all_patterns();
  clear_pattern_counters();

  ok(stop_spamd());
}


sub getmessage {
  my ($msgpath) = @_;

  open(MSG, $msgpath) || return undef;

  my @file = <MSG>;
  my $msg = join('', @file);

  close(MSG);

  return $msg;
}
