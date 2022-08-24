#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_client");

use constant HAS_SDBM_FILE => eval { require SDBM_File; };

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan skip_all => "Long running tests disabled" unless conf_bool('run_long_tests');

# TODO: These should be skips down in the code, not changing the test count.
my $num_tests = 18;

# UNIX socket tests
if (!$RUNNING_ON_WINDOWS) {
  $num_tests += 13;
}

# learn tests
if (HAS_SDBM_FILE) {
  $num_tests += 21;
}

plan tests => $num_tests;

# ---------------------------------------------------------------------------

my $testmsg = getmessage("data/spam/gtube.eml");

ok($testmsg);

%patterns = (
  qr/^X-Spam-Flag: YES/m, 'flag',
  q{ 1000 GTUBE }, 'gtube',
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'gtube string',
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
qr/^X-Spam-Flag: YES/m, 'flag',
);

%anti_patterns = (
  'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'gtube string',
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
    qr/^X-Spam-Flag: YES/m, 'flag',
    q{ 1000 GTUBE }, 'gtube',
    'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X', 'gtube string',
      );

  %anti_patterns = ();

  my $sockpath = mk_socket_tempdir()."/spamd.sock";
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
}

if (HAS_SDBM_FILE) {

  clear_pattern_counters();
  $spamd_already_killed = undef;

  tstprefs ("
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

