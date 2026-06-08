#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("neural_network");

use File::Path qw(rmtree);
use File::Spec;
use Storable qw(retrieve);
use Test::More;

use constant HAS_SQLITE => eval { require DBD::SQLite; 1 };

plan tests => 18;

sub check_examined {
  local ($_);
  my $string = shift;

  if (defined $string) {
    $_ = $string;
  } else {
    $_ = join ('', <IN>);
  }

  if ($_ =~ /(?:Forgot|Learned) tokens from \d+ message\(s\) \((\d+) message\(s\) examined\)/) {
    #print STDERR "examined $1 messages\n";
    if (defined $wanted_examined && $wanted_examined == $1) {
      $found{'Acted on message'}++;
    }
  }
}

sub nn_reinit {
  my $extra = shift || '';
  rmtree("$userstate/NN") if -d "$userstate/NN";
  mkdir "$userstate/NN";
  tstprefs("
  loadplugin Mail::SpamAssassin::Plugin::NeuralNetwork

  neuralnetwork_data_dir	$userstate/NN
  neuralnetwork_min_spam_count	0
  neuralnetwork_min_ham_count	0
  neuralnetwork_min_vocab_hits	1

  body		NN_SPAM		eval:check_neuralnetwork_spam()
  describe	NN_SPAM		Email considered as spam by Neural Network
  score		NN_SPAM		1.0

  body		NN_HAM		eval:check_neuralnetwork_ham()
  describe	NN_HAM		Email considered as ham by Neural Network
  score		NN_HAM		-1.0

  $extra
");
}

nn_reinit();
ok(salearnrun("-L --spam data/spam/001", \&check_examined));
ok(salearnrun("-L --ham  data/nice/001", \&check_examined));

%patterns    = ( q{ 1.0 NN_SPAM }, '' );
%anti_patterns = ( q{ -1.0 NN_HAM }, '' );
sarun("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

%patterns    = ( q{ -1.0 NN_HAM }, '' );
%anti_patterns = ( q{ 1.0 NN_SPAM }, '' );
sarun("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();

# Verify _tbuf accumulates one entry per class and retrain is suppressed.

nn_reinit("neuralnetwork_retrain_interval 0");

salearnrun("--ham  data/nice/001", undef);
salearnrun("--spam data/spam/001", undef);

{
  my $username   = lc((getpwuid($<))[0] || 'nobody');
  my $vocab_path = File::Spec->catfile($userstate, 'NN',
                                       "vocabulary-$username.data");

  ok(-f $vocab_path, "vocabulary file exists at $vocab_path");

  my $vocab = eval { retrieve($vocab_path) };
  ok(ref($vocab) eq 'HASH', 'vocabulary loaded as hashref');

  my $buf = $vocab->{_tbuf};
  ok(ref($buf) eq 'HASH', '_tbuf is a hashref');

  is(scalar(@{ $buf->{ham}  || [] }), 1, 'ham training buffer has 1 entry');
  is(scalar(@{ $buf->{spam} || [] }), 1, 'spam training buffer has 1 entry');
}

# After retrain_interval=1, _learns_since_retrain must reset to 0.

nn_reinit("neuralnetwork_retrain_interval 1");

salearnrun("--spam data/spam/001", undef);
salearnrun("--ham  data/nice/001", undef);

{
  my $username   = lc((getpwuid($<))[0] || 'nobody');
  my $vocab_path = File::Spec->catfile($userstate, 'NN',
                                       "vocabulary-$username.data");

  ok(-f $vocab_path, "vocabulary file created at $vocab_path");

  my $vocab = eval { retrieve($vocab_path) };
  ok(ref($vocab) eq 'HASH', 'vocabulary loaded as hashref');

  is($vocab->{_learns_since_retrain}, 0,
     '_learns_since_retrain resets to 0 after periodic retrain triggers');
}

# Ham-heavy stream (3 spam : 6 ham) must not collapse all predictions to HAM.

SKIP: {
  skip 'DBD::SQLite not installed', 2 unless HAS_SQLITE;

  nn_reinit("neuralnetwork_dsn dbi:SQLite:$userstate/NN/neural.db");

  for my $i (1..3) {
    my $f = sprintf("data/spam/%03d", $i);
    salearnrun("--spam $f", undef);
  }
  for my $i (1..6) {
    my $f = sprintf("data/nice/%03d", $i);
    salearnrun("--ham $f", undef);
  }

  my $any_spam = 0;
  for my $i (1..3) {
    my $f = sprintf("data/spam/%03d", $i);
    sarun("-L -t < $f", sub { $any_spam = 1 if join('', <IN>) =~ /1\.0 NN_SPAM/ });
  }
  ok($any_spam, 'at least one spam classified as spam (model not collapsed to ham)');

  my $any_ham = 0;
  for my $i (1..6) {
    my $f = sprintf("data/nice/%03d", $i);
    sarun("-L -t < $f", sub { $any_ham = 1 if join('', <IN>) =~ /-1\.0 NN_HAM/ });
  }
  ok($any_ham, 'at least one ham classified as ham after imbalanced training');
}

# SQLite backend regression

SKIP: {
  skip 'DBD::SQLite not installed', 2 unless HAS_SQLITE;

  nn_reinit("neuralnetwork_dsn dbi:SQLite:$userstate/NN/neural.db");

  salearnrun("--spam data/spam/001", undef);
  salearnrun("--ham  data/nice/001", undef);
  salearnrun("--spam data/spam/002", undef);
  salearnrun("--ham  data/nice/002", undef);

  my $correct_spam = 0;
  for my $i (1..2) {
    my $f = sprintf("data/spam/%03d", $i);
    sarun("-L -t < $f", sub { $correct_spam++ if join('', <IN>) =~ /1\.0 NN_SPAM/ });
  }
  is($correct_spam, 2, 'SQLite backend: all spam classified correctly');

  my $correct_ham = 0;
  for my $i (1..2) {
    my $f = sprintf("data/nice/%03d", $i);
    sarun("-L -t < $f", sub { $correct_ham++ if join('', <IN>) =~ /-1\.0 NN_HAM/ });
  }
  is($correct_ham, 2, 'SQLite backend: all ham classified correctly');
}
