#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("neural_network");

use Test::More;
plan tests => 4;

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

tstprefs("
  loadplugin Mail::SpamAssassin::Plugin::NeuralNetwork

  neuralnetwork_data_dir	$userstate/NN
  neuralnetwork_min_spam_count	0
  neuralnetwork_min_ham_count	0
  neuralnetwork_min_vocab_hits  5

  body		NN_SPAM		eval:check_neuralnetwork_spam()
  describe	NN_SPAM		Email considered as spam by Neural Network
  score		NN_SPAM		1.0

  body		NN_HAM		eval:check_neuralnetwork_ham()
  describe	NN_HAM		Email considered as ham by Neural Network
  score		NN_HAM		-1.0

");

%patterns = (
  q{ 1.0 NN_SPAM }, '',
);
%antipatterns = (
  q{ -1.0 NN_HAM }, '',
);

mkdir "$userstate/NN";
ok(salearnrun("-L --spam data/spam/001", \&check_examined));
sarun("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ -1.0 NN_HAM }, '',
);
%antipatterns = (
  q{ 1.0 NN_SPAM }, '',
);

ok(salearnrun("-L --ham data/nice/001", \&check_examined));
sarun("-L -t < data/nice/001", \&patterns_run_cb);
ok_all_patterns();
