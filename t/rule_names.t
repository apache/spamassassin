#!/usr/bin/perl -w

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("rule_names");

use strict;
use Mail::SpamAssassin;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

our $RUN_THIS_TEST;

use Test;
BEGIN {
  $RUN_THIS_TEST = conf_bool('run_rule_name_tests');

  plan tests => 0  if !$RUN_THIS_TEST;
};

if (!$RUN_THIS_TEST) {
  print "NOTE: this test requires 'run_rule_name_tests' set to 'y'.\n";
  exit;
}

use vars qw(%patterns %anti_patterns);

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

# allow_user_rules, otherwise $sa->{conf}->{test_types} will be
# deleted by SA::Conf::Parser::finish_parsing()
$sa->{conf}->{allow_user_rules} = 1;

$sa->init(0); # parse rules

# get rule names
my @tests;
while (my ($test, $type) = each %{ $sa->{conf}->{test_types} }) {
  push @tests, $test;
}

# run tests
my $mail = 'log/rule_names.eml';
write_mail();
%patterns = ();
my $i = 1;
for my $test (@tests) {
  # look for test with spaces on either side, should match report
  # lines in spam report, only exempt rules that are really unavoidable
  # and are clearly not hitting due to rules being named poorly
  next if $test =~ /^UPPERCASE_\d/;
  next if $test eq "UNIQUE_WORDS";
  # exempt the auto-generated nightly mass-check rules
  next if $test =~ /^T_MC_/;

  $anti_patterns{"$test,"} = "P_" . $i++;
}

{ # couldn't call Test::plan in a BEGIN phase, the %patterns and %anti_patterns
  # must be assembled first in order to get the planned test count

  plan tests => scalar(keys %anti_patterns) + scalar(keys %patterns),

  onfail => sub {
      warn "\n\n   Note: rule_name failures may be only cosmetic" .
      "\n        but must be fixed before release\n\n";
  };
};

# ---------------------------------------------------------------------------


tstprefs ("
	# set super low threshold, so always marked as spam
	required_score -10000.0
	# add two fake lexically high tests so every other hit will always be
	# followed by a comma in the X-Spam-Status header
	body ZZZZZZZZ /./
	body zzzzzzzz /./
");
sarun ("-L < $mail", \&patterns_run_cb);
ok_all_patterns();

# function to write test email with varied (not random) ordering tests in body
sub write_mail {
  if (open(MAIL, ">$mail")) {
    print MAIL <<'EOF';
Received: from internal.example.com [127.0.0.1] by localhost
    for recipient@example.com; Fri, 07 Oct 2002 09:02:00 +0000
Received: from external.example.org [150.51.53.1] by internal.example.com
    for recipient@example.com; Fri, 07 Oct 2002 09:01:00 +0000
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: this trivial message should have no hits
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

EOF

    # we are looking for random failures, but we do a deterministic
    # test to prevent too much frustration with "make test".

    # start off sorted
    @tests = sort @tests;

    print MAIL join("\n", @tests) . "\n\n";

    # 25 iterations gets most hits most of the time, but 10 is large enough
    for (1..10) {
      print MAIL join("\n", sha1_shuffle($_, @tests)) . "\n\n";
    }
    close(MAIL);
  }
  else {
    die "can't open output file: $!";
  }
}

# Fisher-Yates shuffle
sub fy_shuffle {
  for (my $i = $#_; $i > 0; $i--) {
    @_[$_,$i] = @_[$i,$_] for int rand($i+1);
  }
  return @_;
}

# SHA1 shuffle
sub sha1_shuffle {
  my $i = shift;
  return map { $_->[0] }
         sort { $a->[1] cmp $b->[1] }
         map { [$_, sha1($_ . $i)] }
         @_;
}
