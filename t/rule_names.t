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

use strict;
use SATest; sa_t_init("rule_names");
use Test;
use Mail::SpamAssassin;
use vars qw(%patterns %anti_patterns);

# initialize SpamAssassin
my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});
$sa->init(0); # parse rules

# get rule names
my @tests;
while (my ($test, $type) = each %{ $sa->{conf}->{test_types} }) {
  push @tests, $test;
}

# run tests
my $mail = 'log/rule_names.eml';
write_mail();
plan tests => (scalar @tests);
%patterns = ();
my $i = 1;
for my $test (@tests) {
  # look for test with spaces on either side, should match report
  # lines in spam report, only exempt rules that are really unavoidable
  # and are clearly not hitting due to rules being named poorly
  next if $test eq "LINES_OF_YELLING";
  next if $test eq "LINES_OF_YELLING_2";
  next if $test eq "LINES_OF_YELLING_3";
  next if $test eq "UPPERCASE_75_100";
  next if $test eq "UNIQUE_WORDS";
  $anti_patterns{"$test,"} = "P_" . $i++;
}
tstprefs ("
	# set super low threshold, so always marked as spam
	required_hits -10000.0
	# add a fake lexically final test so every other hit will always be
	# followed by a comma in the X-Spam-Status header
	body ZZZZZZZZ /./
");
sarun ("-L < $mail", \&patterns_run_cb);
ok_all_patterns();

# function to write test email with randomly ordered tests in body
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
    print MAIL join("\n", @tests) . "\n\n";
    # this is non-deterministic, but we are looking for random failures
    # 25 iterations gets most hits most of the time, but 10 is large enough
    for (1..10) {
      print MAIL join("\n", shuffle(@tests)) . "\n\n";
    }
    close(MAIL);
  }
  else {
    die "can't open output file: $!";
  }
}

# Fisher-Yates shuffle
sub shuffle {
  for (my $i = $#_; $i > 0; $i--) {
    @_[$_,$i] = @_[$i,$_] for rand $i+1;
  }
  return @_;
}
