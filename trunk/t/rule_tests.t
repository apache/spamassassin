#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
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

use SATest; sa_t_init("rule_tests");

use strict;
use Test;
use Mail::SpamAssassin;
use vars qw($num_tests);

$num_tests = 1;

$Mail::SpamAssassin::Conf::COLLECT_REGRESSION_TESTS = 1;

my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

foreach my $symbol ($sa->{conf}->regression_tests()) {
    foreach my $test ($sa->{conf}->regression_tests($symbol)) {
        my $test_type = $sa->{conf}->{test_types}->{$symbol};
        next unless defined($test_type);        # score, but no test

        $num_tests++;
    }
}

plan tests => $num_tests;

ok($sa);

foreach my $symbol ($sa->{conf}->regression_tests()) {
    foreach my $test ($sa->{conf}->regression_tests($symbol)) {
        my ($ok_or_fail, $string) = @$test;
        # warn("got test_type: $test_type\n");
        my $test_type = $sa->{conf}->{test_types}->{$symbol};
        next unless defined($test_type);        # score, but no test

	my $mail;

        if ($test_type == $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS ||
            $test_type == $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS)
        {
  	    my $test_string;
	    # Look through all of the priorities until we find our test
  	    for my $priority (sort(keys %{$sa->{conf}->{priorities}})) {
	      $test_string = $sa->{conf}->{head_tests}->{$priority}->{$symbol}
		|| $sa->{conf}->{head_evals}->{$priority}->{$symbol};
	      last if $test_string;
            }
	    if (ref($test_string) eq 'ARRAY'){
	      $test_string = join("_", @{$test_string});
	      $test_string = "Received" if ($test_string =~ /received/i);
	    }
            my ($header_name) = $test_string =~ /^(\S+)/;
	    $header_name =~ s/:.*$//; # :name, :addr, etc.
            # warn("got header name: $header_name - setting to: $string\n");
	    $mail = $sa->parse(["${header_name}: $string\n","\n","\n"]);
        }
        else {
            # warn("setting body: $string\n");
	    my $type = "text/plain";

	    # the test strings are too short for the built-in heuristic to pick up
	    # whether or not the message is html.  so we kind of fudge it here...
	    if ( $string =~ /<[^>]*>/ ) {
	      $type = "text/html";
	    }
	    $mail = $sa->parse(["Content-type: $type\n","\n","$string\n"]);
        }

	# debugging, what message is being processed
	#print $symbol, "\n", "-"x48, "\n", $mail->get_pristine(), "\n", "-"x48, "\n";

        my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
        my $conf = $msg->{conf};

        # set all scores to 0 so that by default no tests run
        foreach my $symbol (keys %{$conf->{scores}}) {
            $conf->{scores}->{$symbol} = 0;
        }

	# Make sure that this test will run
        $conf->{scores}->{$symbol} = 1;
        $msg->check();

	my %rules_hit = map { $_ => 1 } split(/,/,$msg->get_names_of_tests_hit()),
		split(/,/,$msg->get_names_of_subtests_hit());

	# debugging, what rule hits actually occurred
	#print $symbol, ": ", join(", ", keys(%rules_hit), "\n");

print "Test for '$symbol' (type: $test_type) against '$string'\n";
        ok( (exists $rules_hit{$symbol} ? 1 : 0), ($ok_or_fail eq 'ok' ? 1 : 0),
                "Test for '$symbol' (type: $test_type) against '$string'" );
    }
}
