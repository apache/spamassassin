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

use strict;
use Test;
use Mail::SpamAssassin;
use vars qw($num_tests);

$num_tests = 1;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});

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

        if ($test_type == Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS ||
            $test_type == Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS)
        {
            my $test_string = $sa->{conf}->{head_tests}->{$symbol} || $sa->{conf}->{head_evals}->{$symbol};
            my ($header_name) = $test_string =~ /^(\S+)/;
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

        ok( (exists $rules_hit{$symbol} ? 1 : 0), ($ok_or_fail eq 'ok' ? 1 : 0),
                "Test for '$symbol' (type: $test_type) against '$string'" );
    }
}
