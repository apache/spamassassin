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

use lib '.';
use SATest;
sa_t_init("rule_tests");

use strict;
use Test::More;
use Mail::SpamAssassin;

my $num_tests = 1;

$Mail::SpamAssassin::Conf::COLLECT_REGRESSION_TESTS = 1;

my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

#Debug
#warn ("All the head tests by hash priority - ". debug_hash($sa->{conf}->{head_tests}));
#warn ("All the head evals by hash priority - ". debug_hash($sa->{conf}->{head_evals}));

my %symbols;

foreach my $symbol ($sa->{conf}->regression_tests()) {
    #warn ("$symbol - ". debug_array($sa->{conf}->regression_tests($symbol)));

    foreach my $test ($sa->{conf}->regression_tests($symbol)) {
        my $test_type = $sa->{conf}->{test_types}->{$symbol};
        if (defined($test_type)) {
          #warn ( "\n$symbol / $test_type - ". debug_array($test));
          $num_tests++;
          $symbols{$symbol}++;
        } else {
          #warn "$symbol / no test type - skipping"; #. debug_array($test);
        }
    }
}

plan tests => $num_tests;

ok($sa);

# Debug What priorities are available?
#foreach my $priority (sort {$a <=> $b} (keys %{$sa->{conf}->{priorities}})) {
#  warn("Priority $priority\n");
#}

#Loop through all the tests that had test_types defined & build an array

my (@tests);

foreach my $symbol (keys %symbols) {

    foreach my $test ($sa->{conf}->regression_tests($symbol)) {
     
        #warn("Check #4" . $sa->{conf}->{head_tests}->{0}->{INVALID_DATE});

        my ($ok_or_fail, $string) = @$test;
        my $test_type = $sa->{conf}->{test_types}->{$symbol};
        #warn("Got test_type: $symbol $test_type\n");
        next unless defined($test_type);        # score, but no test

        my $mail;

        if ($test_type == $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS || $test_type == $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS) {

            my $test_string;

            # Look through all of the priorities until we find our test
            foreach my $priority (sort {$a <=> $b} (keys %{$sa->{conf}->{priorities}})) {
                #warn("Check #5" . $sa->{conf}->{head_tests}->{0}->{INVALID_DATE});

                #warn ("$priority - $sa->{conf}->{head_tests}->{$priority}\n");
                #warn ("$priority - $sa->{conf}->{head_evals}->{$priority}\n");

                #warn ("$sa->{conf}->{head_tests}->{$priority}->{$symbol}\n");
                #warn ("$sa->{conf}->{head_evals}->{$priority}->{$symbol}\n");

                #warn ('Head tests hash: '.debug_hash($sa->{conf}->{head_tests}->{$priority}));
                #warn ('Head evals hash: '.debug_hash($sa->{conf}->{head_evals}->{$priority}));

                $test_string = $sa->{conf}->{head_tests}->{$priority}->{$symbol} || $sa->{conf}->{head_evals}->{$priority}->{$symbol};
                last if $test_string;
            }

            if (ref($test_string) eq 'ARRAY'){
                $test_string = join("_", @{$test_string});
                $test_string = "Received" if ($test_string =~ /received/i);
            }

            #IF WE DON'T HAVE A TEST STRING WE CAN'T POSSIBLY HAVE A GOOD TEST
            if (!defined $test_string) {
                warn ("$symbol doesn't have a test string!\n");
                ok(0 == 1);
                next;
            }

            #warn ("test string is $test_string\n");
            my ($header_name) = $test_string =~ /^(\S+)/;
            $header_name =~ s/:.*$//; # :name, :addr, etc.
            #warn("got header name: $header_name - setting to: $string\n");
            $mail = $sa->parse(["${header_name}: $string\n","\n","\n"]);
        } else {
            #warn("setting body: $string\n");
            my $type = "text/plain";

            # the test strings are too short for the built-in heuristic to pick up
            # whether or not the message is html.  so we kind of fudge it here...
            if ( $string =~ /<[^>]*>/ ) {
                $type = "text/html";
            }
            $mail = $sa->parse(["Content-type: $type\n","\n","$string\n"]);
        }

        #Building array with loop because if I call msg->check() during the loop, I loose the 
        #access to the $sa->{conf} hash.  Not sure why... 
        push (@tests, [$symbol,$ok_or_fail,$mail, $test_type, $string]);
    }
}



foreach my $tests (@tests) {

    my ($symbol, $ok_or_fail, $mail, $test_type, $string) = @$tests;

    # debugging, what message is being processed
    #print $symbol, "\n", "-"x48, "\n", $mail->get_pristine(), "\n", "-"x48, "\n";

    my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

    # set all scores to 0 so that by default no tests run
    foreach my $symbol2 (keys %{$msg->{conf}->{scores}}) {
        $msg->{conf}->{scores}->{$symbol2} = 0;
    }

    # Make sure that this test will run
    $msg->{conf}->{scores}->{$symbol} = 1;

    $msg->check();

    my %rules_hit = map { $_ => 1 } split(/,/,$msg->get_names_of_tests_hit()), split(/,/,$msg->get_names_of_subtests_hit());

    # debugging, what rule hits actually occurred
    #print $symbol, ": ", join(", ", keys(%rules_hit), "\n");

    is( (exists $rules_hit{$symbol} ? 1 : 0), ($ok_or_fail eq 'ok' ? 1 : 0), "Test for '$symbol' (type: $test_type) against '$string'" );
}

