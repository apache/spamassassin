#!/usr/bin/perl

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  use lib '../lib';
  $prefix = '..';
}

use strict;
use Test;
use Mail::SpamAssassin;
use Data::Dumper; $Data::Dumper::Indent=1;
use vars qw($num_tests);

$num_tests = 1;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/rules",
});

$sa->init(0); # parse rules

my $mail = SATest::Message->new();

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
        $mail->reset;

        my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
        my $conf = $msg->{conf};

        # set all scores to 0 so that by default no tests run
        foreach my $symbol (keys %{$conf->{scores}}) {
            $conf->{scores}->{$symbol} = 0;
        }

        my $test_type = $conf->{test_types}->{$symbol};
        next unless defined($test_type);        # score, but no test

        if ($test_type == Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS ||
            $test_type == Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS)
        {
            my $test_string = $conf->{head_tests}->{$symbol} || $conf->{head_evals}->{$symbol};
            my ($header_name) = $test_string =~ /^(\S+)/;
            # warn("got header name: $header_name - setting to: $string\n");
            $mail->set_header($header_name => $string);
        }
        else {
            # warn("setting body: $string\n");
            $mail->set_body($string);
        }

        $conf->{scores}->{$symbol} = 1;
        $msg->check();
        ok( $msg->get_hits(), ($ok_or_fail eq 'ok' ? 1 : 0),
                "Test for '$symbol' (type: $test_type) against '$string'" );
    }
}

package SATest::Message;

sub new {
    my $class = shift;
    return bless {headers => {}, body => []}, $class;
}

sub reset {
    my $self = shift;
    $self->{headers} = {};
    $self->{body} = [];
}

sub set_header {
    my $self = shift;
    my ($header, $value) = @_;
    # single values because thats all this test harness needs
    $self->{headers}->{$header} = $value;
}

sub get_header {
    my $self = shift;
    my ($header) = @_;
    # warn("get_header: $header\n");
    if (exists $self->{headers}->{$header}) {
        return $self->{headers}->{$header};
    }
    else {
        return '';
    }
}

sub delete_header {
    my $self = shift;
    my ($header) = @_;
    delete $self->{headers}->{$header};
}

sub get_all_headers {
    my $self = shift;
    my @lines;
    foreach my $header (keys %{$self->{headers}}) {
        push @lines, "$header: $self->{headers}->{$header}";
        $lines[-1] .= "\n" unless $lines[-1] =~ /\n$/s;
    }
    return wantarray ? @lines : join('', @lines);
}

sub get_body {
    my $self = shift;
    return $self->{body};
}

sub set_body {
    my $self = shift;
    my @lines = @_;
    $self->{body} = \@lines;
}

