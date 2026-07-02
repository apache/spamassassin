#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;

my @tests = (
    {
        input  => 'obj',
        token  => 'obj',
        output => 1,
    },{
        input => '  obj  ',
        token => 'obj',
        output => 1,
    },{
        input => "\nobj\n",
        token => 'obj',
        output => 1,
    },{
        input => "noobj",
        token => 'obj',
        output => undef,
    },{
        input => "<</Columns 5/Predictor 12>>",
        token => '<<',
        output => 1,
    }
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $token = $test->{token};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my $result = eval { $core->assert_token($token); 1;};
    is($result, $output, "assert_token($input)");
}
