#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;

my @tests = (
    {
        input  => '/Name1/Name2',
        output => '/Name1',
    },{
        input  => '/A;Name_With-Various***Characters?',
        output => '/A;Name_With-Various***Characters?',
    },{
        input  => '/1.2',
        output => '/1.2',
    },{
        input  => '/$$',
        output => '/$$',
    },{
        input  => '/@pattern',
        output => '/@pattern',
    },{
        input  => '/.notdef',
        output => '/.notdef',
    },{
        input  => '/Adobe#20Green>>',
        output => '/Adobe Green',
    },{
        input  => '/ % a slash followed by no regular characters is a valid name ',
        output => '/',
    },{
        input  => '//Foo',
        output => '/',
    }
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my $result = $core->get_name();
    is($result, $output, "parse_object_number($input) == $output");
}
