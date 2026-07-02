#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;


my @tests = (
    {
        input  => '[/PDF/Text/ImageB/ImageC/ImageI]/Font<<',
        output => [
            '/PDF',
            '/Text',
            '/ImageB',
            '/ImageC',
            '/ImageI'
        ],
    },{
        input  => '[]',
        output => [],
    }
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my $result = $core->get_array();
    is_deeply($result, $output, Dumper($result));
}
