#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;


my @tests = (
    {
        input  => '<</Columns 5/Predictor 12>>',
        output => {
            '/Columns'   => 5,
            '/Predictor' => 12,
        },
    },{
        input  => "<</C 506/Filter/FlateDecode/I 528/Length 17/O 426/S 223/V 442>>\r\nstream\r\n...stream data...\r\nendstream",
        output => {
            '/C' => '506',
            '/Length' => '17',
            '/Filter' => '/FlateDecode',
            '/I' => '528',
            '/O' => '426',
            '/S' => '223',
            '/V' => '442',
            '_stream_offset' => 82,
        },
    },{
        # First LF is the line ending, second LF is the stream data (length 1)
        input  => "<</Length 1>> stream\n\nendstream",
        output => {
            '/Length'        => '1',
            '_stream_offset' => 30,
        },
    },{
        input  => "<</AcroForm<</Fields[]>>/Pages 2 0 R /StructTreeRoot 72 0 R /Type/Catalog/MarkInfo<</Marked true>>/Lang(en-US)/Metadata 475 0 R >>\nendobj",
        output => {
            '/AcroForm'       => {
                '/Fields' => [],
            },
            '/Lang'           => 'en-US',
            '/MarkInfo'       => {
                '/Marked' => 'true',
            },
            '/Metadata'       => '475 0 R',
            '/Pages'          => '2 0 R',
            '/StructTreeRoot' => '72 0 R',
            '/Type'           => '/Catalog',
        },
    }
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my $result = $core->get_dict();
    is_deeply($result, $output, Dumper($result));
}
