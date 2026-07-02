#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;


my @tests = (
    {
        input  => '0 15 R',
        output => '0 15 R',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_REF,
    },{
        input  => '0    15     R',
        output => '0 15 R',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_REF,
    },{
        input => '6.24 6.24 re',
        output => '6.24',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    },{
        input => '159 0 R/Size',
        output => '159 0 R',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_REF,
    },{
        input => '2 15 R<</Type /Page>>',
        output => '2 15 R',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_REF,
    },{
        input => '230 0 R>>>>/Rotate 0',
        output => '230 0 R',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_REF,
    },{
        input  => '5/Predictor 12>>',
        output => '5',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    },{
        input  => '5 4/Predictor 12>>',
        output => '5',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    },{
        input => '2 15 RRR',
        output => '2',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    },{
        input => "2.3 4.5 R 18",
        output => '2.3',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    },{
        input => "44 (\x{01}\x{C5}\x{92})24",
        output => '44',
        type    => Mail::SpamAssassin::PDF::Core::TYPE_NUM,
    }
);

plan tests => scalar @tests * 2;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my ($token,$type) = $core->get_primitive();
    is($token, $output, "$input");
    is($type, $test->{type}, "type: $input");
}
