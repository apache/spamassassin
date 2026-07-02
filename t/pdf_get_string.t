#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Core;
use Data::Dumper;

my @tests = (
    {
        input  => '<feff0066006900760065>',
        output => "\x{fe}\x{ff}\x{00}f\x{00}i\x{00}v\x{00}e",
    },{
        input  => '(P.O.\222s and check request forms accepted)',
        output => "P.O.\x{92}s and check request forms accepted",
    },{
        input  => '(or \(2 inches tall x 5.25 inches wide\))',
        output => 'or (2 inches tall x 5.25 inches wide)',
    },{
        input  => '(Please fax completed form to (407) 555-0111)',
        output => 'Please fax completed form to (407) 555-0111',
    },{
        input  => "(This is binary data that ends with a nul byte\x{00})",
        output => "This is binary data that ends with a nul byte\x{00}",
    },{
        input  => '()',
        output => '',
    }
 );

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = '%PDF-1.4 '.$test->{input};
    my $output = $test->{output};
    my $core = Mail::SpamAssassin::PDF::Core->new(\$input);
    $core->pos(9);
    my $result = $core->get_primitive();
    is_deeply($result, $output, $input);
}
