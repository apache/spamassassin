#!/usr/bin/perl -T
use strict;
use warnings;
use lib '.'; use lib 't';
use SATest; sa_t_init("html_nested_anchors");
use Mail::SpamAssassin::HTML;
use Test::More;

my @tests = (
    {
        html => '<a href="#one">foo<a href="#two">bar</a>baz</a>',
        uris => {
            '#one' => {
                types       => { 'a' => 1 },
                anchor_text => ['foobarbaz'],
            },
            '#two' => {
                types       => { 'a' => 1 },
                anchor_text => ['bar'],
            }
        }
    },
    {
        html => '<a href="#one">foo<a href="#one">bar</a>baz</a>',
        uris => {
            '#one' => {
                types       => { 'a' => 1 },
                anchor_text => ['foobarbaz', 'bar'],
            },
        }
    },
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $html = $test->{html};

    my $html_obj = Mail::SpamAssassin::HTML->new(0, 0);
    $html_obj->parse($html);

    my $uris = $html_obj->{results}->{uri_detail};
    is_deeply($uris, $test->{uris}, "URI details match for HTML: $html");

}
