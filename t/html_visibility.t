#!/usr/bin/perl -T
use strict;
use warnings;
use lib 'lib';
use Mail::SpamAssassin::HTML;
use Test::More;

my @tests = (
    {
        html               => '<div style="background-color: transparent">X</div>',
        visibility         => 'visible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="color: transparent">X</div>',
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="color: transparent;background-color: red">X</div>',
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="background-color: red;color: transparent">X</div>',
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="background: 60px 60px, 0 0, 30px 30px, red;color: transparent">X</div>',
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => q{<div style="background: url('../../media/examples/lizard.png'), red;color: transparent">X</div>},
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => q{<div style='background: url("../../media/examples/lizard.png"), linear-gradient(rgba(0, 0, 255, 0.5), rgba(255, 255, 0, 0.5)), 60px 60px, 0 0, 30px 30px, red;color: transparent'>X</div>},
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="background-color: transparent;color: transparent">X</div>',
        visibility         => 'invisible',
        font_invalid_color => 0,
    },
    {
        html               => '<div style="color: red !important">X</div>',
        visibility         => 'visible',
        font_invalid_color => 0,
    },
);

plan tests => scalar @tests * 2;

foreach my $test (@tests) {
    my $html = $test->{html};

    my $html_obj = Mail::SpamAssassin::HTML->new(0,0, debug => 'message');
    $html_obj->parse($html);

    my $visible_text = $html_obj->get_rendered_text(invisible => 0);
    my $invisible_text = $html_obj->get_rendered_text(invisible => 1);

    my $visibility =
        ($visible_text =~ /\S/ ? 'visible' : '') .
        ($invisible_text =~ /\S/ ? 'invisible' : '');

    is($visibility, $test->{visibility}, $html);

    my $font_invalid_color = $html_obj->{results}->{font_invalid_color} // 0;

    is($font_invalid_color, $test->{font_invalid_color}, $html);
}

