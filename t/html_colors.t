#!/usr/bin/perl -w -T

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("html_colors");
use Test::More;
use Mail::SpamAssassin::HTML::Color;

my @test_constructor = (
    {
        color => 'transparent',
        rgb   => [ 0, 0, 0, 0 ],
    },
    {
        color => 'TRANSPARENT',
        rgb   => [ 0, 0, 0, 0 ],
    },
    {
        color => 'black',
        rgb   => [ 0, 0, 0, 1 ],
    },
    {
        color => 'WHITE',
        rgb   => [ 255, 255, 255, 1 ],
    },
    {
        color => ' peachpuff ',
        rgb   => [ 255, 218, 185, 1 ],
    },
    {
        color => '#0f7',
        rgb   => [ 0, 255, 119, 1 ],
    },
    {
        color => '#aaBBcc',
        rgb   => [ 170, 187, 204, 1 ],
    },
    {
        color => 'rgb(255, 0, 153)',
        rgb   => [ 255, 0, 153, 1 ],
    },
    {
        color => ' rgb(255 0 153) ',
        rgb   => [ 255, 0, 153, 1 ],
    },
    {
        color => 'RGB(255 0 153)',
        rgb   => [ 255, 0, 153, 1 ],
    },
    {
        color => 'rgb(255 122 127 / 80%)',
        rgb   => [ 255, 122, 127, 0.8 ],
    },
    {
        color => 'rgb(0 0 0/50%)',
        rgb   => [ 0, 0, 0, 0.5 ],
    },
    {
        color => 'rgb(255 122 127 / .2)',
        rgb   => [ 255, 122, 127, 0.2 ],
    },
    {
        color => 'rgb(30% 20% 50%)',
        rgb   => [ 77, 51, 128, 1 ],
    },
    {
        color => 'rgb(none 20 50%)',
        rgb   => [ 0, 20, 128, 1 ],
    },
    {
        color => 'rgba(255, 0, 153)',
        rgb   => [ 255, 0, 153, 1 ],
    },
    {
        color => 'hsl(120deg 75% 25%)',
        rgb   => [ 16, 112, 16, 1 ],
    },
    {
        color => 'hsl(120 75 25)',
        rgb   => [ 16, 112, 16, 1 ],
    },
    {
        color => 'hsl(120deg 75% 25% / 60%)',
        rgb   => [ 16, 112, 16, 0.6 ],
    },
    {
        color => 'hsl(120DEG 75% 25% / 60%)',
        rgb   => [ 16, 112, 16, 0.6 ],
    },
    {
        color => ' HSL(NONE 75% 25%) ',
        rgb   => [ 112, 16, 16, 1 ],
    },
    {
        color => 'hwb(12 50% 0%)',
        rgb   => [ 255, 153, 128 , 1 ],
    },
    {
        color => 'hwb(50deg 30% 40%)',
        rgb   => [ 153, 140, 77, 1 ],
    },
    {
        color => 'hwb(0.5turn 10% 0% / .5)',
        rgb   => [ 26, 255, 255, 0.5 ],
    },
    {
        color => ' HWB(0.5TURN 10% 0% / .5)',
        rgb   => [ 26, 255, 255, 0.5 ],
    },
    {
        color => 'hwb(0 100% 0% / 50%)',
        rgb   => [ 255, 255, 255, 0.5 ],
    },
    {
        color => 'foo',
        rgb   => undef,
    },
    {
        color => '000',
        rgb   => undef,
    },
    {
        color => '#zftygn',
        rgb   => undef,
    },
    {
        color => '#f',
        rgb   => undef,
    },
    {
        color => '#12345678',
        rgb   => undef,
    },
    {
        color => 'rgb(foo bar baz)',
        rgb   => undef,
    },
);

my @test_distance = (
    {
        color1 => 'lightsteelblue',
        color2 => 'lightslategray',
        distance => 44.8677,
    },
    {
        color1 => 'lightgoldenrodyellow',
        color2 => 'papayawhip',
        distance => 7.9416,
    },
    {
        color1 => 'turquoise',
        color2 => 'violet',
        distance => 76.7648,
    },
    {
        color1 => 'darkolivegreen',
        color2 => 'darkolivegreen',
        distance => 0,
    },
);

my @test_blend = (
    {
        fg => 'rgba(255, 0, 0, 0.5)',
        bg => 'rgb(0, 255, 0)',
        result => [ 128, 128, 0, 1 ],
    },
    {
        fg     => 'rgba(70 130 180 / 80%)',
        bg     => 'navajowhite',
        result => [ 107, 148, 179, 1 ],
    }
);

plan tests => scalar @test_constructor + scalar @test_distance + scalar @test_blend;

foreach my $test (@test_constructor) {
  my $color    = $test->{color};
  my $expected = $test->{rgb};

  my $got;
  eval {
    my $html_color = Mail::SpamAssassin::HTML::Color->new($color);
    my @rgb = $html_color->as_array();
    $got = \@rgb;
  };

  is_deeply($got, $expected, "Color $color is converted to RGB");
}

foreach my $test (@test_distance) {
  my $color1 = $test->{color1};
  my $color2 = $test->{color2};
  my $distance = $test->{distance};

  my $html_color1 = Mail::SpamAssassin::HTML::Color->new($color1);
  my $html_color2 = Mail::SpamAssassin::HTML::Color->new($color2);

  # Bug 8338: Round to 4 decimal places to avoid floating point precision issues
  my $result = sprintf("%.4f",$html_color1->distance($html_color2)) + 0;

  is($result, $distance, "Distance between $color1 and $color2 is $distance");
}

foreach my $test (@test_blend) {
  my $fg = $test->{fg};
  my $bg = $test->{bg};
  my $result = $test->{result};

  my $html_fg = Mail::SpamAssassin::HTML::Color->new($fg);
  my $html_bg = Mail::SpamAssassin::HTML::Color->new($bg);
  my @rgb = $html_fg->blend($html_bg)->as_array();

  is_deeply(\@rgb, $result, "Blending $fg on $bg gives " . join(',', @$result));
}
