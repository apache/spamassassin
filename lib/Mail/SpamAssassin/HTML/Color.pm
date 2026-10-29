# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::HTML::Color;
use strict;
use warnings;
no warnings 'numeric';
use Carp qw(croak);
use overload '""' => sub { shift->as_hex }, fallback => 1;

my %html_color = (
    # HTML 4 defined 16 colors
    aqua => [0, 255, 255],
    black => [0, 0, 0],
    blue => [0, 0, 255],
    fuchsia => [255, 0, 255],
    gray => [128, 128, 128],
    green => [0, 128, 0],
    lime => [0, 255, 0],
    maroon => [128, 0, 0],
    navy => [0, 0, 128],
    olive => [128, 128, 0],
    purple => [128, 0, 128],
    red => [255, 0, 0],
    silver => [192, 192, 192],
    teal => [0, 128, 128],
    white => [255, 255, 255],
    yellow => [255, 255, 0],
    # colors specified in CSS3 color module
    aliceblue => [240, 248, 255],
    antiquewhite => [250, 235, 215],
    aquamarine => [127, 255, 212],
    azure => [240, 255, 255],
    beige => [245, 245, 220],
    bisque => [255, 228, 196],
    blanchedalmond => [255, 235, 205],
    blueviolet => [138, 43, 226],
    brown => [165, 42, 42],
    burlywood => [222, 184, 135],
    cadetblue => [95, 158, 160],
    chartreuse => [127, 255, 0],
    chocolate => [210, 105, 30],
    coral => [255, 127, 80],
    cornflowerblue => [100, 149, 237],
    cornsilk => [255, 248, 220],
    crimson => [220, 20, 60],
    cyan => [0, 255, 255],
    darkblue => [0, 0, 139],
    darkcyan => [0, 139, 139],
    darkgoldenrod => [184, 134, 11],
    darkgray => [169, 169, 169],
    darkgreen => [0, 100, 0],
    darkkhaki => [189, 183, 107],
    darkmagenta => [139, 0, 139],
    darkolivegreen => [85, 107, 47],
    darkorange => [255, 140, 0],
    darkorchid => [153, 50, 204],
    darkred => [139, 0, 0],
    darksalmon => [233, 150, 122],
    darkseagreen => [143, 188, 143],
    darkslateblue => [72, 61, 139],
    darkslategray => [47, 79, 79],
    darkturquoise => [0, 206, 209],
    darkviolet => [148, 0, 211],
    deeppink => [255, 20, 147],
    deepskyblue => [0, 191, 255],
    dimgray => [105, 105, 105],
    dodgerblue => [30, 144, 255],
    firebrick => [178, 34, 34],
    floralwhite => [255, 250, 240],
    forestgreen => [34, 139, 34],
    gainsboro => [220, 220, 220],
    ghostwhite => [248, 248, 255],
    gold => [255, 215, 0],
    goldenrod => [218, 165, 32],
    greenyellow => [173, 255, 47],
    honeydew => [240, 255, 240],
    hotpink => [255, 105, 180],
    indianred => [205, 92, 92],
    indigo => [75, 0, 130],
    ivory => [255, 255, 240],
    khaki => [240, 230, 140],
    lavender => [230, 230, 250],
    lavenderblush => [255, 240, 245],
    lawngreen => [124, 252, 0],
    lemonchiffon => [255, 250, 205],
    lightblue => [173, 216, 230],
    lightcoral => [240, 128, 128],
    lightcyan => [224, 255, 255],
    lightgoldenrodyellow => [250, 250, 210],
    lightgray => [211, 211, 211],
    lightgreen => [144, 238, 144],
    lightpink => [255, 182, 193],
    lightsalmon => [255, 160, 122],
    lightseagreen => [32, 178, 170],
    lightskyblue => [135, 206, 250],
    lightslategray => [119, 136, 153],
    lightsteelblue => [176, 196, 222],
    lightyellow => [255, 255, 224],
    limegreen => [50, 205, 50],
    linen => [250, 240, 230],
    magenta => [255, 0, 255],
    mediumaquamarine => [102, 205, 170],
    mediumblue => [0, 0, 205],
    mediumorchid => [186, 85, 211],
    mediumpurple => [147, 112, 219],
    mediumseagreen => [60, 179, 113],
    mediumslateblue => [123, 104, 238],
    mediumspringgreen => [0, 250, 154],
    mediumturquoise => [72, 209, 204],
    mediumvioletred => [199, 21, 133],
    midnightblue => [25, 25, 112],
    mintcream => [245, 255, 250],
    mistyrose => [255, 228, 225],
    moccasin => [255, 228, 181],
    navajowhite => [255, 222, 173],
    oldlace => [253, 245, 230],
    olivedrab => [107, 142, 35],
    orange => [255, 165, 0],
    orangered => [255, 69, 0],
    orchid => [218, 112, 214],
    palegoldenrod => [238, 232, 170],
    palegreen => [152, 251, 152],
    paleturquoise => [175, 238, 238],
    palevioletred => [219, 112, 147],
    papayawhip => [255, 239, 213],
    peachpuff => [255, 218, 185],
    peru => [205, 133, 63],
    pink => [255, 192, 203],
    plum => [221, 160, 221],
    powderblue => [176, 224, 230],
    rosybrown => [188, 143, 143],
    royalblue => [65, 105, 225],
    saddlebrown => [139, 69, 19],
    salmon => [250, 128, 114],
    sandybrown => [244, 164, 96],
    seagreen => [46, 139, 87],
    seashell => [255, 245, 238],
    sienna => [160, 82, 45],
    skyblue => [135, 206, 235],
    slateblue => [106, 90, 205],
    slategray => [112, 128, 144],
    snow => [255, 250, 250],
    springgreen => [0, 255, 127],
    steelblue => [70, 130, 180],
    tan => [210, 180, 140],
    thistle => [216, 191, 216],
    tomato => [255, 99, 71],
    turquoise => [64, 224, 208],
    violet => [238, 130, 238],
    wheat => [245, 222, 179],
    whitesmoke => [245, 245, 245],
    yellowgreen => [154, 205, 50],
);

sub new {
    my ($class, $color) = @_;
    my $self = [];
    bless $self, $class;

    croak("Color value is required") unless (defined $color);
    $color =~ s/^\s+|\s+$//g;  # Trim whitespace
    $color = lc($color);

    # If color is 'transparent', set all values to 0
    if ($color eq 'transparent') {
        @$self = (0, 0, 0, 0);
        return $self;
    }

    # Check if color is a named color
    if (exists $html_color{$color}) {
        @$self = (@{ $html_color{$color} }, 1);
        return $self;
    }

    # Check if color is in hexadecimal format (#000 or #aabbcc)
    if ($color =~ /^#([0-9a-f]{3}|[0-9a-f]{6})$/) {
        my $hex = length($1) == 3
                ? join('', map { $_ x 2 } split //, $1)
                : $1;
        @$self = map { hex($_) } $hex =~ /../g;
        push @$self, 1;
        return $self;
    }

    # Check if color is in RGB format (rgb(255, 0, 153) or rgb(255 0 153 / 80%))
    if ($color =~ /^rgba?\s*\((.*)\)$/) {
        my @args = split(/[ ,\/]+/, $1);
        push @args, 1 if @args == 3;
        croak("Invalid number of arguments for RGB color") unless @args == 4;
        for (@args) {
            croak("Invalid RGB value: $_") unless $_ =~ /^(?:none|[+-]?(?:\d*+\.)?\d++%?)$/;
        }
        my ($r, $g, $b) = map {
            /^(.*)%$/ ? _round($1 * 255 / 100) : $_ + 0;
        } @args[0..2];
        $a = $args[3];
        $a = $a =~ s/%$// ? $a / 100 : $a + 0;
        @$self = ($r, $g, $b, $a);
        return $self;
    }

    # Check if color is in HSL format (hsl(360, 100%, 50%) or hsl(360 100% 50% / 80%))
    if ($color =~ /^hsla?\s*\((.*)\)$/) {
        my @args = split(/[ ,\/]+/, $1);
        push @args, 1 if @args == 3;
        croak("Invalid number of arguments for HSL color") unless @args == 4;
        for (@args[1..3]) {
            croak("Invalid HSL value: $_") unless $_ =~ /^(?:none|[+-]?(?:\d*+\.)?\d++%?)$/;
        }
        my ($h, $s, $l, $a) = @args;
        $h = _parse_angle($h);
        $s =~ s/%$//; $s /= 100;
        $l =~ s/%$//; $l /= 100;
        $a = $a =~ s/%$// ? $a / 100 : $a + 0;

        @$self = _hsl_to_rgb($h, $s, $l);
        push @$self, $a;
        return $self;
    }

    # Check if color is in HWB format (hwb(240, 100%, 0%) or hwb(240 100% 0% / 80%))
    if ($color =~ /^hwba?\s*\((.*)\)$/) {
        my @args = split(/[ ,\/]+/, $1);
        push @args, 1 if @args == 3;
        croak("Invalid number of arguments for HWB color") unless @args == 4;
        for (@args[1..3]) {
            croak("Invalid HWB value: $_") unless $_ =~ /^(?:none|[+-]?(?:\d*+\.)?\d++%?)$/;
        }
        my ($h, $wh, $bl, $a) = @args;
        $h = _parse_angle($h);
        $wh =~ s/%$//; $wh /= 100;
        $bl =~ s/%$//; $bl /= 100;
        $a = $a =~ s/%$// ? $a / 100 : $a + 0;

        @$self = _hwb_to_rgb($h, $wh, $bl);
        push @$self, $a;
        return $self;
    }

    croak("Unsupported color format: $color");
}

sub blend {
    my ($self, $background) = @_;
    my ($r, $g, $b, $a) = @$self;
    return $self if $a == 1;
    my ($br, $bg, $bb) = @$background;

    my $new_r = _round(($r * $a) + ($br * (1 - $a)));
    my $new_g = _round(($g * $a) + ($bg * (1 - $a)));
    my $new_b = _round(($b * $a) + ($bb * (1 - $a)));

    @$self = ($new_r, $new_g, $new_b, 1);
    return $self;
}

sub distance {
    my ($self, $other_color) = @_;
    my ($r1, $g1, $b1) = @$self[0..2];
    my ($r2, $g2, $b2) = @$other_color[0..2];

    my $r = ($r1 - $r2);
    my $g = ($g1 - $g2);
    my $b = ($b1 - $b2);

    # geometric distance weighted by brightness
    # maximum distance is 191.151823601032
    my $distance = ((0.2126 * $r)**2 + (0.7152 * $g)**2 + (0.0722 * $b)**2)**0.5;

    return $distance;
}

sub as_hex {
    my ($self) = @_;
    my ($r, $g, $b) = @$self[0..2];
    return sprintf("#%02x%02x%02x", $r, $g, $b);
}

sub as_array {
    my ($self) = @_;
    return @$self;
}

#
# Static Private Methods
#

sub _hsl_to_rgb {
    my ($hue, $saturation, $lightness) = @_;

    # Ensure the hue is between 0-360 degrees and S, L are between 0 and 1
    $hue %= 360;
    $saturation = 0 if $saturation < 0;
    $lightness = 0 if $lightness < 0;
    $saturation = 1 if $saturation > 1;
    $lightness = 1 if $lightness > 1;

    my $c = (1 - abs(2 * $lightness - 1)) * $saturation;
    my $x = $c * (1 - abs(($hue / 60) % 2 - 1));
    my $m = $lightness - $c / 2;
    my @rgb;

    if ($hue >= 0 && $hue < 60) {
        @rgb = ($c, $x, 0);
    } elsif ($hue >= 60 && $hue < 120) {
        @rgb = ($x, $c, 0);
    } elsif ($hue >= 120 && $hue < 180) {
        @rgb = (0, $c, $x);
    } elsif ($hue >= 180 && $hue < 240) {
        @rgb = (0, $x, $c);
    } elsif ($hue >= 240 && $hue < 300) {
        @rgb = ($x, 0, $c);
    } else {
        @rgb = ($c, 0, $x);
    }

    return map { _round(($_ + $m) * 255) } @rgb;
}

sub _hwb_to_rgb {
    my ($hue, $whiteness, $blackness) = @_;

    # Ensure the hue is between 0-360 degrees and W, B are between 0 and 1
    $hue %= 360;
    $whiteness = 0 if $whiteness < 0;
    $blackness = 0 if $blackness < 0;
    $whiteness = 1 if $whiteness > 1;
    $blackness = 1 if $blackness > 1;

    # Convert hue to range 0 to 1
    my $h = $hue / 60;  # Divide hue by 60 to put it in [0, 6)
    my $f = $h - int($h);
    my @rgb_base;

    # Get RGB base values based on hue
    if    ($h < 1) { @rgb_base = (1, $f, 0); }
    elsif ($h < 2) { @rgb_base = (1 - $f, 1, 0); }
    elsif ($h < 3) { @rgb_base = (0, 1, $f); }
    elsif ($h < 4) { @rgb_base = (0, 1 - $f, 1); }
    elsif ($h < 5) { @rgb_base = ($f, 0, 1); }
    else           { @rgb_base = (1, 0, 1 - $f); }

    # Apply whiteness and blackness to compute final RGB values
    my $i = 1 - $whiteness - $blackness;
    my @rgb = map { _round(($whiteness + $i * $_) * 255) } @rgb_base;

    return @rgb;
}

sub _parse_angle {
    my ($angle) = @_;

    croak("Invalid color angle: $angle") unless $angle =~ /^(?:none|[+-]?(?:\d*+\.)?\d++(?:deg|grad|rad|turn)?)$/;

    $angle = $angle =~ s/deg$// ? $angle
        : $angle =~ s/grad$// ? $angle * 360 / 400
        : $angle =~ s/rad$// ? $angle * 180 / 3.14159
        : $angle =~ s/turn$// ? $angle * 360
        : $angle;

    return _round($angle) % 360;

}

sub _round {
    my ($value) = @_;
    return int($value + 0.5);
}

1;

__END__

=head1 NAME

Mail::SpamAssassin::HTML::Color - A class to parse and manipulate CSS color values

=head1 SYNOPSIS

  use Mail::SpamAssassin::HTML::Color;

  my $color = Mail::SpamAssassin::HTML::Color->new('rgba(255, 0, 153, 0.5)');
  $color->blend([255, 255, 255]);
  my $distance = $color->distance([0, 0, 0]);
  print "$color";  # Outputs the color as a hex string

=head1 DESCRIPTION

This class provides methods to parse various CSS color formats, blend them with a background color, calculate the distance between two colors, and convert the color to a hex string.

=head1 METHODS

=head2 new($color)

Creates a new color object from a CSS color string.

=head2 blend($background)

Blends the color with the given background color. Modifies the color in-place and returns the modified object.

=head2 distance($other_color)

Calculates the distance between the current color and another color using a brightness-weighted geometric formula.

=head2 as_hex

Returns the color as a hex string with a leading '#'.

=head2 as_array

Returns the color as an array of RGB values.

=cut
