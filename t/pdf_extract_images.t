#!/usr/bin/perl
#
# Tests Mail::SpamAssassin::PDF::Parser::extract_images and the handler's image
# encoding: an embedded XObject image is decoded from a fixture and re-encoded
# into a PNG/JPEG that an image reader (libpng/tesseract) accepts.

use strict;
use warnings;
# Normalise the working directory so fixtures (data/pdf/*) and lib paths resolve
# whether the test is run from the repo root (make test / prove t/foo.t) or from
# t/.  Mirrors SATest's "(-f t/test_dir) && chdir t".
BEGIN { chdir 't' if -d 't' && -f 't/test_dir'; }
use lib '../blib/lib';
use Test::More;
use Mail::SpamAssassin::PDF::Parser;
use Mail::SpamAssassin::Handler::PDF;

plan tests => 8;

sub slurp {
    my $f = shift;
    open my $fh, '<', $f or die "Can't open $f: $!";
    binmode $fh; local $/; my $d = <$fh>; close $fh;
    return $d;
}

# --- extract_images returns one raw image from a FlateDecode XObject fixture --
{
    my $p = Mail::SpamAssassin::PDF::Parser->new();
    my $data = slurp('data/pdf/indirect_mediabox.pdf');
    $p->parse(\$data);
    my $imgs = $p->extract_images();
    is(scalar(@$imgs), 1, 'extract_images: one image from indirect_mediabox.pdf');
    is($imgs->[0]{format}, 'raw', 'image format is raw (FlateDecode samples)');
    is($imgs->[0]{width} . 'x' . $imgs->[0]{height}, '1x1', 'image dimensions');
}

# --- inline (BI/ID/EI) images are NOT extracted (no stream offset) -----------
{
    my $p = Mail::SpamAssassin::PDF::Parser->new();
    my $data = slurp('data/pdf/inline_image.pdf');
    $p->parse(\$data);
    my $imgs = $p->extract_images();
    is(scalar(@$imgs), 0, 'inline images are not extracted');
}

# --- the handler encodes a raw image into a valid PNG (8-byte signature) -----
{
    my $p = Mail::SpamAssassin::PDF::Parser->new();
    my $data = slurp('data/pdf/indirect_mediabox.pdf');
    $p->parse(\$data);
    my $img = $p->extract_images()->[0];
    my $spec = Mail::SpamAssassin::Handler::PDF::_encode_image(undef, $img);
    ok(defined $spec, 'handler encoded the raw image');
    is($spec->{type}, 'image/png', 'encoded as image/png');
    is(substr($spec->{data}, 0, 8), "\x89PNG\x0d\x0a\x1a\x0a", 'valid PNG signature');
}

# --- a larger grayscale image round-trips and is a well-formed PNG -----------
# ocr_image.pdf embeds an 800x200 DeviceGray image; confirm it decodes and the
# encoded PNG declares the right dimensions in its IHDR.
{
    my $p = Mail::SpamAssassin::PDF::Parser->new();
    my $data = slurp('data/pdf/ocr_image.pdf');
    $p->parse(\$data);
    my $img = $p->extract_images()->[0];
    my $spec = Mail::SpamAssassin::Handler::PDF::_encode_image(undef, $img);
    my ($w, $h) = unpack('NN', substr($spec->{data}, 16, 8));  # IHDR width/height
    is("$w $h", "800 200", 'PNG IHDR reports the original image dimensions');
}
