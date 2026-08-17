#!/usr/bin/perl
#
# Tests the CCITT-to-TIFF wrapper in PDF::Parser and the TIFF branch of
# Handler::Image::_image_info.
#
# CCITT fax data carries no dimensions or polarity of its own -- they live in the
# PDF's /DecodeParms -- so it is passed through still encoded and described by a
# TIFF header, which image readers decode natively.
#
# The wrapper never inspects the bytes it wraps, so most tests here pass a dummy
# payload and assert on the generated TIFF header.  The one fixture on disk,
# data/pdf/ccitt_g4.pdf, is a minimal PDF embedding a real Group 4 image; it
# exercises the whole path from parse to sub-part.  Its image data was produced
# by an independent encoder and can be regenerated with:
#
#   magick -size 64x16 xc:white -fill black -draw 'rectangle 0,0 7,15' \
#          -monochrome -compress Group4 g4.tiff
#   # then embed the TIFF's strip bytes as the stream of an /XObject /Image with
#   # /Filter /CCITTFaxDecode and /DecodeParms <</K -1 /Columns 64 /Rows 16>>
#
# Decoding correctness belongs to libtiff (via leptonica, in tesseract), not to
# this code; what is tested here is that the header we generate describes the
# data accurately -- dimensions, compression, polarity and strip geometry.

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
use Mail::SpamAssassin::Handler::Image;

plan tests => 28;

sub slurp {
    my $f = shift;
    open my $fh, '<', $f or die "Can't open $f: $!";
    binmode $fh; local $/; my $d = <$fh>; close $fh;
    return $d;
}

sub wrap {
    my (%parms) = @_;
    my $bytes = delete $parms{bytes} // 'abc';
    return Mail::SpamAssassin::PDF::Parser::_ccitt_to_tiff($bytes, \%parms);
}

sub info { Mail::SpamAssassin::Handler::Image::_image_info(undef, \$_[0]) }

# Read a tag's value out of a little-endian TIFF built by the wrapper.
sub tag {
    my ($tiff, $want) = @_;
    my $ifd   = unpack('V', substr($tiff, 4, 4));
    my $count = unpack('v', substr($tiff, $ifd, 2));
    for my $i (0 .. $count - 1) {
        my $e = $ifd + 2 + $i * 12;
        my ($tag, $type) = unpack('vv', substr($tiff, $e, 4));
        next unless $tag == $want;
        return $type == 3 ? unpack('v', substr($tiff, $e + 8, 2))
                          : unpack('V', substr($tiff, $e + 8, 4));
    }
    return undef;
}

# --- each coding mode produces a TIFF the reader identifies and measures ----
for my $t ( [-1, 'Group 4 (K<0)'],
            [ 0, 'Group 3 1-D (K=0)'],
            [ 4, 'Group 3 2-D (K>0)'] ) {
    my ($k, $label) = @$t;
    my $tiff = wrap(K => $k, Columns => 64, Rows => 16);
    ok(defined $tiff, "$label: wrapped");
    my ($type, $w, $h) = info($tiff);
    is("$type $w $h", 'tiff 64 16', "$label: _image_info reads type and dimensions");
}

# --- /K maps onto the TIFF compression tag ----------------------------------
is(tag(wrap(K => -1, Columns => 64, Rows => 16), 259), 4,
   'K<0 selects Compression 4 (Group 4)');
is(tag(wrap(K =>  0, Columns => 64, Rows => 16), 259), 3,
   'K=0 selects Compression 3 (Group 3)');
is(tag(wrap(K =>  4, Columns => 64, Rows => 16), 259), 3,
   'K>0 selects Compression 3 (Group 3)');
is(tag(wrap(K =>  0, Columns => 64, Rows => 16), 292), 0,
   'K=0 clears the T4Options 2-D bit');
is(tag(wrap(K =>  4, Columns => 64, Rows => 16), 292), 1,
   'K>0 sets the T4Options 2-D bit');

# --- BlackIs1 maps onto PhotometricInterpretation ---------------------------
# PDF BlackIs1 false (default) means 0 = black, i.e. TIFF WhiteIsZero (0).
is(tag(wrap(K => -1, Columns => 64, Rows => 16), 262), 0,
   'BlackIs1 false gives PhotometricInterpretation 0 (WhiteIsZero)');
is(tag(wrap(K => -1, Columns => 64, Rows => 16, BlackIs1 => 1), 262), 1,
   'BlackIs1 true gives PhotometricInterpretation 1 (MinIsBlack)');

# --- the strip offset points at the image data, which is appended verbatim ---
{
    # A payload with every byte value, so a truncation, re-encoding or off-by-one
    # in the strip offset would show up as a mismatch.
    my $data = join('', map { chr } 0 .. 255);
    my $tiff = wrap(bytes => $data, K => -1, Columns => 64, Rows => 16);
    my $off  = tag($tiff, 273);
    is(tag($tiff, 279), length($data), 'StripByteCounts is the payload length');
    is(substr($tiff, $off, length $data), $data,
       'StripOffsets points at the unmodified CCITT bytes');
    is(length($tiff), $off + length($data), 'no trailing slack after the strip');
}

# --- unusable parameters are declined rather than mis-described -------------
ok(!defined wrap(K => -1),                        'missing Columns/Rows declined');
ok(!defined wrap(K => -1, Columns => 0, Rows => 16), 'zero Columns declined');
ok(!defined wrap(K => -1, Columns => 64, Rows => 0), 'zero Rows declined');
# EncodedByteAlign has no Group 4 equivalent in TIFF; wrapping it would decode to
# garbage, so it must be declined (but is fine for Group 3, as T4Options bit 2).
ok(!defined wrap(K => -1, Columns => 64, Rows => 16, EncodedByteAlign => 1),
   'Group 4 with EncodedByteAlign declined');
{
    my $tiff = wrap(K => 0, Columns => 64, Rows => 16, EncodedByteAlign => 1);
    ok(defined $tiff, 'Group 3 with EncodedByteAlign wrapped');
    is(tag($tiff, 292) & 0x4, 0x4, 'EncodedByteAlign sets the T4Options fill bit');
}

# --- the extract_images contract: descriptors carry ready-to-use image bytes --
# A CCITT image comes back as a complete TIFF file (like 'jpeg', unlike 'raw'),
# so the handler passes it straight through without needing the codec parameters.
{
    my $p = Mail::SpamAssassin::PDF::Parser->new();
    my $data = slurp('data/pdf/ccitt_g4.pdf');
    $p->parse(\$data);
    my $img = $p->extract_images()->[0];
    is($img->{format}, 'tiff', 'extract_images reports format tiff for CCITT');
    my $spec = Mail::SpamAssassin::Handler::PDF::_encode_image(undef, $img);
    is($spec->{type}, 'image/tiff', 'handler passes the TIFF through as image/tiff');
}

# --- _image_info: big-endian TIFF and malformed input -----------------------
{
    # Hand-build a big-endian TIFF with SHORT dimension tags.
    my @tags = ([256, 3, 320], [257, 3, 240]);
    my $be = "MM\x00\x2a" . pack('N', 8) . pack('n', scalar @tags);
    $be .= pack('nnN', $_->[0], $_->[1], 1) . pack('nn', $_->[2], 0) for @tags;
    $be .= pack('N', 0);
    my ($type, $w, $h) = info($be);
    is("$type $w $h", 'tiff 320 240', 'big-endian TIFF with SHORT tags is read');
}

# A TIFF whose IFD is unreadable must still be typed (so OCR is attempted, since
# the size gate fails open on undef dimensions) rather than dying.
{
    my $junk = "II\x2a\x00" . pack('V', 8) . pack('v', 65535) . ('x' x 32);
    my ($type, $w, $h) = eval { info($junk) };
    ok(!$@, 'malformed IFD does not die');
    is($type, 'tiff', 'malformed IFD still identified as tiff');
    ok(!defined $w && !defined $h, 'malformed IFD yields undef dimensions');
}
