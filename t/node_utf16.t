#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
use lib 'blib/lib'; use lib '../blib/lib';
use Test::More;
use Encode qw();
use Mail::SpamAssassin::Message::Node;

# ---------------------------------------------------------------------------
# Direct unit tests for the UTF-16 handling in Mail::SpamAssassin::Message::Node:
#
#   * detect_utf16($bytes) - returns an Encode decoder for UTF-16 input
#     (BOM'd or BOM-less, either endianness).
#   * _normalize($bytes, 'UTF-16', 0, 0) - transcodes UTF-16 octets to UTF-8
#     octets via that decoder.
#
# Regression guard: detect_utf16() used to return undef when a BOM was present
# ("let perl figure it out from the BOM"), but its only caller only ever used the
# decoder it returned -- so BOM'd UTF-16 dropped through to the Windows-1252 last
# resort in _normalize() and was mangled.  The BOM'd cases below cover that.
# ---------------------------------------------------------------------------

my $sample = "The quick brown fox jumps over the lazy dog.\n";

my $le_bom   = "\xff\xfe" . Encode::encode('UTF-16LE', $sample);
my $be_bom   = "\xfe\xff" . Encode::encode('UTF-16BE', $sample);
my $le_nobom = Encode::encode('UTF-16LE', $sample);
my $be_nobom = Encode::encode('UTF-16BE', $sample);

my $utf8  = Encode::encode('UTF-8', "caf\x{e9} \x{4e16}\x{754c}\n");
my $ascii = "plain ascii, no nulls here\n";

plan tests => 6;

# --- detect_utf16: returns the CORRECT decoder for every UTF-16 variant ------
# The BOM'd cases are the regression guard (before the fix these returned undef).
# A BOM declares its own endianness, so both BOM'd inputs must resolve to the
# BOM-aware 'UTF-16' codec -- NOT UTF-16LE/UTF-16BE, which would ignore the BOM
# and mis-decode the opposite endianness.  BOM-less inputs must resolve to the
# specific endianness the heuristic sniffed.  We check both the decoder's name
# and that it actually decodes the sample back to the original text.
my @detect = (
  ['BOM LE',    $le_bom,    'UTF-16'],
  ['BOM BE',    $be_bom,    'UTF-16'],
  ['no-BOM LE', $le_nobom,  'UTF-16LE'],
  ['no-BOM BE', $be_nobom,  'UTF-16BE'],
);
for my $c (@detect) {
  my ($name, $bytes, $want) = @$c;
  subtest "detect_utf16: $name -> $want" => sub {
    plan tests => 2;
    my $dec = Mail::SpamAssassin::Message::Node::detect_utf16($bytes);
    is(defined $dec ? $dec->name : undef, $want,
       "returns the $want decoder");
    is(defined $dec ? $dec->decode($bytes, Encode::LEAVE_SRC) : undef, $sample,
       "that decoder round-trips the sample text");
  };
}

# --- _normalize('UTF-16'): every variant transcodes to clean UTF-8 ----------
# Result must be UTF-8 octets: the ASCII text is contiguous again (a BOM'd input
# that fell through to Windows-1252 would keep its interleaved NUL bytes and the
# mangled BOM, so both checks would fail).
subtest '_normalize decodes all UTF-16 variants to UTF-8' => sub {
  plan tests => 4;
  for my $c (['BOM LE', $le_bom], ['BOM BE', $be_bom],
             ['no-BOM LE', $le_nobom], ['no-BOM BE', $be_nobom]) {
    my ($name, $bytes) = @$c;
    my $out = Mail::SpamAssassin::Message::Node::_normalize($bytes, 'UTF-16', 0, 0);
    ok($out =~ /\QThe quick brown fox\E/ && index($out, "\x00") < 0,
       "$name decoded (BOM consumed, no NULs)");
  }
};

# --- _normalize leaves already-UTF-8 and plain ASCII unchanged --------------
# Each input is declared with the charset it actually is, so we exercise the
# matching decode path rather than relying on the "try UTF-8 first" fallback.
subtest '_normalize leaves UTF-8 / ASCII unchanged' => sub {
  plan tests => 2;
  is(Mail::SpamAssassin::Message::Node::_normalize($utf8, 'UTF-8', 0, 0), $utf8,
     'valid UTF-8 octets unchanged');
  is(Mail::SpamAssassin::Message::Node::_normalize($ascii, 'us-ascii', 0, 0), $ascii,
     'plain ASCII unchanged');
};
