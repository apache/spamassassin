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
#     (BOM'd or BOM-less, either endianness), and undef for anything else --
#     notably 8-bit text containing a stray NUL.
#   * _normalize($bytes, 'UTF-16', 0, 0) - transcodes UTF-16 octets to UTF-8
#     octets via that decoder, falling back to the declared byte order (or
#     big-endian) when detect_utf16() finds no evidence.
#   * _normalize($bytes, undef, ...) - handles an UNDECLARED charset (a
#     handler-produced pseudo-part has none): decodes what detect_utf16()
#     identifies as UTF-16, passes UTF-8/ASCII through untouched, and emits no
#     "uninitialized value" warnings (the whole file runs under
#     `warnings FATAL => 'all'`, so any such warning fails the test).
#
# Regression guard: detect_utf16() used to return undef when a BOM was present
# ("let perl figure it out from the BOM"), but its only caller only ever used the
# decoder it returned -- so BOM'd UTF-16 dropped through to the Windows-1252 last
# resort in _normalize() and was mangled.  The BOM'd cases below cover that.
# A second guard: _normalize() with an undef charset used to warn 7x and mangle
# BOM-less UTF-16; the "undeclared charset" section below covers that.
# ---------------------------------------------------------------------------

my $sample = "The quick brown fox jumps over the lazy dog.\n";

my $le_bom   = "\xff\xfe" . Encode::encode('UTF-16LE', $sample);
my $be_bom   = "\xfe\xff" . Encode::encode('UTF-16BE', $sample);
my $le_nobom = Encode::encode('UTF-16LE', $sample);
my $be_nobom = Encode::encode('UTF-16BE', $sample);

my $utf8  = Encode::encode('UTF-8', "caf\x{e9} \x{4e16}\x{754c}\n");
my $ascii = "plain ascii, no nulls here\n";

plan tests => 16;

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

# --- _normalize with an UNDECLARED charset (undef) --------------------------
# A pseudo-part carries no declared charset.  _normalize(undef) must still detect
# UTF-16 (by BOM-or-NUL) and decode it to UTF-8 octets, while leaving UTF-8/ASCII
# untouched -- and must not misclassify NUL-free text as UTF-16.
subtest '_normalize(undef charset) decodes UTF-16 to UTF-8' => sub {
  plan tests => 4;
  for my $c (['BOM LE', $le_bom], ['BOM BE', $be_bom],
             ['no-BOM LE', $le_nobom], ['no-BOM BE', $be_nobom]) {
    my ($name, $bytes) = @$c;
    my $out = Mail::SpamAssassin::Message::Node::_normalize($bytes, undef, 0, 0);
    ok($out =~ /\QThe quick brown fox\E/ && index($out, "\x00") < 0,
       "$name decoded to UTF-8 with no declared charset");
  }
};

subtest '_normalize(undef charset) leaves non-UTF-16 text unchanged' => sub {
  plan tests => 3;
  # No NUL, no BOM -> must NOT be treated as UTF-16.  Short ASCII is a
  # false-positive guard: detect_utf16() used to report it as UTF-16BE.
  is(Mail::SpamAssassin::Message::Node::_normalize('hi', undef, 0, 0), 'hi',
     'short ASCII not misdetected as UTF-16');
  is(Mail::SpamAssassin::Message::Node::_normalize($ascii, undef, 0, 0), $ascii,
     'plain ASCII unchanged with no declared charset');
  is(Mail::SpamAssassin::Message::Node::_normalize($utf8, undef, 0, 0), $utf8,
     'valid UTF-8 unchanged with no declared charset');
};

subtest '_normalize(undef charset, return_decoded=1) yields characters' => sub {
  plan tests => 2;
  # rendered() calls _normalize with return_decoded=1 and (in a later phase) an
  # undef charset; the result must be utf8-flagged Unicode characters.
  my $chars = Mail::SpamAssassin::Message::Node::_normalize($le_bom, undef, 1, 0);
  ok(utf8::is_utf8($chars), 'returns utf8-flagged characters');
  ok($chars =~ /\QThe quick brown fox\E/, 'decoded text matches');
};

# --- odd-length NUL-bearing input must not warn -----------------------------
# detect_utf16() steps through the data in byte pairs, so short and odd-length
# input must not read past the end (an "uninitialized value" warning).  We trap
# warnings from ANY package
# via $SIG{__WARN__} (the file's `warnings FATAL` pragma is lexical and would not
# catch warnings raised inside Node.pm).
subtest 'odd-length NUL input does not warn' => sub {
  plan tests => 3;
  for my $c (['single NUL', "\x00"], ['NUL+odd ascii', "\x00ab"],
             ['odd trailing byte', "a\x00b"]) {
    my ($name, $bytes) = @$c;
    my @warnings;
    {
      local $SIG{__WARN__} = sub { push @warnings, $_[0] };
      Mail::SpamAssassin::Message::Node::_normalize($bytes, undef, 0, 0);
    }
    is("@warnings", '', "$name normalizes with no warnings")
      or diag("warnings: @warnings");
  }
};

# --- detect_utf16 returns undef for data that is not UTF-16 -----------------
# A stray NUL in 8-bit text is the important case: a single NUL (e.g. a "=00" in
# a quoted-printable body) must not turn a whole ASCII part into UTF-16 mojibake.
# UTF-16 with no BOM and almost no ASCII (here CJK) cannot be told apart from
# 8-bit text by its NULs, so it is not detected either -- a known limitation.
my $cjk = "\x{4e16}\x{754c}\x{4f60}\x{597d}" x 20;
my $long_ascii = $sample x 40;   # well past the 1024 bytes examined
my %stray;
for my $pad ('', 'x') {          # both odd and even total lengths
  for my $at (10, 11, 1500, 1501) {   # even/odd offset, inside/past the prefix
    my $s = $long_ascii . $pad;
    substr($s, $at, 0) = "\x00";
    $stray{"stray NUL at $at, length ".length($s)} = $s;
  }
}
subtest 'detect_utf16: not UTF-16 -> undef' => sub {
  my %cases = (
    'empty'               => '',
    'single byte'         => 'a',
    'short ASCII'         => 'hi',
    'ASCII'               => $ascii,
    'long ASCII'          => $long_ascii,
    'UTF-8'               => $utf8,
    'binary 0..255'       => join('', map { chr } 0 .. 255) x 4,
    'CJK UTF-16LE no BOM' => Encode::encode('UTF-16LE', $cjk),
    %stray,
  );
  plan tests => scalar keys %cases;
  for my $name (sort keys %cases) {
    my $dec = Mail::SpamAssassin::Message::Node::detect_utf16($cases{$name});
    is(defined $dec ? $dec->name : undef, undef, "$name is not UTF-16");
  }
};

# --- detect_utf16 examines only the first 1024 bytes ------------------------
subtest 'detect_utf16: only the first 1024 bytes count' => sub {
  plan tests => 2;
  my $late = ('a' x 1100) . Encode::encode('UTF-16LE', $sample x 20);
  my $early = Encode::encode('UTF-16LE', $sample x 30) . "trailing junk \x00\xff";
  is(Mail::SpamAssassin::Message::Node::detect_utf16($late), undef,
     'UTF-16 after the first 1024 bytes is not seen');
  my $dec = Mail::SpamAssassin::Message::Node::detect_utf16($early);
  is(defined $dec ? $dec->name : undef, 'UTF-16LE',
     'UTF-16 in the first 1024 bytes decides, whatever follows');
};

# --- _normalize(undef charset) leaves 8-bit text with a stray NUL alone ------
subtest '_normalize(undef charset) leaves text with a stray NUL unchanged' => sub {
  plan tests => scalar keys %stray;
  for my $name (sort keys %stray) {
    is(Mail::SpamAssassin::Message::Node::_normalize($stray{$name}, undef, 0, 0),
       $stray{$name}, "$name unchanged");
  }
};

# --- declared UTF-16 with no evidence: trust the label ----------------------
# With no BOM and no NUL pattern (CJK), detect_utf16() returns undef, so the
# declared byte order is used -- big-endian for a plain "UTF-16" (RFC 2781).
subtest '_normalize: declared UTF-16 label used when there is no evidence' => sub {
  plan tests => 3;
  my $want = Encode::encode('UTF-8', $cjk);
  is(Mail::SpamAssassin::Message::Node::_normalize(
       Encode::encode('UTF-16LE', $cjk), 'UTF-16LE', 0, 0), $want,
     'UTF-16LE label decodes CJK as little-endian');
  is(Mail::SpamAssassin::Message::Node::_normalize(
       Encode::encode('UTF-16BE', $cjk), 'UTF-16BE', 0, 0), $want,
     'UTF-16BE label decodes CJK as big-endian');
  is(Mail::SpamAssassin::Message::Node::_normalize(
       Encode::encode('UTF-16BE', $cjk), 'UTF-16', 0, 0), $want,
     'plain UTF-16 label defaults to big-endian');
};

# --- declared UTF-16 with evidence: the evidence wins over the label ---------
subtest '_normalize: BOM or NUL pattern wins over the declared byte order' => sub {
  plan tests => 2;
  is(Mail::SpamAssassin::Message::Node::_normalize($be_bom, 'UTF-16LE', 0, 0),
     $sample, 'BOM overrides a UTF-16LE label on big-endian data');
  is(Mail::SpamAssassin::Message::Node::_normalize($le_nobom, 'UTF-16BE', 0, 0),
     $sample, 'NUL pattern overrides a UTF-16BE label on little-endian data');
};

# --- a lone surrogate does not stop a detected UTF-16 decode ----------------
# JavaScript strings are UTF-16 code units, so obfuscated script can split a
# surrogate pair across two string literals, leaving lone surrogates in the
# file.  When a BOM or the NUL pattern shows the data is UTF-16, it is decoded
# leniently (the lone surrogate becomes U+FFFD) rather than rejected outright.
# With only a declared charset as evidence the decode stays strict.
subtest '_normalize: lone surrogate in detected UTF-16' => sub {
  plan tests => 5;
  my $js = Encode::encode('UTF-16LE', "var a = \"x\";\n" x 40)
         . "\x3e\xd8"     # lone high surrogate U+D83E, not followed by a low one
         . Encode::encode('UTF-16LE', "\";\nvar b = WScript;\n");
  for my $c (['BOM', "\xff\xfe$js"], ['no BOM', $js]) {
    my ($name, $bytes) = @$c;
    my $out = Mail::SpamAssassin::Message::Node::_normalize($bytes, undef, 0, 0);
    ok($out =~ /var b = WScript;/ && index($out, "\x00") < 0,
       "$name: text after the lone surrogate is decoded");
    is(scalar(() = $out =~ /\xef\xbf\xbd/g), 1,
       "$name: the lone surrogate becomes one U+FFFD");
  }
  my $cjk_lone = Encode::encode('UTF-16LE', $cjk) . "\x3e\xd8";
  my $out = Mail::SpamAssassin::Message::Node::_normalize($cjk_lone, 'UTF-16LE', 0, 0);
  ok(index($out, Encode::encode('UTF-8', $cjk)) < 0,
     'declared UTF-16LE with no BOM or NUL pattern is still decoded strictly');
};
