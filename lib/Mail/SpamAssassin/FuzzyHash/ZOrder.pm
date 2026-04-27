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

package Mail::SpamAssassin::FuzzyHash::ZOrder;

use strict;
use warnings;
use Digest::MD5 qw(md5);
use Exporter 'import';
use Mail::SpamAssassin::FuzzyHash::Util qw(normalize_tokens hamming_distance);

our $VERSION = '1.0';
our $PROTO = '2';
our @EXPORT_OK = qw(
  zorder_digest
  zorder_compare
  zorder_dns_keys
  zorder_body_band_labels
  zorder_explain
);

=head1 NAME

FuzzyHash::ZOrder - Fuzzy text similarity via DNS, using exactly 4 queries

=head1 SYNOPSIS

  use FuzzyHash::ZOrder qw(zorder_digest zorder_compare zorder_dns_keys);

  my $query_digest = zorder_digest($incoming_text);
  for my $key (zorder_dns_keys($incoming_text, 'fbl.example.com')) {
    for my $stored_digest (dns_txt_lookup($key)) {
      my $sim = zorder_compare($query_digest, $stored_digest);
      if ($sim >= 85) { # rule fires }
    }
  }

=head1 DESCRIPTION

FuzzyHash::ZOrder detects texts with ~90% token overlap using exactly
B<4 DNS TXT lookups> followed by a B<local> similarity check via
C<zorder_compare()>.

=head2 Algorithm

=over 4

=item Normalisation

Lowercase, replace non-alphanumeric with spaces, collapse whitespace,
deduplicate tokens.

=item 32-bit MinHash signature

32 independent hash functions are applied to the deduplicated token set.
Each function finds the token with the minimum hash value; the LSB parity
of that minimum becomes one output bit. The result is a 32-bit signature.
Each bit agrees between two texts with probability exactly equal
to their Jaccard similarity.

=item 4 bands x 8 bits

The 32-bit signature is split into 4 consecutive 8-bit bands.  Two texts
share a band key when all 8 bits in that band agree: probability S^8 at
Jaccard similarity S.

=item Local similarity verification

Each TXT response carries the full 32-bit digest of the indexed string.
C<zorder_compare()> verifies similarity locally using all 32 bits.
Unrelated texts will have a score of ~50%.

=back

=cut

# 32 precomputed salts, one per MinHash function.
# Each salt = first 4 bytes of MD5("mhsalt_N") as big-endian uint32.
my @SALT = map { unpack('N', substr(md5("mhsalt_$_"), 0, 4)) } 0 .. 31;

use constant C1 => 0x9e3779b9;
use constant C2 => 0x85ebca6b;
use constant C3 => 0xc2b2ae35;

# _minhash($text) -> arrayref of 32 bits
#
# For each of 32 hash functions: mix each unique token's base hash with
# the function's salt, keep the minimum, emit LSB parity as one bit.
# LSB parity of the minimum agrees between two texts with P = Jaccard(A,B).

sub _minhash {
  my ($text) = @_;

  my @words = normalize_tokens($text);

  # encode each token back before hashing using md5()
  my @wh = map { my $w = $_; utf8::encode($w); unpack('N', substr(md5($w), 0, 4)) } @words;

  my @bits;
  for my $k (0 .. 31) {
    my $salt = $SALT[$k];
    my $min  = 0xFFFFFFFF;
    for my $w (@wh) {
      my $h = (($w ^ $salt) * C1) & 0xFFFFFFFF;
      $h ^= ($h >> 16);
      $h  = ($h  * C2) & 0xFFFFFFFF;
      $h ^= ($h >> 13);
      $h  = ($h  * C3) & 0xFFFFFFFF;
      $h ^= ($h >> 16);
      $min = $h if $h < $min;
    }
    push @bits, ($min ^ ($min >> 1)) & 1;
  }
  return \@bits;
}

# _bits_to_hex(\@bits) -> 8-char hex (4 bytes)
sub _bits_to_hex {
  my ($bits) = @_;
  my $hex = '';
  for my $i (0 .. 3) {
    my $byte = 0;
    $byte |= ($bits->[$i * 8 + $_] << (7 - $_)) for 0 .. 7;
    $hex .= sprintf('%02x', $byte);
  }
  return $hex;
}

# _band_keys(\@bits, $domain) -> list of 4 FQDNs
# Format: "fz2BVV.domain"  fz=algo, 2=version, B=band 0-3, VV=byte 00-ff
sub _band_keys {
  my ($bits, $domain) = @_;
  my @keys;
  for my $b (0 .. 3) {
    my $val = 0;
    $val |= ($bits->[$b * 8 + $_] << (7 - $_)) for 0 .. 7;
    push @keys, sprintf('fz' . $PROTO . '%d%02x.%s', $b, $val, $domain);
  }
  return @keys;
}

=head1 FUNCTIONS

=head2 zorder_digest($text)

Computes the 32-bit MinHash signature of C<$text>.
Returns an 8-character lowercase hex string.

This is the value stored in each DNS TXT record at index time and used
for local similarity verification at query time.

=cut

sub zorder_digest {
  my ($text) = @_;
  return _bits_to_hex(_minhash($text));
}

=head2 zorder_dns_keys($text, $domain)

Returns a list of exactly B<4 DNS FQDNs> for C<$text> under C<$domain>.

Use for both indexing (store digest as TXT at each key) and querying
(look up each key, verify TXT responses locally with zorder_compare).

=cut

sub zorder_dns_keys {
  my ($text, $domain) = @_;
  return _band_keys(_minhash($text), $domain);
}

=head2 zorder_body_band_labels($text)

Returns a list of exactly B<4 bare band labels> without a trailing domain,
each of the form C<fz2BVV>.

=cut

sub zorder_body_band_labels {
  my ($text) = @_;
  my $bits = _minhash($text);
  my @labels;
  for my $b (0 .. 3) {
    my $val = 0;
    $val |= ($bits->[$b * 8 + $_] << (7 - $_)) for 0 .. 7;
    push @labels, sprintf('fz' . $PROTO . '%d%02x', $b, $val);
  }
  return @labels;
}

=head2 zorder_compare($digest_a, $digest_b)

Compares two 8-char hex digests.  Returns integer similarity 0-100,
computed as C<100 * (1 - hamming_distance / 32)>.

  100  = identical token sets (0 bits differ)
   91  = ~3 bits differ  -> very high overlap
   85  = ~5 bits differ  -> high overlap
   75  = ~8 bits differ  -> moderate overlap
   50  = ~16 bits differ -> noise floor for unrelated texts

The noise floor at ~50% provides a clean gap below the suggested 90% threshold,
so coincidental DNS band hits from unrelated indexed strings are reliably
rejected without any additional DNS queries.

=cut

sub zorder_compare {
  my ($a, $b) = @_;
  die "zorder_compare: digest A must be 8 hex chars (got " . length($a) . ")\n"
    unless length($a) == 8;
  die "zorder_compare: digest B must be 8 hex chars (got " . length($b) . ")\n"
    unless length($b) == 8;
  return int((1.0 - hamming_distance($a, $b) / 32.0) * 100 + 0.5);
}

=head2 zorder_explain($digest_a, $digest_b)

Returns a human-readable breakdown: Hamming distance, similarity score,
shared band count, firing decision, and a per-band bit-agreement table.
Used only for debugging RBL entries and tuning the similarity threshold.

=cut

sub zorder_explain {
  my ($digest_a, $digest_b) = @_;

  my $hamming = hamming_distance($digest_a, $digest_b);
  my $sim = int((1 - $hamming / 32) * 100 + 0.5);

  my $shared = 0;
  for my $b (0 .. 3) {
    $shared++ if hex(substr($digest_a, $b*2, 2)) == hex(substr($digest_b, $b*2, 2));
  }

  my $out = '';
  $out .= "Digest A     : $digest_a\n";
  $out .= "Digest B     : $digest_b\n";
  $out .= sprintf("Hamming dist : %d / 32 bits differ\n", $hamming);
  $out .= sprintf("Similarity   : %d%%\n", $sim);
  $out .= sprintf("Shared bands : %d / 4  (DNS hits at query time)\n", $shared);
  $out .= sprintf("Fires rule   : %s  (local sim %d%% %s threshold 85%%)\n\n",
    $sim >= 95 ? 'YES' : 'no', $sim, $sim >= 95 ? '>=' : '<');
  $out .= sprintf("  %-6s  %-10s  %-10s  %-14s  %s\n",
    'Band', 'A (bits)', 'B (bits)', 'Agreement', 'DNS key match?');
  $out .= "  " . "-" x 58 . "\n";
  for my $b (0 .. 3) {
    my $ba   = hex(substr($digest_a, $b*2, 2));
    my $bb   = hex(substr($digest_b, $b*2, 2));
    my $xor  = $ba ^ $bb;
    my $diff = 0; my $x = $xor; while ($x) { $diff++; $x &= $x-1 }
    my $ok   = 8 - $diff;
    $out .= sprintf("  band%d   %08b  %08b  %s %d/8 bits  %s\n",
      $b, $ba, $bb,
      ('|' x $ok) . ('.' x $diff), $ok,
      $ba == $bb ? 'yes (TXT returned)' : 'no');
  }
  return $out;
}

1;
