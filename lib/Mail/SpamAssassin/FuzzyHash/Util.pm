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

package Mail::SpamAssassin::FuzzyHash::Util;

use strict;
use warnings;
use Unicode::Normalize qw(NFKC);
use Exporter 'import';

our $VERSION = '1.0';
our @EXPORT_OK = qw(normalize_tokens hamming_distance);

=head1 NAME

Mail::SpamAssassin::FuzzyHash::Util - Shared utilities for FuzzyHash algorithms

=head1 SYNOPSIS

  use Mail::SpamAssassin::FuzzyHash::Util qw(normalize_tokens hamming_distance);

  my @tokens = normalize_tokens($text);
  my $dist   = hamming_distance($hex_a, $hex_b);

=head1 FUNCTIONS

=head2 normalize_tokens($text)

Normalises C<$text> and returns a list of unique tokens suitable for
fuzzy-hash computation.

Steps: ensure UTF-8 flag is set, apply NFKC normalisation (folds
full-width ASCII spam chars and ligatures), lowercase, insert space
boundaries around CJK characters, strip anything that is not a Unicode
letter, digit, or space, collapse whitespace, split and deduplicate.

Returns C<('__empty__')> for texts that produce no tokens after
normalisation.

=cut

sub normalize_tokens {
  my ($text) = @_;

  # Set Perl's Unicode flag is set so \p{} properties will work correctly
  my $str = $text;
  utf8::decode($str) unless utf8::is_utf8($str);

  # NFKC normalisation folds full-width ASCII spam chars and ligatures
  my $norm = NFKC(lc $str);

  # Insert space boundaries around each CJK/ideographic character so that
  # scripts without whitespace word-separators like Chinese
  # are tokenised character-by-character instead of becoming a single token
  $norm =~ s/([\p{Han}\p{Katakana}\p{Hiragana}\p{Hangul}])/ $1 /g;

  # Strip anything that is not a Unicode letter, digit, or space
  $norm =~ s/[^\p{L}\p{N} ]/ /g;
  $norm =~ s/\s+/ /g;
  $norm =~ s/^\s+|\s+$//g;

  my (%seen, @words);
  for my $w (split / /, $norm) {
    push @words, $w if $w ne '' && !$seen{$w}++;
  }
  push @words, '__empty__' unless @words;
  return @words;
}

=head2 hamming_distance($hex_a, $hex_b)

Returns the Hamming distance (number of differing bits) between two
equal-length lowercase hex strings. The strings must have even length.

=cut

sub hamming_distance {
  my ($a, $b) = @_;
  my $nbytes = length($a) / 2;
  my $hamming = 0;
  for my $i (0 .. $nbytes - 1) {
    my $xor = hex(substr($a, $i*2, 2)) ^ hex(substr($b, $i*2, 2));
    while ($xor) { $hamming++; $xor &= $xor - 1 }
  }
  return $hamming;
}

1;
