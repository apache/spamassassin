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

package Mail::SpamAssassin::Plugin::BodyEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:sa);

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("multipart_alternative_difference", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("multipart_alternative_difference_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_blank_line_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("tvd_vertical_words", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_stock_info", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_body_length", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  $self->register_eval_rule("plaintext_body_length", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("plaintext_sig_length", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("plaintext_body_sig_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

sub multipart_alternative_difference {
  my ($self, $pms, $fulltext, $min, $max) = @_;

  $self->_multipart_alternative_difference($pms) unless (exists $pms->{madiff});

  if (($min == 0 || $pms->{madiff} > $min) &&
      ($max eq "undef" || $pms->{madiff} <= $max)) {
      return 1;
  }
  return 0;
}

sub multipart_alternative_difference_count {
  my ($self, $pms, $fulltext, $ratio, $minhtml) = @_;
  $self->_multipart_alternative_difference($pms) unless (exists $pms->{madiff});
  return 0 unless $pms->{madiff_html} > $minhtml;
  return (($pms->{madiff_text} / $pms->{madiff_html}) > $ratio);
}

sub _multipart_alternative_difference {
  my ($self, $pms) = @_;
  $pms->{madiff} = 0;
  $pms->{madiff_html} = 0;
  $pms->{madiff_text} = 0;

  my $msg = $pms->{msg};

  # Find all multipart/alternative parts in the message
  my @ma = $msg->find_parts(qr@^multipart/alternative\b@);

  # If there are no multipart/alternative sections, skip this test.
  return if (!@ma);

  # Figure out what the MIME content of the message looks like
  my @content = $msg->content_summary();

  # Exchange meeting requests come in as m/a text/html text/calendar,
  # which we want to ignore because of the high FP rate it would cause.
  # 
  if (@content == 3 && $content[2] eq 'text/calendar' &&
  	$content[1] eq 'text/html' &&
  	$content[0] eq 'multipart/alternative') {
    return;
  }

  # Go through each of the multipart parts
  foreach my $part (@ma) {
    my %html;
    my %text;

    # limit our search to text-based parts
    my @txt = $part->find_parts(qr@^text\b@);
    foreach my $text (@txt) {
      # we only care about the rendered version of the part
      my ($type, $rnd) = $text->rendered();
      next unless defined $type;

      # parse the rendered text into tokens.  assume they are whitespace
      # separated, and ignore anything that doesn't have a word-character
      # in it (0-9a-zA-Z_) since those are probably things like bullet
      # points, horizontal lines, etc.  this assumes that punctuation
      # in one part will be the same in other parts.
      #
      if ($type eq 'text/html') {
        foreach my $w (grep(/\w/, split(/\s+/, $rnd))) {
	  #dbg("eval: HTML: $w");
          $html{$w}++;
        }

	# If there are no words, mark if there's at least 1 image ...
	if (!%html && exists $text->{html_results}{inside}{img}) {
	  # Use "\n" as the mark since it can't ever occur normally
	  $html{"\n"}=1;
	}
      }
      else {
        foreach my $w (grep(/\w/, split(/\s+/, $rnd))) {
	  #dbg("eval: TEXT: $w");
          $text{$w}++;
        }
      }
    }

    # How many HTML tokens do we have at the start?
    my $orig = keys %html;
    next if ($orig == 0);

    $pms->{madiff_html} = $orig;
    $pms->{madiff_text} = keys %text;
    dbg('eval: text words: ' . $pms->{madiff_text} . ', html words: ' . $pms->{madiff_html});

    # If the token appears at least as many times in the text part as
    # in the html part, remove it from the list of html tokens.
    while(my ($k,$v) = each %text) {
      delete $html{$k} if (exists $html{$k} && $html{$k}-$text{$k} < 1);
    }

    #map { dbg("eval: LEFT: $_") } keys %html;

    # In theory, the tokens should be the same in both text and html
    # parts, so there would be 0 tokens left in the html token list, for
    # a 0% difference rate.  Calculate it here, and record the difference
    # if it's been the highest so far in this message.
    my $diff = scalar(keys %html)/$orig*100;
    $pms->{madiff} = $diff if ($diff > $pms->{madiff});

    dbg("eval: " . sprintf "madiff: left: %d, orig: %d, max-difference: %0.2f%%", scalar(keys %html), $orig, $pms->{madiff});
  }

  return;
}

sub check_blank_line_ratio {
  my ($self, $pms, $fulltext, $min, $max, $minlines) = @_;

  if (!defined $minlines || $minlines < 1) {
    $minlines = 1;
  }

  my $blank_line_ratio_ref = $pms->{blank_line_ratio};

  if (! exists $blank_line_ratio_ref->{$minlines}) {
    $fulltext = $pms->get_decoded_body_text_array();

    my $blank = 0;
    my $nlines = 0;
    foreach my $chunk (@$fulltext) {
      foreach (split(/^/m, $chunk, -1)) {
        $nlines++;
        $blank++  if !/\S/;
      }
    }

    # report -1 if it's a blank message ...
    $blank_line_ratio_ref->{$minlines} =
      $nlines < $minlines ? -1 : 100 * $blank / $nlines;
  }

  return (($min == 0 && $blank_line_ratio_ref->{$minlines} <= $max) ||
	  ($blank_line_ratio_ref->{$minlines} > $min &&
	   $blank_line_ratio_ref->{$minlines} <= $max));
}

sub tvd_vertical_words {
  my ($self, $pms, $text, $min, $max) = @_;

  # klugy
  $max = 101 if ($max >= 100);

  if (!defined $pms->{tvd_vertical_words}) {
    $pms->{tvd_vertical_words} = -1;

    foreach (@{$text}) {
      my $l = length $_;
      next unless ($l > 5);
      my $spaces = tr/ / /;
      my $nonspaces = $l - $spaces;
      my $pct;
      if ($spaces > $nonspaces || $nonspaces == 0) {
        $pct = 100;
      }
      else {
        $pct = int(100*$spaces/$nonspaces);
      }
      $pms->{tvd_vertical_words} = $pct if ($pct > $pms->{tvd_vertical_words});
    }
  }

  dbg("eval: tvd_vertical_words value: $pms->{tvd_vertical_words} / min: $min / max: $max - value must be >= min and < max");
  return ($pms->{tvd_vertical_words} >= $min && $pms->{tvd_vertical_words} < $max);
}

sub check_stock_info {
  my ($self, $pms, $fulltext, $min) = @_;

  $self->_check_stock_info($pms) unless (exists $pms->{stock_info});

  if ($min == 0 || $pms->{stock_info} >= $min) {
      return 1;
  }
  return 0;
}

sub _check_stock_info {
  my ($self, $pms) = @_;
  $pms->{stock_info} = 0;

  # Find all multipart/alternative parts in the message
  my @parts = $pms->{msg}->find_parts(qr@^text/plain$@);
  return if (!@parts);

  # Go through each of the multipart parts
  my %hits;
  my $part = $parts[0];
  my ($type, $rnd) = $part->rendered();
  return unless $type;

  # bug 5644,5717: avoid pathological cases where a regexp takes massive amount
  # of time by applying the regexp to limited-size text chunks, one at a time

  foreach my $rnd_chunk (
    Mail::SpamAssassin::Message::split_into_array_of_short_paragraphs($rnd))
  {
    foreach ( $rnd_chunk =~ /^\s*([^:\s][^:\n]{2,29})\s*:\s*\S/mg ) {
      my $str = lc $_;
      $str =~ tr/a-z//cd;
      #$str =~ s/([a-z])0([a-z])/$1o$2/g;

      if ($str =~ /(
        ^trad(?:e|ing)date|
        company(?:name)?|
        s\w?(?:t\w?o\w?c\w?k|y\w?m(?:\w?b\w?o\w?l)?)|
        t(?:arget|icker)|
        (?:opening|current)p(?:rice)?|
        p(?:rojected|osition)|
        expectations|
        weeks?high|
        marketperformance|
        (?:year|week|month|day|price)(?:target|estimates?)|
        sector|
        r(?:ecommendation|ating)
      )$/x) {
        $hits{$1}++;
        dbg("eval: stock info hit: $1");
      }
    }
  }

  $pms->{stock_info} = scalar keys %hits;
  dbg("eval: stock info total: ".$pms->{stock_info});

  return;
}

sub check_body_length {
  my ($self, $pms, undef, $min) = @_;

  my $body_length = $pms->{msg}->{pristine_body_length};
  dbg("eval: body_length - %s - check for min of %s", $body_length, $min);

  return (defined $body_length && $body_length <= $min) ? 1 : 0;
}


# For plain text parts with a signature delimiter, evaluate the ratio and
# lengths (in bytes) of the body and signature parts.
# 
# Arguments: min and (optional) max value
# 
#   body  __SIG_RATIO_EXCESSIVE  eval:plaintext_body_sig_ratio('0','0.5')

sub plaintext_body_length {
  my ($self, $pms, undef, $min, $max) = @_;

  $self->_plaintext_body_sig_ratio($pms);

  my $len = $pms->{plaintext_body_sig_ratio}->{body_length};

  return (    defined $len
	   && $len >= $min
	   && (defined $max ? $len <= $max : 1) ) ? 1 : 0;
}

sub plaintext_sig_length {
  my ($self, $pms, undef, $min, $max) = @_;

  $self->_plaintext_body_sig_ratio($pms);

  my $len = $pms->{plaintext_body_sig_ratio}->{sig_length};

  return (    defined $len
	   && $len >= $min
	   && (defined $max ? $len <= $max : 1) ) ? 1 : 0;
}

sub plaintext_body_sig_ratio {
  my ($self, $pms, undef, $min, $max) = @_;

  $self->_plaintext_body_sig_ratio($pms);

  my $len = $pms->{plaintext_body_sig_ratio}->{ratio};

  return (    defined $len
	   && $len >= $min
	   && (defined $max ? $len <= $max : 10**6) ) ? 1 : 0;
}

sub _plaintext_body_sig_ratio {
  my ($self, $pms) = @_;

  return if exists $pms->{plaintext_body_sig_ratio};

  $pms->{plaintext_body_sig_ratio} = {};

  # Find the first text/plain MIME part.

  # Naive approach.  This should commonly match the text/plain part we want,
  # but could be enhanced to better cope with complex MIME structures.
  my $part = ($pms->{msg}->find_parts(qr/^text\/plain/))[0];

  return unless defined $part;

  # Decode if necessary, do not render or alter whitespace.
  my $text = $part->decode();

  # Find the last occurence of a signature delimiter and get the body and
  # signature lengths.

  my $len_b = length($text);
  my $len_s = 0;

  while ($text =~ /^-- ?\r?$/mg) {

    # ignore decoy marker at the end
    next if ( length($text) - $+[0] <= 4 );

    $len_b = $-[0];
    $len_s = length($text) - $+[0];
  }

  $pms->{plaintext_body_sig_ratio}->{body_length} = $len_b;
  $pms->{plaintext_body_sig_ratio}->{sig_length}  = $len_s;

  $pms->{plaintext_body_sig_ratio}->{ratio} = $len_s ? $len_b/$len_s : 10**6;

  return 1;
}


# ---------------------------------------------------------------------------

# capability checks for "if can()":
#
sub has_check_body_length { 1 }

sub has_plaintext_body_sig_ratio { 1 }

1;
