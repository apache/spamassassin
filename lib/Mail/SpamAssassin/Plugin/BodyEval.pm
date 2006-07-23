# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_unique_words");
  $self->register_eval_rule("multipart_alternative_difference");
  $self->register_eval_rule("multipart_alternative_difference_count");
  $self->register_eval_rule("check_blank_line_ratio");
  $self->register_eval_rule("tvd_vertical_words");

  return $self;
}

sub check_unique_words {
  my ($self, $pms, $body, $m, $b) = @_;

  if (!defined $pms->{unique_words_repeat}) {
    $pms->{unique_words_repeat} = 0;
    $pms->{unique_words_unique} = 0;
    my %count;
    for (@$body) {
      # copy to avoid changing @$body
      my $line = $_;
      # from tokenize_line in Bayes.pm
      $line =~ tr/-A-Za-z0-9,\@\*\!_'"\$.\241-\377 / /cs;
      $line =~ s/(\w)(\.{3,6})(\w)/$1 $2 $3/gs;
      $line =~ s/(\w)(\-{2,6})(\w)/$1 $2 $3/gs;
      $line =~ s/(?:^|\.\s+)([A-Z])([^A-Z]+)(?:\s|$)/ ' '.(lc $1).$2.' '/ge;
      for my $token (split(' ', $line)) {
        $count{$token}++;
      }
    }
    $pms->{unique_words_unique} = scalar grep { $_ == 1 } values(%count);
    $pms->{unique_words_repeat} = scalar keys(%count) - $pms->{unique_words_unique};
  }

  # y = mx+b where y is number of unique words needed
  my $unique = $pms->{unique_words_unique};
  my $repeat = $pms->{unique_words_repeat};
  my $y = ($unique + $repeat) * $m + $b;
  return ($unique > $y);
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
  return(($pms->{madiff_text} / $pms->{madiff_html}) > $ratio);
}

sub _multipart_alternative_difference {
  my ($self, $pms) = @_;
  $pms->{madiff} = 0;
  $pms->{madiff_html} = 0;
  $pms->{madiff_text} = 0;

  my $msg = $pms->{msg};

  # Find all multipart/alternative parts in the message
  my @ma = $msg->find_parts(qr@^multipart/alternative\b@i);

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
    my %html = ();
    my %text = ();

    # limit our search to text-based parts
    my @txt = $part->find_parts(qr@^text\b@i);
    foreach my $text (@txt) {
      # we only care about the rendered version of the part
      my ($type, $rnd) = $text->rendered();

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
	if (keys %html == 0 && exists $pms->{html}{inside}{img}) {
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

  if (! exists $pms->{blank_line_ratio}->{$minlines}) {
    $fulltext = $pms->get_decoded_body_text_array();
    my ($blank) = 0;
    if (scalar @{$fulltext} >= $minlines) {
      foreach my $line (@{$fulltext}) {
        next if ($line =~ /\S/);
        $blank++;
      }
      $pms->{blank_line_ratio}->{$minlines} = 100 * $blank / scalar @{$fulltext};
    }
    else {
      $pms->{blank_line_ratio}->{$minlines} = -1; # don't report if it's a blank message ...
    }
  }

  return (($min == 0 && $pms->{blank_line_ratio}->{$minlines} <= $max) ||
	  ($pms->{blank_line_ratio}->{$minlines} > $min &&
	   $pms->{blank_line_ratio}->{$minlines} <= $max));
}

sub tvd_vertical_words {
  my ($self, $pms, $text, $min, $max) = @_;

  # klugy
  $max = 101 if ($max >= 100);

  if (!defined $pms->{tvd_vertical_words}) {
    $pms->{tvd_vertical_words} = 0;

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

  return 1 if ($pms->{tvd_vertical_words} >= $min && $pms->{tvd_vertical_words} < $max);
}

1;
