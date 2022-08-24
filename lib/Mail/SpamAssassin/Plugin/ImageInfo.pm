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
#
# -------------------------------------------------------
# ImageInfo Plugin for SpamAssassin
# Version: 0.7
# Created: 2006-08-02
# Modified: 2007-01-17
#
# Changes:
#   0.7 - added image_name_regex to allow pattern matching on the image name
#       - added support for image/pjpeg content types (progressive jpeg)
#       - updated imageinfo.cf with a few sample rules for using image_name_regex()
#   0.6 - fixed dems_ bug in image_size_range_
#   0.5 - added image_named and image_to_text_ratio
#   0.4 - added image_size_exact and image_size_range
#   0.3 - added jpeg support
#   0.2 - optimized by theo
#   0.1 - added gif/png support
#
#
# Usage:
#  image_count()
#
#     body RULENAME  eval:image_count(<type>,<min>,[max])
#        type: 'all','gif','png', or 'jpeg'
#        min: required, message contains at least this
#             many images
#        max: optional, if specified, message must not
#             contain more than this number of images
#
#  image_count() examples
#
#     body ONE_IMAGE  eval:image_count('all',1,1)
#     body ONE_OR_MORE_IMAGES  eval:image_count('all',1)
#     body ONE_PNG eval:image_count('png',1,1)
#     body TWO_GIFS eval:image_count('gif',2,2)
#     body MANY_JPEGS eval:image_count('gif',5)
#
#  pixel_coverage()
#
#     body RULENAME  eval:pixel_coverage(<type>,<min>,[max])
#        type: 'all','gif','png', or 'jpeg'
#        min: required, message contains at least this
#             much pixel area
#        max: optional, if specified, message must not
#             contain more than this much pixel area
#
#   pixel_coverage() examples
#
#     body LARGE_IMAGE_AREA  eval:pixel_coverage('all',150000)  # catches any images that are 150k pixel/sq or higher
#     body SMALL_GIF_AREA  eval:pixel_coverage('gif',1,40000)   # catches only gifs that 1 to 40k pixel/sql
#
#  image_name_regex()
#
#     body RULENAME  eval:image_name_regex(<regex>)
#        regex: full quoted regexp, see examples below
#
#  image_name_regex() examples
#
#     body CG_DOUBLEDOT_GIF  eval:image_name_regex('/^\w{2,9}\.\.gif$/i') # catches double dot gifs  abcd..gif
#
#
#
# -------------------------------------------------------

package Mail::SpamAssassin::Plugin::ImageInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
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

  $self->register_eval_rule ("image_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pixel_coverage", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("image_size_exact", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("image_size_range", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("image_named", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("image_name_regex", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("image_to_text_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

# -----------------------------------------

my %get_details = (
  'gif' => sub {
    my ($pms, $part) = @_;
    my $header = $part->decode(13);

    # make sure this is actually a valid gif..
    return unless $header =~ s/^GIF(8[79]a)//;
    my $version = $1;

    my ($width, $height, $packed, $bgcolor, $aspect) = unpack("vvCCC", $header);
    my $color_table_size = 1 << (($packed & 0x07) + 1);

    # for future enhancements
    #my $global_color_table = $packed & 0x80;
    #my $has_global_color_table = $global_color_table ? 1 : 0;
    #my $sorted_colors = ($packed & 0x08)?1:0;
    #my $resolution = ((($packed & 0x70) >> 4) + 1);

    if ($height && $width) {
      my $area = $width * $height;
      $pms->{imageinfo}->{pc_gif} += $area;
      $pms->{imageinfo}->{dems_gif}->{"${height}x${width}"} = 1;
      $pms->{imageinfo}->{names_all}->{$part->{'name'}} = 1 if $part->{'name'};
      dbg("imageinfo: gif image ".($part->{'name'} ? $part->{'name'} : '')." is $height x $width pixels ($area pixels sq.), with $color_table_size color table");
    }
  },

  'png' => sub {
    my ($pms, $part) = @_;
    my $data = $part->decode();

    return unless (substr($data, 0, 8) eq "\x89PNG\x0d\x0a\x1a\x0a");

    my $datalen = length $data;
    my $pos = 8;
    my $chunksize = 8;
    my ($width, $height) = ( 0, 0 );
    my ($depth, $ctype, $compression, $filter, $interlace);

    while ($pos < $datalen) {
      my ($len, $type) = unpack("Na4", substr($data, $pos, $chunksize));
      $pos += $chunksize;

      last if $type eq "IEND";  # end of png image.

      next unless ( $type eq "IHDR" && $len == 13 );

      my $bytes = substr($data, $pos, $len + 4);
      my $crc = unpack("N", substr($bytes, -4, 4, ""));

      if ($type eq "IHDR" && $len == 13) {
        ($width, $height, $depth, $ctype, $compression, $filter, $interlace) = unpack("NNCCCCC", $bytes);
        last;
      }
    }

    if ($height && $width) {
      my $area = $width * $height;
      $pms->{imageinfo}->{pc_png} += $area;
      $pms->{imageinfo}->{dems_png}->{"${height}x${width}"} = 1;
      $pms->{imageinfo}->{names_all}->{$part->{'name'}} = 1 if $part->{'name'};
      dbg("imageinfo: png image ".($part->{'name'} ? $part->{'name'} : '')." is $height x $width pixels ($area pixels sq.)");
    }
  },

  'jpeg' => sub {
    my ($pms, $part) = @_;

    my $data = $part->decode();

    my $index = substr($data, 0, 2);
    return unless $index eq "\xFF\xD8";

    my $pos = 2;
    my $chunksize = 4;
    my ($prec, $height, $width, $comps) = (undef,0,0,undef);
    while  (1) {
      my ($xx, $mark, $len) = unpack("CCn", substr($data, $pos, $chunksize));
      last if (!defined $xx   || $xx != 0xFF);
      last if (!defined $mark || $mark == 0xDA || $mark == 0xD9);
      last if (!defined $len  || $len < 2);
      $pos += $chunksize;
      my $block = substr($data, $pos, $len - 2);
      my $blocklen = length($block);
      if ( ($mark >= 0xC0 && $mark <= 0xC3) || ($mark >= 0xC5 && $mark <= 0xC7) ||
           ($mark >= 0xC9 && $mark <= 0xCB) || ($mark >= 0xCD && $mark <= 0xCF) ) {
        ($prec, $height, $width, $comps) = unpack("CnnC", substr($block, 0, 6, ""));
        last;
      }
      $pos += $blocklen;
    }

    if ($height && $width) {
      my $area = $height * $width;
      $pms->{imageinfo}->{pc_jpeg} += $area;
      $pms->{imageinfo}->{dems_jpeg}->{"${height}x${width}"} = 1;
      $pms->{imageinfo}->{names_all}->{$part->{'name'}} = 1 if $part->{'name'};
      dbg("imageinfo: jpeg image ".($part->{'name'} ? $part->{'name'} : '')." is $height x $width pixels ($area pixels sq.)");
    }

  },

);

sub _get_images {
  my ($self,$pms) = @_;
  my $result = 0;

  foreach my $type ( 'all', keys %get_details ) {
    $pms->{'imageinfo'}->{"pc_$type"} = 0;
    $pms->{'imageinfo'}->{"count_$type"} = 0;
  }

  foreach my $p ($pms->{msg}->find_parts(qr@^image/(?:gif|png|jpe?g)$@, 1)) {
    # make sure its base64 encoded
    my $cte = lc($p->get_header('content-transfer-encoding') || '');
    next if ($cte !~ /^base64$/);

    my ($type) = $p->{'type'} =~ m@/(\w+)$@;
    $type = 'jpeg' if $type eq 'jpg';
    if ($type && exists $get_details{$type}) {
       $get_details{$type}->($pms,$p);
       $pms->{'imageinfo'}->{"count_$type"} ++;
    }
  }

  foreach my $name ( keys %{$pms->{'imageinfo'}->{"names_all"}} ) {
    dbg("imageinfo: image name $name found");
  }

  foreach my $type ( keys %get_details ) {
    $pms->{'imageinfo'}->{'pc_all'} += $pms->{'imageinfo'}->{"pc_$type"};
    $pms->{'imageinfo'}->{'count_all'} += $pms->{'imageinfo'}->{"count_$type"};
    foreach my $dem ( keys %{$pms->{'imageinfo'}->{"dems_$type"}} ) {
      dbg("imageinfo: adding $dem to dems_all");
      $pms->{'imageinfo'}->{'dems_all'}->{$dem} = 1;
    }
  }
}

# -----------------------------------------

sub image_named {
  my ($self,$pms,$body,$name) = @_;
  return 0 unless (defined $name);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'imageinfo'}->{"names_all"});
  return 1 if (exists $pms->{'imageinfo'}->{"names_all"}->{$name});
  return 0;
}

# -----------------------------------------

sub image_name_regex {
  my ($self,$pms,$body,$re) = @_;
  return 0 unless (defined $re);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'imageinfo'}->{"names_all"});

  my $hit = 0;
  foreach my $name (keys %{$pms->{'imageinfo'}->{"names_all"}}) {
    dbg("imageinfo: checking image named $name against regex $re");
    if (eval { $name =~ /$re/ }) { $hit = 1 }
    dbg("imageinfo: error in regex /$re/ - $@") if $@;
    if ($hit) {
      dbg("imageinfo: image_name_regex hit on $name");
      return 1;
    }
  }
  return 0;

}

# -----------------------------------------

sub image_count {
  my ($self,$pms,$body,$type,$min,$max) = @_;

  return 0 unless defined $min;

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  # dbg("imageinfo: count: $min, ".($max ? $max:'').", $type, ".$pms->{'imageinfo'}->{"count_$type"});
  return result_check($min, $max, $pms->{'imageinfo'}->{"count_$type"});
}

# -----------------------------------------

sub pixel_coverage {
  my ($self,$pms,$body,$type,$min,$max) = @_;

  return 0 unless (defined $type && defined $min);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  # dbg("imageinfo: pc_$type: $min, ".($max ? $max:'').", $type, ".$pms->{'imageinfo'}->{"pc_$type"});
  return result_check($min, $max, $pms->{'imageinfo'}->{"pc_$type"});
}

# -----------------------------------------

sub image_to_text_ratio {
  my ($self,$pms,$body,$type,$min,$max) = @_;
  return 0 unless (defined $type && defined $min && defined $max);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  # depending on how you call this eval (body vs rawbody),
  # the $textlen will differ.
  my $textlen = length(join('',@$body));

  return 0 unless ( $textlen > 0 && exists $pms->{'imageinfo'}->{"pc_$type"} && $pms->{'imageinfo'}->{"pc_$type"} > 0);

  my $ratio = $textlen / $pms->{'imageinfo'}->{"pc_$type"};
  dbg("imageinfo: image ratio=$ratio, min=$min max=$max");
  return result_check($min, $max, $ratio, 1);
}

# -----------------------------------------

sub image_size_exact {
  my ($self,$pms,$body,$type,$height,$width) = @_;
  return 0 unless (defined $type && defined $height && defined $width);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  return 0 unless (exists $pms->{'imageinfo'}->{"dems_$type"});
  return 1 if (exists $pms->{'imageinfo'}->{"dems_$type"}->{"${height}x${width}"});
  return 0;
}

# -----------------------------------------

sub image_size_range {
  my ($self,$pms,$body,$type,$minh,$minw,$maxh,$maxw) = @_;
  return 0 unless (defined $type && defined $minh && defined $minw);

  # make sure we have image data read in.
  if (!exists $pms->{'imageinfo'}) {
    $self->_get_images($pms);
  }

  my $name = 'dems_'.$type;
  return 0 unless (exists $pms->{'imageinfo'}->{$name});

  foreach my $dem ( keys %{$pms->{'imageinfo'}->{"dems_$type"}}) {
    my ($h,$w) = split(/x/,$dem);
    next if ($h < $minh);  # height less than min height
    next if ($w < $minw);  # width less than min width
    next if (defined $maxh && $h > $maxh);  # height more than max height
    next if (defined $maxw && $w > $maxw);  # width more than max width

    # if we make it here, we have a match
    return 1;
  }

  return 0;
}

# -----------------------------------------

sub result_check {
  my ($min, $max, $value, $nomaxequal) = @_;
  return 0 unless defined $value;
  return 0 if ($value < $min);
  return 0 if (defined $max && $value > $max);
  return 0 if (defined $nomaxequal && $nomaxequal && $value == $max);
  return 1;
}

# -----------------------------------------

1;
