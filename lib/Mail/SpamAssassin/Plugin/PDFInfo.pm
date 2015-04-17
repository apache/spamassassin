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

=head1 NAME

Mail::SpamAssassin::Plugin::PDFInfo - PDFInfo Plugin for SpamAssassin

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::PDFInfo

=head1 DESCRIPTION

This plugin helps detected spam using attached PDF files

=over 4

=item See "Usage:" below - more documentation see 20_pdfinfo.cf

 Original info kept for history.
 -------------------------------------------------------
 PDFInfo Plugin for SpamAssassin
 Version: 0.8
 Info: $Id: PDFInfo.pm 904 2007-08-12 01:36:23Z root $
 Created: 2007-08-10
 Modified: 2007-08-10
 By: Dallas Engelken


 Changes:
   0.8 - added .fdf detection (thanks John Lundin) [axb]
   0.7 - fixed empty body/pdf count buglet(thanks Jeremy) [axb]
   0.6 - added support for tags - PDFCOUNT, PDFVERSION, PDFPRODUCER, etc.
       - fixed issue on perl 5.6.1 where pdf_match_details() failed to call
         _find_pdf_mime_parts(), resulting in no detection of pdf mime parts.
       - quoted-printable support - requires MIME::QuotedPrint (which should be in everyones
         install as a part of the MIME-Base64 package which is a SA req)
       - added simple pdf_is_empty_body() function with counts the body bytes minus the
         subject line.  can add optional <bytes> param if you need to allow for a few bytes.
   0.5 - fix warns for undef $pdf_tags
       - remove { } and \ before running eval in pdf_match_details to avoid eval error
   0.4 - added pdf_is_encrypted() function
       - added option to look for image HxW on same line
   0.3 - added 2nd fuzzy md5 which uses pdf tag layout as data
       - renamed pdf_image_named() to pdf_named()
          - PDF images are encapsulated and have no names.  We are matching the PDF file name.
       - renamed pdf_image_name_regex() to pdf_name_regex()
          - PDF images are encapsulated and have no names.  We are matching the PDF file name.
       - changed pdf_image_count() a bit and added pdf_count().
          - pdf_count() checks how many pdf attachments there are on the mail
          - pdf_image_count() checks how many images are found within all pdfs in the mail.
       - removed the restriction of the pdf containing an image in order to md5 it.
       - added pdf_match_details() function to check the following 'details'
          - author: Author of PDF if specified
          - producer: Software used to produce PDF
          - creator: Software used to produce PDF, usually similar to producer
          - title: Title of PDF
          - created: Creation Date
          - modified: Last Modified
   0.2 - support PDF octet-stream
   0.1 - just ported over the imageinfo code, and renamed to pdfinfo.
         - removed all support for png, gif, and jpg from the code.
         - prepended pdf_ to all function names to avoid conflicts with ImageInfo in SA 3.2.


 Usage:

  pdf_count()

     body RULENAME  eval:pdf_count(<min>,[max])
        min: required, message contains at least x pdf mime parts
        max: optional, if specified, must not contain more than x pdf mime parts

  pdf_image_count()

     body RULENAME  eval:pdf_image_count(<min>,[max])
        min: required, message contains at least x images in pdf attachments.
        max: optional, if specified, must not contain more than x pdf images

  pdf_pixel_coverage()

     body RULENAME  eval:pdf_pixel_coverage(<min>,[max])
        min: required, message contains at least this much pixel area
        max: optional, if specified, message must not contain more than this much pixel area

  pdf_named()

     body RULENAME  eval:pdf_named(<string>)
        string: exact file name match, if you need partial match, see pdf_name_regex()

  pdf_name_regex()

     body RULENAME  eval:pdf_name_regex(<regex>)
        regex: regular expression, see examples in ruleset

  pdf_match_md5()

     body RULENAME  eval:pdf_match_md5(<string>)
        string: 32-byte md5 hex

  pdf_match_fuzzy_md5()

     body RULENAME  eval:pdf_match_md5(<string>)
        string: 32-byte md5 hex - see ruleset for obtaining the fuzzy md5

  pdf_match_details()

     body RULENAME  eval:pdf_match_details(<detail>,<regex>);
        detail: author, creator, created, modified, producer, title
        regex: regular expression, see examples in ruleset

  pdf_is_encrypted()

     body RULENAME eval:pdf_is_encrypted()

  pdf_is_empty_body()

     body RULENAME eval:pdf_is_empty_body(<bytes>)
        bytes: maximum byte count to allow and still consider it empty

  NOTE: See the ruleset for more examples that are not documented here.

=back

=cut

# -------------------------------------------------------

package Mail::SpamAssassin::Plugin::PDFInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;
use Digest::MD5 qw(md5_hex);
use MIME::QuotedPrint;

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

  $self->register_eval_rule ("pdf_count");
  $self->register_eval_rule ("pdf_image_count");
  $self->register_eval_rule ("pdf_pixel_coverage");
  $self->register_eval_rule ("pdf_image_size_exact");
  $self->register_eval_rule ("pdf_image_size_range");
  $self->register_eval_rule ("pdf_named");
  $self->register_eval_rule ("pdf_name_regex");
  $self->register_eval_rule ("pdf_image_to_text_ratio");
  $self->register_eval_rule ("pdf_match_md5");
  $self->register_eval_rule ("pdf_match_fuzzy_md5");
  $self->register_eval_rule ("pdf_match_details");
  $self->register_eval_rule ("pdf_is_encrypted");
  $self->register_eval_rule ("pdf_is_empty_body");

  return $self;
}

# -----------------------------------------

my %get_details = (
  'pdf' => sub {
    my ($self, $pms, $part) = @_;

    my $type = $part->{'type'} || 'base64';
    my $data = '';

    if ($type eq 'quoted-printable') {
      $data = decode_qp($data); # use QuotedPrint->decode_qp
    }
    else {
      $data = $part->decode();  # just use built in base64 decoder
    }

    my $index = substr($data, 0, 8);

    return unless ($index =~ /.PDF\-(\d\.\d)/);
    my $version = $1;
    $self->_set_tag($pms, 'PDFVERSION', $version);
    # dbg("pdfinfo: pdf version = $version");

    my ($height, $width, $fuzzy_data, $pdf_tags);
    my ($producer, $created, $modified, $title, $creator, $author) = ('unknown','0','0','untitled','unknown','unknown');
    my ($md5, $fuzzy_md5) = ('', '');
    my ($total_height, $total_width, $total_area, $line_count) = (0,0,0,0);

    my $name = $part->{'name'} || '';
    $self->_set_tag($pms, 'PDFNAME', $name);

    my $no_more_fuzzy = 0;
    my $got_image = 0;
    my $encrypted = 0;

    while($data =~ /([^\n]+)/g) {
      # dbg("pdfinfo: line=$1");
      my $line = $1;

      $line_count++;

      # lines containing high bytes will have no data we need, so save some cycles
      next if ($line =~ /[\x80-\xff]/);

      if (!$no_more_fuzzy && $line_count < 70) {
        if ($line !~ m/^\%/ && $line !~ m/^\/(?:Height|Width|(?:(?:Media|Crop)Box))/ && $line !~ m/^\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+cm$/) {
          $line =~ s/\s+$//;  # strip off whitespace at end.
          $fuzzy_data .= $line;
	}
      }

      if ($line =~ m/^\/([A-Za-z]+)/) {
         $pdf_tags .= $1;
      }

      $got_image=1 if ($line =~ m/\/Image/);
      $encrypted=1 if ($line =~ m/^\/Encrypt/);

      # once we hit the first stream, we stop collecting data for fuzzy md5
      $no_more_fuzzy = 1 if ($line =~ m/stream/);

      # From a v1.3 pdf
      # [12234] dbg: pdfinfo: line=630 0 0 149 0 0 cm
      # [12234] dbg: pdfinfo: line=/Width 630
      # [12234] dbg: pdfinfo: line=/Height 149
      if ($got_image) {
        if ($line =~ /^(\d+)\s+\d+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+cm$/) {
          $width = $1;
          $height = $2;
        }
        elsif ($line =~ /^\/Width\s(\d+)/) {
          $width = $1;
        }
        elsif ($line =~ /^\/Height\s(\d+)/) {
          $height = $1;
        }
        elsif ($line =~ m/\/Width\s(\d+)\/Height\s(\d+)/) {
          $width = $1;
          $height = $2;
        }
      }

      # did pdf contain image data?
      if ($got_image && $width && $height) {
        $no_more_fuzzy = 1;
        my $area = $width * $height;
        $total_height += $height;
        $total_width += $width;
        $total_area += $area;
        $pms->{pdfinfo}->{dems_pdf}->{"${height}x${width}"} = 1;
        $pms->{'pdfinfo'}->{"count_pdf_images"} ++;
        dbg("pdfinfo: Found image in PDF ".($name ? $name : '')." - $height x $width pixels ($area pixels sq.)");
        $self->_set_tag($pms, 'PDFIMGDIM', "${height}x${width}");
        $height=0; $width=0;  # reset and check for next image
        $got_image = 0;
      }

      # [5310] dbg: pdfinfo: line=<</Producer(GPL Ghostscript 8.15)
      # [5310] dbg: pdfinfo: line=/CreationDate(D:20070703144220)
      # [5310] dbg: pdfinfo: line=/ModDate(D:20070703144220)
      # [5310] dbg: pdfinfo: line=/Title(Microsoft Word - Document1)
      # [5310] dbg: pdfinfo: line=/Creator(PScript5.dll Version 5.2)
      # [5310] dbg: pdfinfo: line=/Author(colet)>>endobj
      # or all on same line inside xml - v1.6+
      # <</CreationDate(D:20070226165054-06'00')/Creator( Adobe Photoshop CS2 Windows)/Producer(Adobe Photoshop for Windows -- Image Conversion Plug-in)/ModDate(D:20070226165100-06'00')>>

      if ($line =~ /\/Producer\s?\(([^\)\\]+)/) {
        $producer = $1;
      }
      if ($line =~ /\/CreationDate\s?\(D\:(\d+)/) {
        $created = $1;
      }
      if ($line =~ /\/ModDate\s?\(D\:(\d+)/) {
        $modified = $1;
      }
      if ($line =~ /\/Title\s?\(([^\)\\]+)/) {
        $title = $1;
        # Title=\376\377\000w\000w\000n\000g
        # Title=wwng
        $title =~ s/\\\d{3}//g;
      }
      if ($line =~ /\/Creator\s?\(([^\)\\]+)/) {
        $creator = $1;
      }
      if ($line =~ /\/Author\s?\(([^\)]+)/) {
        $author = $1;
        # Author=\376\377\000H\000P\000_\000A\000d\000m\000i\000n\000i\000s\000t\000r\000a\000t\000o\000r
        # Author=HP_Administrator
        $author =~ s/\\\d{3}//g;
      }
    }

    # store the file name so we can check pdf_named() or pdf_name_match() later.
    $pms->{pdfinfo}->{names_pdf}->{$name} = 1 if $name;

    # store encrypted flag.
    $pms->{pdfinfo}->{encrypted} = $encrypted;

    # if we had multiple images in the pdf, we need to store the total HxW as well.
    # If it was a single Image PDF, then this value will already be in the hash.
    $pms->{pdfinfo}->{dems_pdf}->{"${total_height}x${total_width}"} = 1 if ($total_height && $total_width);;

    if ($total_area) {
      $pms->{pdfinfo}->{pc_pdf} = $total_area;
      $self->_set_tag($pms, 'PDFIMGAREA', $total_area);
      dbg("pdfinfo: Filename=$name Total HxW: $total_height x $total_width ($total_area area)") if ($total_area);
    }

    dbg("pdfinfo: Filename=$name Title=$title Author=$author Producer=$producer Created=$created Modified=$modified");

    $md5 = uc(md5_hex($data)) if $data;
    $fuzzy_md5 = uc(md5_hex($fuzzy_data)) if $fuzzy_data;
    my $tags_md5;
    $tags_md5 = uc(md5_hex($pdf_tags)) if $pdf_tags;

    dbg("pdfinfo: MD5 results for ".($name ? $name : '')." - md5=".($md5 ? $md5 : '')." fuzzy1=".($fuzzy_md5 ? $fuzzy_md5 : '')." fuzzy2=".($tags_md5 ? $tags_md5 : ''));

    # we dont need tags for these.
    $pms->{pdfinfo}->{details}->{created} = $created if $created;
    $pms->{pdfinfo}->{details}->{modified} = $modified if $modified;

    if ($producer) {
      $pms->{pdfinfo}->{details}->{producer} = $producer if $producer;
      $self->_set_tag($pms, 'PDFPRODUCER', $producer);
    }
    if ($title) {
      $pms->{pdfinfo}->{details}->{title} = $title;
      $self->_set_tag($pms, 'PDFTITLE', $title);
    }
    if ($creator) {
      $pms->{pdfinfo}->{details}->{creator} = $creator;
      $self->_set_tag($pms, 'PDFCREATOR', $creator);
    }
    if ($author) {
      $pms->{pdfinfo}->{details}->{author} = $author;
      $self->_set_tag($pms, 'PDFAUTHOR', $author);
    }
    if ($md5) {
      $pms->{pdfinfo}->{md5}->{$md5} = 1;
      $self->_set_tag($pms, 'PDFMD5', $fuzzy_md5);
    }
    if ($fuzzy_md5) {
      $pms->{pdfinfo}->{fuzzy_md5}->{$fuzzy_md5} = 1;
      $self->_set_tag($pms, 'PDFMD5FUZZY1', $fuzzy_md5);
    }
    if ($tags_md5) {
      $pms->{pdfinfo}->{fuzzy_md5}->{$tags_md5} = 1;
      $self->_set_tag($pms, 'PDFMD5FUZZY2', $tags_md5);
    }
  },

);

# ----------------------------------------

sub _set_tag {

  my ($self, $pms, $tag, $value) = @_;

  dbg("pdfinfo: set_tag called for $tag $value");
  return unless ($tag && $value);

  if (exists $pms->{tag_data}->{$tag}) {
    $pms->{tag_data}->{$tag} .= " $value";  # append value
  }
  else {
    $pms->{tag_data}->{$tag} = $value;
  }
}

# ----------------------------------------

sub _find_pdf_mime_parts {
  my ($self,$pms) = @_;

  # bail early if message does not have pdf parts
  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});

  # initialize
  $pms->{'pdfinfo'}->{"pc_pdf"} = 0;
  $pms->{'pdfinfo'}->{"count_pdf"} = 0;
  $pms->{'pdfinfo'}->{"count_pdf_images"} = 0;

  my @parts = $pms->{msg}->find_parts(qr@^(image|application)/(pdf|octet\-stream)$@, 1);
  my $part_count = scalar @parts;

  dbg("pdfinfo: Identified $part_count possible mime parts that need checked for PDF content");

  # cache this so we can easily bail
  $pms->{'pdfinfo'}->{'no_parts'} = 1 unless $part_count;

  foreach my $p (@parts) {
    my $type = $p->{'type'} =~ m@/([\w\-]+)$@;
    my $name = $p->{'name'};

    my $cte = lc $p->get_header('content-transfer-encoding') || '';

    dbg("pdfinfo: found part, type=".($type ? $type : '')." file=".($name ? $name : '')." cte=".($cte ? $cte : '')."");

    # make sure its a cte we support
    next unless ($cte =~ /^(?:base64|quoted\-printable)$/);

    # filename must end with .pdf, or application type can be pdf
    # sometimes windows muas will wrap a pdf up inside a .dat file
    # v0.8 - Added .fdf phoney PDF detection
    next unless ($name =~ /\.[fp]df$/ || $type eq 'pdf');

    # if we get this far, make sure type is pdf for sure (not octet-stream or anything else)
    $type='pdf';

    if ($type && exists $get_details{$type}) {
       $get_details{$type}->($self, $pms, $p);
       $pms->{'pdfinfo'}->{"count_$type"} ++;
    }
  }

  $self->_set_tag($pms, 'PDFCOUNT',  $pms->{'pdfinfo'}->{"count_pdf"});
  $self->_set_tag($pms, 'PDFIMGCOUNT', $pms->{'pdfinfo'}->{"count_pdf_images"});

}


# ----------------------------------------

sub pdf_named {
  my ($self,$pms,$body,$name) = @_;
  return unless (defined $name);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});

  return 0 unless (exists $pms->{'pdfinfo'}->{"names_pdf"});
  return 1 if (exists $pms->{'pdfinfo'}->{"names_pdf"}->{$name});
  return 0;
}

# -----------------------------------------

sub pdf_name_regex {
  my ($self,$pms,$body,$re) = @_;
  return unless (defined $re);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"names_pdf"});

  my $hit = 0;
  foreach my $name (keys %{$pms->{'pdfinfo'}->{"names_pdf"}}) {
    my $eval = 'if (q{'.$name.'} =~  '.$re.') {  $hit = 1; } ';
    eval $eval;
    dbg("pdfinfo: error in regex $re - $@") if $@;
    if ($hit) {
      dbg("pdfinfo: pdf_name_regex hit on $name");
      return 1;
    }
  }
  return 0;

}

# -----------------------------------------

sub pdf_is_encrypted {
  my ($self,$pms,$body) = @_;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return $pms->{'pdfinfo'}->{'encrypted'};
}

# -----------------------------------------

sub pdf_count {
  my ($self,$pms,$body,$min,$max) = @_;
  return unless defined $min;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"count_pdf"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"count_pdf"});

}

# -----------------------------------------

sub pdf_image_count {
  my ($self,$pms,$body,$min,$max) = @_;
  return unless defined $min;

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"count_pdf_images"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"count_pdf_images"});

}

# -----------------------------------------

sub pdf_pixel_coverage {
  my ($self,$pms,$body,$min,$max) = @_;
  return unless (defined $min);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"pc_pdf"});

  # dbg("pdfinfo: pc_$type: $min, ".($max ? $max:'').", $type, ".$pms->{'pdfinfo'}->{"pc_pdf"});
  return result_check($min, $max, $pms->{'pdfinfo'}->{"pc_pdf"});
}

# -----------------------------------------

sub pdf_image_to_text_ratio {
  my ($self,$pms,$body,$min,$max) = @_;
  return unless (defined $min && defined $max);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"pc_pdf"});

  # depending on how you call this eval (body vs rawbody),
  # the $textlen will differ.
  my $textlen = length(join('',@$body));

  return 0 unless ( $textlen > 0 && exists $pms->{'pdfinfo'}->{"pc_pdf"} && $pms->{'pdfinfo'}->{"pc_pdf"} > 0);

  my $ratio = $textlen / $pms->{'pdfinfo'}->{"pc_pdf"};
  dbg("pdfinfo: image ratio=$ratio, min=$min max=$max");
  return result_check($min, $max, $ratio, 1);
}

# -----------------------------------------

sub pdf_is_empty_body {
  my ($self,$pms,$body,$min) = @_;

  $min ||= 0;  # default to 0 bytes

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless $pms->{'pdfinfo'}->{"count_pdf"};

  # check for cached result
  return 1 if $pms->{'pdfinfo'}->{"no_body_text"};

  shift @$body;  # shift body array removes line #1 -> subject line.

  my $bytes = 0;
  my $textlen = length(join('',@$body));
  foreach my $line (@$body) {
    next unless ($line =~ m/\S/);
    next if ($line =~ m/^Subject/);
    $bytes += length($line);
  }

  dbg("pdfinfo: is_empty_body = $bytes bytes");

  if ($bytes == 0 || ($bytes <= $min)) {
    $pms->{'pdfinfo'}->{"no_body_text"} = 1;
    return 1;
  }

  # cache it and return 0
  $pms->{'pdfinfo'}->{"no_body_text"} = 0;
  return 0;
}

# -----------------------------------------

sub pdf_image_size_exact {
  my ($self,$pms,$body,$height,$width) = @_;
  return unless (defined $height && defined $width);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"dems_pdf"});
  return 1 if (exists $pms->{'pdfinfo'}->{"dems_pdf"}->{"${height}x${width}"});
  return 0;
}

# -----------------------------------------

sub pdf_image_size_range {
  my ($self,$pms,$body,$minh,$minw,$maxh,$maxw) = @_;
  return unless (defined $minh && defined $minw);

  # make sure we have image data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"dems_pdf"});

  foreach my $dem ( keys %{$pms->{'pdfinfo'}->{"dems_pdf"}}) {
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

sub pdf_match_md5 {

  my ($self,$pms,$body,$md5) = @_;
  return unless defined $md5;

  my $uc_md5 = uc($md5);  # uppercase matches only

  # make sure we have pdf data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"md5"});
  return 1 if (exists $pms->{'pdfinfo'}->{"md5"}->{$uc_md5});
  return 0;
}

# -----------------------------------------

sub pdf_match_fuzzy_md5 {

  my ($self,$pms,$body,$md5) = @_;
  return unless defined $md5;

  my $uc_md5 = uc($md5);  # uppercase matches only

  # make sure we have pdf data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{"fuzzy_md5"});
  return 1 if (exists $pms->{'pdfinfo'}->{"fuzzy_md5"}->{$uc_md5});
  return 0;
}

# -----------------------------------------

sub pdf_match_details {
  my ($self, $pms, $body, $detail, $regex) = @_;
  return unless ($detail && $regex);

  # make sure we have pdf data read in.
  if (!exists $pms->{'pdfinfo'}) {
    $self->_find_pdf_mime_parts($pms);
  }

  return 0 if (exists $pms->{'pdfinfo'}->{'no_parts'});
  return 0 unless (exists $pms->{'pdfinfo'}->{'details'});

  my $check_value = $pms->{pdfinfo}->{details}->{$detail};
  return unless $check_value;

  my $hit = 0;
  $check_value =~ s/[\{\}\\]//g;
  my $eval = 'if (q{'.$check_value.'} =~ '.$regex.') { $hit = 1; }';
  eval $eval;
  dbg("pdfinfo: error in regex $regex - $@") if $@;
  if ($hit) {
    dbg("pdfinfo: pdf_match_details $detail $regex matches $check_value");
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

