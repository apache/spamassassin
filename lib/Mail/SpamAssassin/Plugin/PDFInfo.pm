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

 Original info kept for history. For later changes see SVN repo
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

  pdf_image_to_text_ratio()

     body RULENAME eval:pdf_image_to_text_ratio(<min>,<max>)
        Ratio calculated as body_length / total_image_area
        min: minimum ratio
        max: maximum ratio

  pdf_image_size_exact()

     body RULENAME eval:pdf_image_size_exact(<h>,<w>)
        h: image height is exactly h
        w: image width is exactly w

  pdf_image_size_range()

     body RULENAME eval:pdf_image_size_range(<minh>,<minw>,[<maxh>],[<maxw>])
        minh: image height is atleast minh
        minw: image width is atleast minw
        maxh: (optional) image height is no more than maxh
        maxw: (optional) image width is no more than maxw

  NOTE: See the ruleset for more examples that are not documented here.

=back

=cut

# -------------------------------------------------------

package Mail::SpamAssassin::Plugin::PDFInfo;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(compile_regexp);
use strict;
use warnings;
use re 'taint';
use Digest::MD5 qw(md5_hex);

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("pdf_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_image_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_pixel_coverage", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_image_size_exact", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_image_size_range", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_named", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_name_regex", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_image_to_text_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_match_md5", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_match_fuzzy_md5", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_match_details", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_is_encrypted", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf_is_empty_body", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # lower priority for add_uri_detail_list to work
  $self->register_method_priority ("parsed_metadata", -1);

  return $self;
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};

  # initialize
  $pms->{pdfinfo}->{count_pdf} = 0;
  $pms->{pdfinfo}->{count_pdf_images} = 0;

  my @parts = $pms->{msg}->find_parts(qr@^(image|application)/(pdf|octet\-stream)$@, 1);
  my $part_count = scalar @parts;

  dbg("pdfinfo: Identified $part_count possible mime parts that need checked for PDF content");

  foreach my $p (@parts) {
    my $type = $p->{type} || '';
    my $name = $p->{name} || '';

    dbg("pdfinfo: found part, type=$type file=$name");

    # filename must end with .pdf, or application type can be pdf
    # sometimes windows muas will wrap a pdf up inside a .dat file
    # v0.8 - Added .fdf phoney PDF detection
    next unless ($name =~ /\.[fp]df$/i || $type =~ m@/pdf$@);

    _get_pdf_details($pms, $p);
    $pms->{pdfinfo}->{count_pdf}++;
  }

  _set_tag($pms, 'PDFCOUNT',  $pms->{pdfinfo}->{count_pdf});
  _set_tag($pms, 'PDFIMGCOUNT', $pms->{pdfinfo}->{count_pdf_images});
}

sub _get_pdf_details {
  my ($pms, $part) = @_;

  my $data = $part->decode();

  # Remove UTF-8 BOM
  $data =~ s/^\xef\xbb\xbf//;

  # Search magic in first 1024 bytes
  if ($data !~ /^.{0,1024}\%PDF\-(\d\.\d)/s) {
    dbg("pdfinfo: PDF magic header not found, invalid file?");
    return;
  }
  my $version = $1;
  _set_tag($pms, 'PDFVERSION', $version);
  # dbg("pdfinfo: pdf version = $version");

  my ($fuzzy_data, $pdf_tags);
  my ($md5, $fuzzy_md5) = ('','');
  my ($total_height, $total_width, $total_area, $line_count) = (0,0,0,0);

  my $name = $part->{name} || '';
  _set_tag($pms, 'PDFNAME', $name);
  # store the file name so we can check pdf_named() or pdf_name_match() later.
  $pms->{pdfinfo}->{names_pdf}->{$name} = 1 if $name;

  my $no_more_fuzzy = 0;
  my $got_image = 0;
  my $encrypted = 0;
  my %uris;

  while ($data =~ /([^\n]+)/g) {
    # dbg("pdfinfo: line=$1");
    my $line = $1;

    if (!$no_more_fuzzy && ++$line_count < 70) {
      if ($line !~ m/^\%/ && $line !~ m/^\/(?:Height|Width|(?:(?:Media|Crop)Box))/ && $line !~ m/^\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+cm$/) {
        $line =~ s/\s+$//;  # strip off whitespace at end.
        $fuzzy_data .= $line;
      }
      # once we hit the first stream, we stop collecting data for fuzzy md5
      $no_more_fuzzy = 1  if index($line, 'stream') >= 0;
    }

    $got_image = 1  if index($line, '/Image') >= 0;
    if (!$encrypted && index($line, '/Encrypt') == 0) {
      # store encrypted flag.
      $encrypted = $pms->{pdfinfo}->{encrypted} = 1;
    }

    # From a v1.3 pdf
    # [12234] dbg: pdfinfo: line=630 0 0 149 0 0 cm
    # [12234] dbg: pdfinfo: line=/Width 630
    # [12234] dbg: pdfinfo: line=/Height 149
    if ($got_image) {
      my ($width, $height);
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
      if ($width && $height) {
        $no_more_fuzzy = 1;
        my $area = $width * $height;
        $total_height += $height;
        $total_width += $width;
        $total_area += $area;
        $pms->{pdfinfo}->{dems_pdf}->{"${height}x${width}"} = 1;
        $pms->{pdfinfo}->{count_pdf_images}++;
        dbg("pdfinfo: Found image in PDF $name: $height x $width pixels ($area pixels sq.)");
        _set_tag($pms, 'PDFIMGDIM', "${height}x${width}");
        $got_image = $height = $width = 0;  # reset and check for next image
      }
    }

    #
    # Triage - expecting / to be found for rest of the checks
    #
    next unless index($line, '/') >= 0;

    if ($line =~ m/^\/([A-Za-z]+)/) {
      $pdf_tags .= $1;
    }

    # XXX some pdf have uris but are stored inside binary data
    if (keys %uris < 20 && $line =~ /(?:\/S\s{0,2}\/URI\s{0,2}|^\s*)\/URI\s{0,2}( \( .*? (?<!\\) \) | < [^>]* > )|\((https?:\/\/.{8,256})\)>>/x) {
      my $location;
      if (defined $1 and (index($1, '.') > 0)) {
        $location = _parse_string($1);
      }
      if (not defined($location) or index($location, '.') <= 0) {
        $location = _parse_string($2);
      }
      next unless index($location, '.') > 0; # ignore some binary mess
      next if $location =~ /\0/; # ignore urls with NUL characters
      if (!exists $uris{$location}) {
        $uris{$location} = 1;
        dbg("pdfinfo: found URI: $location");
        $pms->add_uri_detail_list($location);
      }
    }

    # [5310] dbg: pdfinfo: line=<</Producer(GPL Ghostscript 8.15)
    # [5310] dbg: pdfinfo: line=/CreationDate(D:20070703144220)
    # [5310] dbg: pdfinfo: line=/ModDate(D:20070703144220)
    # [5310] dbg: pdfinfo: line=/Title(Microsoft Word - Document1)
    # [5310] dbg: pdfinfo: line=/Creator(PScript5.dll Version 5.2)
    # [5310] dbg: pdfinfo: line=/Author(colet)>>endobj
    # or all on same line inside xml - v1.6+
    # <</CreationDate(D:20070226165054-06'00')/Creator( Adobe Photoshop CS2 Windows)/Producer(Adobe Photoshop for Windows -- Image Conversion Plug-in)/ModDate(D:20070226165100-06'00')>>
    # Or hex values
    # /Creator<FEFF005700720069007400650072>
    if ($line =~ /\/Author\s{0,2}( \( .*? (?<!\\) \) | < [^>]* > )/x) {
      my $author = _parse_string($1);
      dbg("pdfinfo: found property Author=$author");
      $pms->{pdfinfo}->{details}->{author}->{$author} = 1;
      _set_tag($pms, 'PDFAUTHOR', $author);
    }
    if ($line =~ /\/Creator\s{0,2}( \( .*? (?<!\\) \) | < [^>]* > )/x) {
      my $creator = _parse_string($1);
      dbg("pdfinfo: found property Creator=$creator");
      $pms->{pdfinfo}->{details}->{creator}->{$creator} = 1;
      _set_tag($pms, 'PDFCREATOR', $creator);
    }
    if ($line =~ /\/CreationDate\s{0,2}\(D\:(\d+)/) {
      my $created = _parse_string($1);
      dbg("pdfinfo: found property Created=$created");
      $pms->{pdfinfo}->{details}->{created}->{$created} = 1;
    }
    if ($line =~ /\/ModDate\s{0,2}\(D\:(\d+)/) {
      my $modified = _parse_string($1);
      dbg("pdfinfo: found property Modified=$modified");
      $pms->{pdfinfo}->{details}->{modified}->{$modified} = 1;
    }
    if ($line =~ /\/Producer\s{0,2}( \( .*? (?<!\\) \) | < [^>]* > )/x) {
      my $producer = _parse_string($1);
      dbg("pdfinfo: found property Producer=$producer");
      $pms->{pdfinfo}->{details}->{producer}->{$producer} = 1;
      _set_tag($pms, 'PDFPRODUCER', $producer);
    }
    if ($line =~ /\/Title\s{0,2}( \( .*? (?<!\\) \) | < [^>]* > )/x) {
      my $title = _parse_string($1);
      dbg("pdfinfo: found property Title=$title");
      $pms->{pdfinfo}->{details}->{title}->{$title} = 1;
      _set_tag($pms, 'PDFTITLE', $title);
    }
  }

  # if we had multiple images in the pdf, we need to store the total HxW as well.
  # If it was a single Image PDF, then this value will already be in the hash.
  $pms->{pdfinfo}->{dems_pdf}->{"${total_height}x${total_width}"} = 1 if ($total_height && $total_width);

  if ($total_area) {
    $pms->{pdfinfo}->{pc_pdf} = $total_area;
    _set_tag($pms, 'PDFIMGAREA', $total_area);
    dbg("pdfinfo: Total HxW: $total_height x $total_width ($total_area area)");
  }

  $md5 = uc(md5_hex($data)) if $data;
  $fuzzy_md5 = uc(md5_hex($fuzzy_data)) if $fuzzy_data;
  my $tags_md5 = '';
  $tags_md5 = uc(md5_hex($pdf_tags)) if $pdf_tags;

  dbg("pdfinfo: MD5 results for $name: md5=$md5 fuzzy1=$fuzzy_md5 fuzzy2=$tags_md5");

  if ($md5) {
    $pms->{pdfinfo}->{md5}->{$md5} = 1;
    _set_tag($pms, 'PDFMD5', $fuzzy_md5);
  }
  if ($fuzzy_md5) {
    $pms->{pdfinfo}->{fuzzy_md5}->{$fuzzy_md5} = 1;
    _set_tag($pms, 'PDFMD5FUZZY1', $fuzzy_md5);
  }
  if ($tags_md5) {
    $pms->{pdfinfo}->{fuzzy_md5}->{$tags_md5} = 1;
    _set_tag($pms, 'PDFMD5FUZZY2', $tags_md5);
  }
}

sub _parse_string {
  local $_ = shift;
  # Anything inside < > is hex encoded
  if (/^</) {
    # Might contain whitespace so search all hex values
    my $str = '';
    $str .= pack("H*", $1) while (/([0-9A-Fa-f]{2})/g);
    $_ = $str;
    # Handle/strip UTF-16 (in ultra-naive way for now)
    s/\x00//g if (s/^(?:\xfe\xff|\xff\xfe)//);
  } else {
    s/^\(//; s/\)$//;
    # Decode octals
    # Author=\376\377\000H\000P\000_\000A\000d\000m\000i\000n\000i\000s\000t\000r\000a\000t\000o\000r
    s/(?<!\\)\\([0-3][0-7][0-7])/pack("C",oct($1))/ge;
    # Handle/strip UTF-16 (in ultra-naive way for now)
    s/\x00//g if (s/^(?:\xfe\xff|\xff\xfe)//);
    # Unescape some stuff like \\ \( \)
    # Title(Foo \(bar\))
    s/\\([()\\])/$1/g;
  }
  # Limit to some sane length
  return substr($_, 0, 256);
}

sub _set_tag {
  my ($pms, $tag, $value) = @_;

  return unless defined $value && $value ne '';
  dbg("pdfinfo: set_tag called for $tag: $value");

  if (exists $pms->{tag_data}->{$tag}) {
    # Limit to some sane length
    if (length($pms->{tag_data}->{$tag}) < 2048) {
      $pms->{tag_data}->{$tag} .= ' '.$value;  # append value
    }
  }
  else {
    $pms->{tag_data}->{$tag} = $value;
  }
}

sub pdf_named {
  my ($self, $pms, $body, $name) = @_;

  return 0 unless defined $name;

  return 1 if exists $pms->{pdfinfo}->{names_pdf}->{$name};
  return 0;
}

sub pdf_name_regex {
  my ($self, $pms, $body, $regex) = @_;

  return 0 unless defined $regex;
  return 0 unless exists $pms->{pdfinfo}->{names_pdf};

  my ($rec, $err) = compile_regexp($regex, 2);
  if (!$rec) {
    my $rulename = $pms->get_current_eval_rule_name();
    warn "pdfinfo: invalid regexp for $rulename '$regex': $err";
    return 0;
  }

  foreach my $name (keys %{$pms->{pdfinfo}->{names_pdf}}) {
    if ($name =~ $rec) {
      dbg("pdfinfo: pdf_name_regex hit on $name");
      return 1;
    }
  }

  return 0;
}

sub pdf_is_encrypted {
  my ($self, $pms, $body) = @_;

  return $pms->{pdfinfo}->{encrypted} ? 1 : 0;
}

sub pdf_count {
  my ($self, $pms, $body, $min, $max) = @_;

  return _result_check($min, $max, $pms->{pdfinfo}->{count_pdf});
}

sub pdf_image_count {
  my ($self, $pms, $body, $min, $max) = @_;

  return _result_check($min, $max, $pms->{pdfinfo}->{count_pdf_images});
}

sub pdf_pixel_coverage {
  my ($self,$pms,$body,$min,$max) = @_;

  return _result_check($min, $max, $pms->{pdfinfo}->{pc_pdf});
}

sub pdf_image_to_text_ratio {
  my ($self, $pms, $body, $min, $max) = @_;

  return 0 unless defined $max;
  return 0 unless $pms->{pdfinfo}->{pc_pdf};

  # depending on how you call this eval (body vs rawbody),
  # the $textlen will differ.
  my $textlen = length(join('', @$body));
  return 0 unless $textlen;

  my $ratio = $textlen / $pms->{pdfinfo}->{pc_pdf};
  dbg("pdfinfo: image ratio=$ratio, min=$min max=$max");

  return _result_check($min, $max, $ratio, 1);
}

sub pdf_is_empty_body {
  my ($self, $pms, $body, $min) = @_;

  return 0 unless $pms->{pdfinfo}->{count_pdf};
  $min ||= 0;  # default to 0 bytes

  my $bytes = 0;
  my $idx = 0;
  foreach my $line (@$body) {
    next if $idx++ == 0; # skip subject line
    next unless $line =~ /\S/;
    $bytes += length($line);
    # no hit if minimum already exceeded
    return 0 if $bytes > $min;
  }

  dbg("pdfinfo: pdf_is_empty_body matched ($bytes <= $min)");
  return 1;
}

sub pdf_image_size_exact {
  my ($self, $pms, $body, $height, $width) = @_;

  return 0 unless defined $width;

  return 1 if exists $pms->{pdfinfo}->{dems_pdf}->{"${height}x${width}"};
  return 0;
}

sub pdf_image_size_range {
  my ($self, $pms, $body, $minh, $minw, $maxh, $maxw) = @_;

  return 0 unless defined $minw;
  return 0 unless exists $pms->{pdfinfo}->{dems_pdf};

  foreach my $dem (keys %{$pms->{pdfinfo}->{dems_pdf}}) {
    my ($h, $w) = split(/x/, $dem);
    next if ($h < $minh);  # height less than min height
    next if ($w < $minw);  # width less than min width
    next if (defined $maxh && $h > $maxh);  # height more than max height
    next if (defined $maxw && $w > $maxw);  # width more than max width
    # if we make it here, we have a match
    return 1;
  }

  return 0;
}

sub pdf_match_md5 {
  my ($self, $pms, $body, $md5) = @_;

  return 0 unless defined $md5;

  return 1 if exists $pms->{pdfinfo}->{md5}->{uc $md5};
  return 0;
}

sub pdf_match_fuzzy_md5 {
  my ($self, $pms, $body, $md5) = @_;

  return 0 unless defined $md5;

  return 1 if exists $pms->{pdfinfo}->{fuzzy_md5}->{uc $md5};
  return 0;
}

sub pdf_match_details {
  my ($self, $pms, $body, $detail, $regex) = @_;

  return 0 unless defined $regex;
  return 0 unless exists $pms->{pdfinfo}->{details}->{$detail};

  my ($rec, $err) = compile_regexp($regex, 2);
  if (!$rec) {
    my $rulename = $pms->get_current_eval_rule_name();
    warn "pdfinfo: invalid regexp for $rulename '$regex': $err";
    return 0;
  }

  foreach (keys %{$pms->{pdfinfo}->{details}->{$detail}}) {
    if ($_ =~ $rec) {
      dbg("pdfinfo: pdf_match_details $detail ($regex) match: $_");
      return 1;
    }
  }

  return 0;
}

sub _result_check {
  my ($min, $max, $value, $nomaxequal) = @_;
  return 0 unless defined $min && defined $value;
  return 0 if $value < $min;
  return 0 if defined $max && $value > $max;
  return 0 if defined $nomaxequal && $nomaxequal && $value == $max;
  return 1;
}

1;
