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

Mail::SpamAssassin::Handler::PDF - a MIME-part handler for PDFs

=head1 SYNOPSIS

  loadhandler     Mail::SpamAssassin::Handler::PDF

=head1 DESCRIPTION

A MIME-part handler that registers itself for C<application/pdf> parts, parses each
PDF with the pure-Perl L<Mail::SpamAssassin::PDF::Parser>, and exposes the
extracted metadata (page, image and link counts, ratios, encryption flags,
JavaScript/OpenAction flags, document details) to rules via the C<pdf2_*> eval
rules and C<_PDF2*_> tags below.  URLs found inside the PDF are added to the
URI detail list with type C<pdf>.

The C<pdf2_> prefix for tags and eval rules was chosen so as not to conflict with the
PDFInfo plugin.

=head1 RETURNS

The handler returns embedded images extracted from the PDF as sub-parts, each a
C<< { type => '<mediatype>', data => $bytes } >> spec that the handler framework
dispatches to the image handler (e.g. for OCR).  Images are emitted as either
C<image/jpeg> (for streams already in JPEG form) or C<image/png> (raw image data
re-wrapped as PNG).

This extraction is gated by the C<pdf_extract_images>, C<pdf_max_images>, and
C<pdf_max_image_pixels> settings (see L</CONFIGURATION>), and is skipped entirely
for password-protected PDFs.  When image extraction is disabled or the PDF
contains no usable images, the handler returns an empty list.

=head1 REQUIREMENTS

The following non-core perl modules are required for full-functionality:

=over 1

=item Crypt::RC4 - decrypt RC4-encrypted PDFs (and the RC4 step of AES variants)

=item Crypt::Mode::CBC - decrypt AES-encrypted PDFs

=item Digest::SHA - decrypt AES-256 (R5/R6) PDFs

=item Convert::Ascii85 - decode ASCII85-encoded streams

=back

If a required module is missing the handler still loads (with a warning at startup)
and PDFs that do not need it parse normally; however PDFs that require the missing
module are skipped.

Additionally, to analyze text from PDF's you need
L<pdftotext|https://poppler.freedesktop.org/> (from poppler) on the system.  The
handler runs it directly; set C<pdf_pdftotext_path> if it is not on the C<PATH>.
Without it the extracted text is empty, so C<pdf2_word_count>, the C<pdftext>
rule type, and body rules matching PDF text silently produce no hits.

=head1 CONFIGURATION

=over 4

=item pdf_pdftotext_path /path/to/pdftotext

Full path to the C<pdftotext> executable.  If unset, the handler looks for
C<pdftotext> on the C<PATH>.  If it cannot be found, text extraction is disabled
with a debug message, so C<--lint> never fails merely because the binary is
absent.

=item pdf_text_max_pages N    (default: 4)

Extract text from only the first N pages of each PDF (passed to C<pdftotext -l>).
This bounds the work done on large documents and is a countermeasure against
content stuffing.

=item pdf_extract_images ( 0 | 1 )    (default: 1)

Extract embedded images from PDFs and emit them as sub-parts, which the handler
framework dispatches to the image handler (e.g. for OCR).  Set to 0 to disable.

=item pdf_max_images N    (default: 4)

Extract at most N images per PDF, to bound the OCR work done downstream.

=item pdf_max_image_pixels N    (default: 25000000)

Skip images larger than N pixels (width times height). Set to B<0> to
disable the limit entirely and extract every image regardless of size.

=item pdf_max_uris N    (default: 30)

Retain at most N distinct URIs per PDF. Link annotations are read from every
page, so a hostile PDF stuffed with links could otherwise flood the URI list
and the URIBL lookups that follow. Additional links pointing at an
already-seen URI do not count toward the limit, and the C<LinkCount> metric
still counts every link. Set to B<0> to disable the limit entirely.

=back

=head1 EVAL RULES

This handler defines the following eval rules:

  pdf2_count()

     body RULENAME  eval:pdf2_count(<min>,[max])
        min: required, message contains at least x PDF attachments
        max: optional, if specified, must not contain more than x PDF attachments

  pdf2_page_count()

     body RULENAME  eval:pdf2_page_count(<min>,[max])
        min: required, message contains at least x pages in PDF attachments.
        max: optional, if specified, must not contain more than x PDF pages

  pdf2_link_count()

     body RULENAME  eval:pdf2_link_count(<min>,[max])
        min: required, message contains at least x links in PDF attachments.
        max: optional, if specified, must not contain more than x PDF links

        Note: Multiple links to the same URL are counted multiple times

  pdf2_word_count()

     body RULENAME  eval:pdf2_word_count(<min>,[max])
        min: required, message contains at least x words in PDF attachments.
        max: optional, if specified, must not contain more than x PDF words

        Note: pdf2_word_count requires pdftotext (see REQUIREMENTS).  Text is
        not extracted from password-protected PDFs.

  pdf2_match_details()

     body RULENAME  eval:pdf2_match_details(<detail>,<regex>);
        detail: Any standard PDF attribute: Author, Creator, Producer, Title, CreationDate, ModDate, etc..
        regex: regular expression

        Fires if any PDF attachment has the given attribute and it's value
        matches the given regular expression

  pdf2_is_encrypted()

     body RULENAME eval:pdf2_is_encrypted()

        Fires if any PDF attachment is encrypted

  pdf2_is_encrypted_blank_pw()

     body RULENAME eval:pdf2_is_encrypted_blank_pw()

        Fires if any PDF attachment is encrypted with a blank password

  pdf2_is_protected()

     body RULENAME eval:pdf2_is_protected()

        Fires if any PDF attachment is encrypted with a non-blank password

  pdf2_has_javascript()

     body RULENAME eval:pdf2_has_javascript()

        Fires if any PDF attachment has JavaScript

  pdf2_has_open_action()

     body RULENAME eval:pdf2_has_open_action()

        Fires if any PDF attachment has an OpenAction

The following rules only inspect the first page of each document

  pdf2_image_count()

     body RULENAME  eval:pdf2_image_count(<min>,[max])
        min: required, message contains at least x images on page 1 (all attachments combined).
        max: optional, if specified, must not contain more than x images on page 1

  pdf2_image_ratio()

     body RULENAME  eval:pdf2_image_ratio(<min>,[max])
        min: required, images consume at least x percent of page 1 on any PDF attachment
        max: optional, if specified, images do not consume more than x percent of page 1

        Note: Percent values range from 0-100

  pdf2_click_ratio()

     body RULENAME  eval:pdf2_click_ratio(<min>,[max])
        min: required, at least x percent of page 1 is clickable on any PDF attachment
        max: optional, if specified, not more than x percent of page 1 is clickable on any PDF attachment

        Note: Percent values range from 0-100

=head1 TEXT RULES

To match against text extracted from PDF's, use the following syntax:

    pdftext  RULENAME   /regex/
    score    RULENAME   1.0
    describe RULENAME   PDF contains text matching /regex/

These rules behave like C<body> rules and support the C<multiple> and
C<maxhits=N> tflags.  By default a rule stops at its first match.  Text is
extracted with C<pdftotext> (see REQUIREMENTS); if it is unavailable these rules
produce no hits.

=head1 TAGS

The following tags can be defined in an C<add_header> line:

    _PDF2COUNT_      - total number of pdf mime parts in the email
    _PDF2PAGECOUNT_   - total number of pages in all pdf attachments
    _PDF2WORDCOUNT_   - total number of words in all pdf attachments
    _PDF2LINKCOUNT_   - total number of links in all pdf attachments
    _PDF2IMAGECOUNT_  - total number of images found on page 1 inside all pdf attachments
    _PDF2VERSION_     - PDF Version, space seperated if there are > 1 pdf attachments
    _PDF2IMAGERATIO_  - Percent of first page that is consumed by images - per attachment, space separated
    _PDF2CLICKRATIO_  - Percent of first page that is clickable - per attachment, space separated
    _PDF2NAME_        - Filenames as found in the mime headers of PDF parts
    _PDF2PRODUCER_    - Producer/Application that created the PDF(s)
    _PDF2AUTHOR_      - Author of the PDF
    _PDF2CREATOR_     - Creator/Program that created the PDF(s)
    _PDF2TITLE_       - Title of the PDF File, if available
    _PDF2ERRORS_      - number of PDF attachments that failed to parse

=head1 URI DETAILS

This handler creates a new "pdf" URI type. You can detect URI's in PDF's using
the L<URIDetail|Mail::SpamAssassin::Plugin::URIDetail> plugin. For example:

    uri-detail RULENAME  type =~ /^pdf$/  raw =~ /^https?:\/\/bit\.ly\//

=cut

package Mail::SpamAssassin::Handler::PDF;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg info would_log);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var untaint_file_path
                                proc_status_ok exit_status_str);
use Mail::SpamAssassin::PDF::Parser;
use Mail::SpamAssassin::PDF::Context::Info;
use Compress::Zlib qw(compress crc32);

our @ISA = qw(Mail::SpamAssassin::Handler);

use constant DEFAULT_PDFTOTEXT_PATH   => '';
use constant DEFAULT_TEXT_MAX_PAGES   => 4;
use constant DEFAULT_EXTRACT_IMAGES   => 1;
use constant DEFAULT_MAX_IMAGES       => 4;
use constant DEFAULT_MAX_IMAGE_PIXELS => 25_000_000;
use constant DEFAULT_MAX_URIS         => 30;

sub log_dbg  { Mail::SpamAssassin::Logger::dbg ("pdfinfo2: @_"); }
sub log_warn { Mail::SpamAssassin::Logger::log_message('warn', "pdfinfo2: @_"); }

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("pdf2_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_image_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_link_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_word_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_page_count", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_image_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_click_ratio", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_match_details", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_is_encrypted", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_is_encrypted_blank_pw", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_is_protected", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_has_javascript", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule ("pdf2_has_open_action", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # Register as the handler for PDF parts.
  $self->register_handler('application/pdf', 'handle_pdf');

  # Warn once at startup about missing optional dependencies, so the affected
  # PDFs (encrypted / ASCII85-encoded) are knowingly skipped rather than
  # silently mis-parsed.  The parser itself degrades gracefully without them.
  if (!Mail::SpamAssassin::PDF::Filter::Decrypt::HAS_CRYPT_RC4) {
    log_warn("encrypted PDFs not supported, required module Crypt::RC4 missing");
  }
  if (!Mail::SpamAssassin::PDF::Filter::Decrypt::HAS_CRYPT_MODE_CBC) {
    log_warn("AES-encrypted PDFs not supported, required module Crypt::Mode::CBC missing");
  }
  if (!Mail::SpamAssassin::PDF::Filter::ASCII85Decode::HAS_CONVERT_ASCII85) {
    log_warn("ASCII85-encoded PDF streams not supported, required module Convert::Ascii85 missing");
  }

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, (
    {
      # Full path to the pdftotext executable (from poppler).  If unset, the
      # handler looks for pdftotext on the PATH.  If it cannot be found, text
      # extraction is disabled (pdf2_word_count and pdftext rules then no-op).
      setting => 'pdf_pdftotext_path',
      is_admin => 1,
      default => DEFAULT_PDFTOTEXT_PATH,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    },
    {
      # Only extract text from the first N pages of each PDF (pdftotext -l N).
      # Bounds the work done on large documents and resists content stuffing.
      setting => 'pdf_text_max_pages',
      is_admin => 1,
      default => DEFAULT_TEXT_MAX_PAGES,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # Extract embedded images from PDFs and emit them as sub-parts, which the
      # handler framework dispatches to the image handler (e.g. for OCR).  On by
      # default; set to 0 to disable.
      setting => 'pdf_extract_images',
      is_admin => 1,
      default => DEFAULT_EXTRACT_IMAGES,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
    },
    {
      # Extract at most this many images per PDF (bounds OCR work downstream).
      setting => 'pdf_max_images',
      is_admin => 1,
      default => DEFAULT_MAX_IMAGES,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # Retain at most this many *distinct* URIs per PDF.  Link annotations are
      # parsed on every page, so a hostile PDF stuffed with links could otherwise
      # flood the URI list and the URIBL lookups that follow.  Duplicate links to
      # an already-seen URI do not count toward the cap, and LinkCount still
      # counts every link.  Set to 0 to disable the limit entirely.
      setting => 'pdf_max_uris',
      is_admin => 1,
      default => DEFAULT_MAX_URIS,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # Skip images larger than this many pixels (width*height).  The default
      # (25M) covers full-page US Letter / A4 scans up to ~400 DPI, which is the
      # common image-spam / scanned-document case; larger images are skipped to
      # bound OCR work downstream.  Set to 0 to disable the limit entirely (OCR
      # every image regardless of size).
      setting => 'pdf_max_image_pixels',
      is_admin => 1,
      default => DEFAULT_MAX_IMAGE_PIXELS,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # pdftext RULENAME /pattern/modifiers
      # Define a rule that matches against text extracted from PDFs.  The
      # compiled regex is stored and run later (finish_parsing_end builds the
      # match loop); here we only record it and register an empty test so scores
      # and --lint work.
      setting => 'pdftext',
      is_priv => 1,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
      code => sub {
        my ($self, $key, $value, $line) = @_;

        if ($value !~ /^(\S+)\s+(.+)$/) {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        my ($name, $pattern) = ($1, $2);

        my ($re, $err) = compile_regexp($pattern, 1);
        if (!$re) {
          dbg("pdfinfo2: invalid pdftext regexp for $name '$pattern': $err");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $conf->{pdftext_rules}->{$name} = $re;
        $self->{parser}->add_test($name, undef,
          $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      },
    },
  ));

  $conf->{parser}->register_commands(\@cmds);
}

# Resolve the pdftotext binary lazily, on first use, and cache the result.
# Deferred out of new() on purpose: the handler is constructed during config
# parsing, possibly BEFORE pdf_pdftotext_path has been seen.  By the first
# handle_pdf() call all config is parsed.  Returns the path, or undef (text
# extraction then no-ops) if unavailable.
sub _pdftotext {
  my ($self, $conf) = @_;
  return $self->{pdftotext} if exists $self->{pdftotext};
  $self->{pdftotext} = $self->_resolve_binary(
    'pdftotext', $conf->{pdf_pdftotext_path}, 'pdftotext');
  return $self->{pdftotext};
}

sub _resolve_binary {
  my ($self, $label, $cfg_path, $exe) = @_;
  my $path = $cfg_path;
  if (!defined $path || $path eq '') {
    $path = Mail::SpamAssassin::Util::find_executable_in_env_path($exe);
  }
  if (defined $path && -x $path) {
    $path = untaint_file_path($path);
    log_dbg("using $label at $path");
    return $path;
  }
  log_dbg("$label not found, text extraction disabled (set pdf_pdftotext_path)");
  return undef;
}

# _extract_text($pms, $dataref): run pdftotext on the decoded PDF bytes and
# return the extracted text, or undef on any failure.  Shells out exactly the
# way Handler::Image runs tesseract: a temp file fed to the binary, output read
# from a pipe, the whole thing wrapped in a Timeout.  pdftotext writes to stdout
# when the output file is given as "-".
sub _extract_text {
  my ($self, $pms, $dataref) = @_;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $bin  = $self->_pdftotext($conf);
  return undef unless defined $bin;

  my $pages = $conf->{pdf_text_max_pages};
  $pages = DEFAULT_TEXT_MAX_PAGES unless defined $pages;
  my $secs = $conf->{handler_time_limit} || 10;

  my ($tmp_file, $err_file, $pid, $resp, $errno);

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($pms);

  my $timer = Mail::SpamAssassin::Timeout->new(
    { secs => $secs, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($tmp_file, my $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $tmp_file or die "failed to create a temporary file\n";
    binmode $tmp_fh;
    print $tmp_fh $$dataref;
    close($tmp_fh);
    $tmp_file = untaint_file_path($tmp_file);

    ($err_file, my $err_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $err_file or die "failed to create a temporary file\n";
    close($err_fh);
    $err_file = untaint_file_path($err_file);

    # pdftotext [opts] <pdffile> -    ("-" => write text to stdout)
    my @cmd = ($bin, '-l', untaint_var(int($pages)), '-nopgbrk', '-layout',
               '-enc', 'UTF-8', $tmp_file, '-');

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
             *PDF_TOTEXT, undef, ">$err_file", @cmd);
    $pid or die "$!\n";

    my ($inbuf, $nread);
    $resp = '';
    while ($nread = read(PDF_TOTEXT, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread or die "error reading from pipe: $!\n";

    $errno = 0;
    close PDF_TOTEXT or $errno = $!;

    if (proc_status_ok($?, $errno)) {
      log_dbg("pdftotext [$pid] finished successfully");
    } else {
      log_dbg("pdftotext [$pid] finished: " . exit_status_str($?, $errno));
    }
  });

  # Reap a stale child if the timer fired mid-run.
  if (defined(fileno(*PDF_TOTEXT))) {
    if ($pid) {
      kill('TERM', $pid) and log_dbg("killed stale pdftotext [$pid]");
    }
    close PDF_TOTEXT or 1;
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($pms);

  unlink($tmp_file) if defined $tmp_file;
  unlink($err_file) if defined $err_file;

  if ($err) {
    if ($err =~ /__brokenpipe__ignore__/) {
      log_dbg("pdftotext broken pipe, ignoring");
    } elsif ($timer->timed_out) {
      log_dbg("pdftotext timed out after ${secs}s");
    } else {
      chomp(my $e = $err);
      log_warn("pdftotext error: $e");
    }
    return undef;
  }

  return $resp;
}

# _encode_image($img): turn one extracted image descriptor from
# Parser::extract_images ({ format, bytes, width, height, colorspace, bpc }) into a
# child-part spec { type, data } the handler framework can dispatch, or undef if the
# image can't be represented in a format the image handler reads.
#
#   format 'jpeg' - already a complete JPEG file, passed through as image/jpeg
#   format 'raw'  - raw samples, wrapped into a PNG (image/png).  Only DeviceGray,
#                   DeviceRGB (8bpc) and bilevel (1bpc) are handled; CMYK/Indexed/
#                   array colorspaces are skipped.
sub _encode_image {
  my ($self, $img) = @_;
  my $bytes = $img->{bytes};
  return undef unless defined $bytes && length $bytes;

  if ( ($img->{format} // '') eq 'jpeg' ) {
    return { type => 'image/jpeg', data => $bytes };
  }
  return undef unless ($img->{format} // '') eq 'raw';

  my $w   = $img->{width};
  my $h   = $img->{height};
  my $bpc = $img->{bpc};
  my $cs  = $img->{colorspace};

  return undef unless defined($w) && defined($h) && $w > 0 && $h > 0;
  return undef if ref($cs);            # Indexed/ICCBased/etc. arrays - skip
  $cs = '' unless defined($cs);

  my ($channels, $samples);

  if ( defined($bpc) && $bpc == 1 ) {
    # Bilevel: expand 1 bit/pixel (row byte-aligned) to 8-bit gray.  PDF sample
    # 0 = black, so bit 0 -> 0x00, bit 1 -> 0xff.
    my $row_bytes = int(($w + 7) / 8);
    return undef if length($bytes) < $row_bytes * $h;
    my $gray = '';
    for my $y (0 .. $h-1) {
      my $row = substr($bytes, $y * $row_bytes, $row_bytes);
      my $bits = unpack('B*', $row);
      $gray .= pack('C*', map { $_ ? 0xff : 0x00 } split //, substr($bits, 0, $w));
    }
    ($channels, $samples) = (1, $gray);
  }
  elsif ( $cs =~ /rgb/i ) {
    return undef unless !defined($bpc) || $bpc == 8;
    return undef if length($bytes) < $w * $h * 3;
    ($channels, $samples) = (3, substr($bytes, 0, $w * $h * 3));
  }
  elsif ( $cs =~ /gray/i || $cs eq '' ) {
    return undef unless !defined($bpc) || $bpc == 8;
    return undef if length($bytes) < $w * $h;
    ($channels, $samples) = (1, substr($bytes, 0, $w * $h));
  }
  else {
    # CMYK / Separation / unknown - skip
    return undef;
  }

  my $png = _raw_to_png($w, $h, $channels, $samples);
  return undef unless defined $png;
  return { type => 'image/png', data => $png };
}

# _raw_to_png($w, $h, $channels, $samples): encode raw 8-bit samples (1=gray, 3=RGB)
# as a PNG.  Uses Compress::Zlib::compress so the IDAT is a proper zlib stream
# (libpng, which tesseract uses, rejects a bare deflate stream).
sub _raw_to_png {
  my ($w, $h, $channels, $samples) = @_;
  my $color_type = $channels == 3 ? 2 : 0;   # 2 = truecolor, 0 = grayscale
  my $row_bytes  = $w * $channels;

  # Prepend a per-scanline filter byte (0 = None).
  my $raw = '';
  $raw .= "\x00" . substr($samples, $_ * $row_bytes, $row_bytes) for 0 .. $h-1;

  my $idat = compress($raw);
  return undef unless defined $idat;

  my $png = "\x89PNG\x0d\x0a\x1a\x0a";
  $png .= _png_chunk('IHDR', pack('NNCCCCC', $w, $h, 8, $color_type, 0, 0, 0));
  $png .= _png_chunk('IDAT', $idat);
  $png .= _png_chunk('IEND', '');
  return $png;
}

sub _png_chunk {
  my ($type, $data) = @_;
  return pack('N', length $data) . $type . $data
       . pack('N', crc32($type . $data));
}

# handle_pdf($node, $pms): parse one PDF part, accumulate its metadata onto
# $pms->{Handler}{PDF}, set per-file tags, and add any URLs to the URI detail
# list.  Called once per PDF part, so totals accumulate across calls.  Produces
# no child parts (Phase 1).  No parser timeout is set here: the handler
# framework already runs each handler call under a Mail::SpamAssassin::Timeout.
sub handle_pdf {
  my ($self, $node, $pms) = @_;

  my $pdfinfo = $pms->{Handler}{PDF} ||= {
    files     => {},
    text      => [],
    errors    => 0,
    totals    => {
      FileCount        => 0,
      ImageCount       => 0,
      LinkCount        => 0,
      PageCount        => 0,
      WordCount        => 0,
      ImageArea        => 0,
      PageArea         => 0,
      OpenAction       => 0,
      JavaScript       => 0,
      Encrypted        => 0,
      Protected        => 0,
      EncryptedBlankPw => 0,
    },
  };

  my $data = $node->decode();
  return [] unless defined $data && length $data;

  # Parse PDF.  The handler framework already bounds this call with a timeout,
  # so the parser does not need its own.
  my $context = Mail::SpamAssassin::PDF::Context::Info->new(
    max_uris => defined($pms->{conf}->{pdf_max_uris})
      ? $pms->{conf}->{pdf_max_uris} : DEFAULT_MAX_URIS,
  );
  my $pdf = Mail::SpamAssassin::PDF::Parser->new(context => $context);
  my $info = eval {
    $pdf->parse(\$data);
    $pdf->{context}->get_info();
  };
  if ( !defined($info) ) {
    log_dbg($@);
    $pdfinfo->{errors}++;
    return [];
  }

  my $name = $node->{name} || '';
  log_dbg("document is password protected: $name") if $info->{Protected};
  _set_tag($pms, 'PDF2NAME', $name);
  $pdfinfo->{totals}->{FileCount}++;

  # Add URI's
  foreach my $location ( keys %{ $info->{uris} }) {
    log_dbg("found URI: $location");
    $pms->add_uri_detail_list($location, { pdf => 1 }, 'PDFInfo2');
  }

  # Extract text with pdftotext (skip password-protected PDFs, which can't be
  # read without the password).  The text is injected into the body via
  # set_rendered() so ordinary body rules can match it, and is also used for the
  # pdftext rule type and pdf2_word_count below.
  my $text = '';
  if ( !$info->{Protected} ) {
    $text = $self->_extract_text($pms, \$data);
    $text = '' unless defined $text;
  }
  if ( length $text ) {
    $node->set_rendered($text, $node->effective_type);
  }
  for (split(/^/, $text)) {
    chomp;
    next if /^\s*$/;
    push(@{$pdfinfo->{text}}, $_);
  }
  $info->{WordCount} = scalar(split(/\s+/, $text));

  $pdfinfo->{files}->{$name} = $info;
  $pdfinfo->{totals}->{ImageCount}      += $info->{ImageCount};
  $pdfinfo->{totals}->{PageCount}       += $info->{PageCount};
  $pdfinfo->{totals}->{LinkCount}       += $info->{LinkCount};
  $pdfinfo->{totals}->{WordCount}       += $info->{WordCount};
  $pdfinfo->{totals}->{ImageArea}       += $info->{ImageArea};
  $pdfinfo->{totals}->{PageArea}        += $info->{PageArea};
  $pdfinfo->{totals}->{OpenAction}      += $info->{OpenAction};
  $pdfinfo->{totals}->{JavaScript}      += $info->{JavaScript};
  $pdfinfo->{totals}->{Encrypted}       += $info->{Encrypted};
  $pdfinfo->{totals}->{Protected}       += $info->{Protected};
  $pdfinfo->{totals}->{EncryptedBlankPw} +=
    ($info->{Encrypted} && !$info->{Protected}) ? 1 : 0;

  _set_tag($pms, 'PDF2PRODUCER', $info->{Producer});
  _set_tag($pms, 'PDF2AUTHOR', $info->{Author});
  _set_tag($pms, 'PDF2CREATOR', $info->{Creator});
  _set_tag($pms, 'PDF2TITLE', $info->{Title});
  _set_tag($pms, 'PDF2IMAGERATIO', $info->{ImageRatio});
  _set_tag($pms, 'PDF2CLICKRATIO', $info->{ClickRatio});
  _set_tag($pms, 'PDF2VERSION', $info->{Version});

  # Extract embedded images and return them as sub-parts.  The handler framework
  # dispatches them recursively (e.g. to the image handler for OCR).  Skipped for
  # password-protected PDFs (their content can't be read) and when disabled.
  my $conf = $pms->{conf} || $self->{main}->{conf};
  return [] if $info->{Protected};
  return [] unless $conf->{pdf_extract_images};

  my $max_images = defined($conf->{pdf_max_images})
    ? $conf->{pdf_max_images} : DEFAULT_MAX_IMAGES;
  my $max_pixels = defined($conf->{pdf_max_image_pixels})
    ? $conf->{pdf_max_image_pixels} : DEFAULT_MAX_IMAGE_PIXELS;

  my $images = eval {
    $pdf->extract_images(max_images => $max_images, max_pixels => $max_pixels);
  };
  if ( $@ ) {
    chomp(my $e = $@);
    log_dbg("image extraction failed: $e");
    return [];
  }
  return [] unless ref($images) eq 'ARRAY' && @$images;

  my @parts;
  my $n = 0;
  for my $img ( @$images ) {
    my $spec = $self->_encode_image($img);
    next unless defined $spec;
    $n++;
    $spec->{name} = "pdf-image-$n";
    push @parts, $spec;
  }
  log_dbg("extracted ".scalar(@parts)." image sub-part(s) from $name") if @parts;

  return \@parts;
}

# Set the aggregate count tags (now that all parts are processed) and run the
# compiled pdftext rules.  parsed_metadata runs after apply_handlers, so the
# totals and text gathered by handle_pdf are final here.
sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  # Ensure the structure exists even when the message has no PDF parts, so the
  # pdf2_* eval rules can read totals/files without autovivifying or dying.
  my $pdfinfo = $pms->{Handler}{PDF} ||= {
    files     => {},
    text      => [],
    errors    => 0,
    totals    => {},
  };
  my $totals = $pdfinfo->{totals};

  # Aggregate count tags are set directly (not via the appending _set_tag,
  # which is only correct for the space-joined per-file tags).  Only emit them
  # when at least one PDF was seen, matching the old plugin's behaviour.
  if ( $totals->{FileCount} ) {
    $pms->{tag_data}->{PDF2COUNT}       = $totals->{FileCount};
    $pms->{tag_data}->{PDF2IMAGECOUNT}  = $totals->{ImageCount};
    $pms->{tag_data}->{PDF2WORDCOUNT}   = $totals->{WordCount};
    $pms->{tag_data}->{PDF2PAGECOUNT}   = $totals->{PageCount};
    $pms->{tag_data}->{PDF2LINKCOUNT}   = $totals->{LinkCount};
    $pms->{tag_data}->{PDF2ERRORS}      = $pdfinfo->{errors};
  }

  $self->_run_pdftext_rules($opts);
}

# After config is fully parsed, compile all pdftext rules into a single sub
# (_run_pdftext_rules) so the per-rule match loops run as compiled code,
# mirroring how native body rules (and the Image handler's imagetext rules) are
# built.  Each default rule stops at its first hit; "multiple" rules scan with
# /g and honour maxhits=N.
sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  return unless exists $conf->{pdftext_rules};

  my $would_log = would_log('dbg');

  my $eval = <<'EOF';
package Mail::SpamAssassin::Handler::PDF;

sub _run_pdftext_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr, $hits);

    my $pdf_text = $self->_get_pdf_text($pms);
    return unless @$pdf_text;

EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{pdftext_rules}}) {
    $loopid++;
    my $tflags = $conf->{tflags}->{$name} || '';

    my ($dbg_running_rule, $dbg_ran_rule) = ('', '');
    if ($would_log) {
      $dbg_running_rule = qq(dbg("running rule $name"););
      $dbg_ran_rule = qq(dbg(qq(ran rule $name ======> got hit "\$match")););
    }

    my $ifwhile   = 'if';
    my $last      = 'last;';
    my $modifiers = 'p';
    my $init_hits = '';

    if ($tflags =~ /\bmultiple\b/) {
      $ifwhile = 'while';
      $modifiers .= 'g';
      if ($tflags =~ /\bmaxhits=(\d+)\b/) {
        $init_hits = "\$hits = 0;";
        $last = "last rule_$loopid if ++\$hits >= $1;";
      } else {
        $last = '';
      }
    }

    $eval .= <<"EOF";
    $dbg_running_rule
    \$test_qr = \$pms->{conf}->{pdftext_rules}->{$name};
    $init_hits
    rule_$loopid: foreach my \$line (\@\$pdf_text) {
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->got_hit('$name', 'PDFTEXT: ', 'ruletype' => 'body');
            $last
        }
    }
EOF
  }

  $eval .= "}\n";

  # The generated sub replaces the no-op _run_pdftext_rules placeholder below.
  no warnings 'redefine';
  eval untaint_var($eval);
  if ($@) {
    die("pdfinfo2: error compiling pdftext rules: $@");
  }
}

# Real implementation is compiled in by finish_parsing_end; this is the no-op
# used when no pdftext rules are configured.
sub _run_pdftext_rules { }

# The text source for pdftext rules: the per-PDF extracted text that handle_pdf
# stashed on $pms (in document order).
sub _get_pdf_text {
  my ($self, $pms) = @_;
  return ($pms->{Handler}{PDF} && $pms->{Handler}{PDF}{text}) || [];
}

sub _set_tag {
  my ($pms, $tag, $value) = @_;

  return unless defined $value && $value ne '';
  log_dbg("set_tag called for $tag: $value");

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

sub pdf2_is_encrypted {
  my ($self, $pms, $body) = @_;
  return $pms->{Handler}{PDF}->{totals}->{Encrypted} ? 1 : 0;
}

sub pdf2_is_encrypted_blank_pw {
  my ($self, $pms, $body) = @_;
  return $pms->{Handler}{PDF}->{totals}->{EncryptedBlankPw} ? 1 : 0;
}

sub pdf2_is_protected {
  my ($self, $pms, $body) = @_;
  return $pms->{Handler}{PDF}->{totals}->{Protected} ? 1 : 0;
}

sub pdf2_has_open_action {
  my ($self, $pms, $body) = @_;
  return $pms->{Handler}{PDF}->{totals}->{OpenAction} ? 1 : 0;
}

sub pdf2_has_javascript {
  my ($self, $pms, $body) = @_;
  return $pms->{Handler}{PDF}->{totals}->{JavaScript} ? 1 : 0;
}

sub pdf2_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return _result_check($min, $max, $pms->{Handler}{PDF}->{totals}->{FileCount});
}

sub pdf2_image_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return _result_check($min, $max, $pms->{Handler}{PDF}->{totals}->{ImageCount});
}

sub pdf2_image_ratio {
  my ($self, $pms, $body, $min, $max) = @_;
  foreach (keys %{$pms->{Handler}{PDF}->{files}}) {
    return 1 if _result_check($min, $max, $pms->{Handler}{PDF}->{files}->{$_}->{ImageRatio});
  }
  return 0;
}

sub pdf2_click_ratio {
  my ($self, $pms, $body, $min, $max) = @_;
  foreach (keys %{$pms->{Handler}{PDF}->{files}}) {
    return 1 if _result_check($min, $max, $pms->{Handler}{PDF}->{files}->{$_}->{ClickRatio});
  }
  return 0;
}

sub pdf2_link_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return _result_check($min, $max, $pms->{Handler}{PDF}->{totals}->{LinkCount});
}

sub pdf2_word_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return _result_check($min, $max, $pms->{Handler}{PDF}->{totals}->{WordCount});
}

sub pdf2_page_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return _result_check($min, $max, $pms->{Handler}{PDF}->{totals}->{PageCount});
}

sub pdf2_match_details {
  my ($self, $pms, $body, $detail, $regex) = @_;

  return 0 unless defined $regex;
  return 0 unless exists $pms->{Handler}{PDF}->{files};

  my ($re, $err) = compile_regexp($regex, 2);
  if (!$re) {
    my $rulename = $pms->get_current_eval_rule_name();
    warn "pdfinfo2: invalid regexp for $rulename '$regex': $err";
    return 0;
  }

  foreach (keys %{$pms->{Handler}{PDF}->{files}}) {
    my $value = $pms->{Handler}{PDF}->{files}->{$_}->{$detail};
    if ( defined($value) && $value =~ $re ) {
      log_dbg("pdf2_match_details $detail ($regex) match: $_");
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
