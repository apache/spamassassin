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

Mail::SpamAssassin::Handler::Image - A MIME-part handler for image/* parts

=head1 SYNOPSIS

  loadhandler Mail::SpamAssassin::Handler::Image

  imagetext  RULE_NAME  /pattern/modifiers

  body  IMAGE_TEXT_HEAVY  eval:check_image_text_ratio('0.75')
  describe IMAGE_TEXT_HEAVY  Most of the body text came from images

=head1 DESCRIPTION

A handler that registers itself as the MIME-part handler for C<image/*> parts,
runs the C<tesseract> OCR engine on them, and injects the recognised text into
the message body, so ordinary body rules can match text that would otherwise be
hidden inside an image.

It also provides the C<imagetext> rule type, which matches a regular expression
specifically against the OCR'd image text:

  imagetext  RULE_NAME  /pattern/modifiers

These rules behave like C<body> rules and support the C<multiple> and
C<maxhits=N> tflags.  By default a rule stops at its first match.

=head1 TFLAGS

=over 4

=item multiple

Match the rule more than once (for use with meta rules counting hits).

=item maxhits=N

With C<multiple>, stop after N hits.

=back

=head1 CONFIGURATION

=over 4

=item image_tesseract_path /path/to/tesseract

Full path to the C<tesseract> executable.  If unset, the plugin looks for
C<tesseract> on the C<PATH>.  If it cannot be found OCR is disabled with a
warning, so C<--lint> never fails merely because the binary is absent.

=item image_ocr_lang eng

Language(s) passed to C<tesseract -l> (default C<eng>).

=item image_heif_convert_path /path/to/heif-convert

Full path to C<heif-convert> (from libheif), used to convert HEIF/HEIC images
to PNG before OCR, since tesseract cannot read HEIF natively.  If unset, the
plugin looks for C<heif-convert> on the C<PATH>.  If it is unavailable, HEIF
images are skipped while all other image types are still OCR'd.  The real image
type is detected from the file's leading bytes, not its declared Content-Type,
so a HEIF image mislabelled as e.g. image/png is still handled.

=item image_ocr_min_width N    (default: 0)

Skip OCR for any image narrower than N pixels.  Small images (logos, icons,
spacers, tracking pixels) rarely contain readable text, so this avoids wasting
tesseract on them.  C<0> disables the check.  Dimensions are read from the image
header (PNG, JPEG, GIF, WebP, BMP); when they cannot be determined the image is
OCR'd anyway, so this is a best-effort optimisation, not an anti-evasion control.

=item image_ocr_min_height N   (default: 0)

As C<image_ocr_min_width>, but for image height.  C<0> disables the check.  An
image is skipped if it is below I<either> the minimum width I<or> the minimum
height.

=back

=cut

package Mail::SpamAssassin::Handler::Image;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg info would_log);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str compile_regexp);

our @ISA = qw(Mail::SpamAssassin::Handler);

sub new {
  my ($class, $main) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($main);
  bless ($self, $class);

  $self->set_config($main->{conf});

  # Register as the handler for every image type, and an eval rule to query the
  # result.
  $self->register_handler('image/*', 'handle_image');
  $self->register_eval_rule('check_image_text_ratio',
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = (
    {
      setting => 'image_tesseract_path',
      is_admin => 1,
      default => '',
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    },
    {
      setting => 'image_ocr_lang',
      is_admin => 1,
      default => 'eng',
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    },
    {
      setting => 'image_heif_convert_path',
      is_admin => 1,
      default => '',
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    },
    {
      setting => 'image_ocr_min_width',
      is_admin => 1,
      default => 0,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      setting => 'image_ocr_min_height',
      is_admin => 1,
      default => 0,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    },
    {
      # imagetext RULENAME /pattern/modifiers
      # Define a rule that matches against text OCR'd from images.  The compiled
      # regex is stored and run later (finish_parsing_end builds the match loop);
      # here we only record it and register an empty test so scores and --lint
      # work.
      setting => 'imagetext',
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
          dbg("image: invalid imagetext regexp for $name '$pattern': $err");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        $conf->{imagetext_rules}->{$name} = $re;
        $self->{parser}->add_test($name, undef,
          $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      },
    },
  );
  $conf->{parser}->register_commands(\@cmds);
}

# After config is fully parsed, compile all imagetext rules into a single sub
# (_run_imagetext_rules) so the per-rule match loops run as compiled code,
# mirroring how native body rules are built.  Each default rule stops at its
# first hit (if + last); "multiple" rules scan with /g and honour maxhits=N.
sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  return unless exists $conf->{imagetext_rules};

  my $would_log = would_log('dbg');

  my $eval = <<'EOF';
package Mail::SpamAssassin::Handler::Image;

sub _run_imagetext_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr, $hits);

    my $image_text = $self->_get_image_text($pms);
    return unless @$image_text;

EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{imagetext_rules}}) {
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
    \$test_qr = \$pms->{conf}->{imagetext_rules}->{$name};
    $init_hits
    rule_$loopid: foreach my \$line (\@\$image_text) {
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->got_hit('$name', 'IMAGETEXT: ', 'ruletype' => 'body');
            $last
        }
    }
EOF
  }

  $eval .= "}\n";

  # The generated sub replaces the no-op _run_imagetext_rules placeholder below.
  no warnings 'redefine';
  eval untaint_var($eval);
  if ($@) {
    die("image: error compiling imagetext rules: $@");
  }
}

# Real implementation is compiled in by finish_parsing_end; this is the no-op
# used when no imagetext rules are configured.
sub _run_imagetext_rules { }

sub parsed_metadata {
  my ($self, $opts) = @_;
  $self->_run_imagetext_rules($opts);
}

# The text source for imagetext rules: the per-image OCR text that handle_image
# stashed on $pms (in document order).  Cached per scan.
sub _get_image_text {
  my ($self, $pms) = @_;
  return $pms->{plugins}{Image}{text} || [];
}

# handle_image($node, $pms): OCR one image part.  Inject any recognised text via
# set_rendered() and accumulate the per-message OCR image and word counts (used
# by check_image_text_ratio).  Produces no child parts.
sub handle_image {
  my ($self, $node, $pms) = @_;

  my $tesseract = $self->_tesseract($pms->{conf});
  return [] unless $tesseract;

  my $data = $node->decode;
  return [] unless defined $data && length $data;

  # The image bytes can be large, so pass them by reference throughout (avoids
  # copying the whole scalar into each helper's @_).
  my $dataref = \$data;

  # Identify the real type and dimensions from the bytes (not the declared
  # Content-Type, which spammers mislabel).  One parse feeds both the size gate
  # and the HEIF check.
  my ($type, $w, $h) = $self->_image_info($dataref);

  # Type gate: only OCR bytes we positively identify as a raster format tesseract
  # can read.  An undef type means the bytes are not one of our known rasters --
  # most importantly image/svg+xml (XML, not a bitmap), which reaches this
  # image/* handler when no SVG handler is loaded, but also unknown or corrupt
  # blobs.  Feeding any of those to tesseract is a wasted fork (and can emit junk
  # text), so skip them.  ($w/$h may still be undef for a recognised type -- e.g.
  # HEIF, whose dimensions come from the converted PNG -- so gate on $type only.)
  if (!defined $type) {
    dbg("image: skipping OCR, unrecognised image format (type %s)",
        $node->{type} // '?');
    return [];
  }

  # Size gate: skip OCR for images too small to plausibly hold readable text
  # (logos, icons, spacers, tracking pixels).  Fail open when dimensions are
  # unknown, so an unmeasurable format can't be used to dodge OCR.
  my $minw = $pms->{conf}->{image_ocr_min_width}  || 0;
  my $minh = $pms->{conf}->{image_ocr_min_height} || 0;
  if (($minw || $minh) && defined $w && defined $h) {
    if (($minw && $w < $minw) || ($minh && $h < $minh)) {
      dbg("image: skipping OCR, %dx%d below min %dx%d", $w, $h, $minw, $minh);
      return [];
    }
  }

  # HEIF/HEIC must be converted to PNG before tesseract.  _heif_to_png returns a
  # ref to the converted bytes, which becomes the new source for OCR.
  if (($type // '') eq 'heif') {
    my $pngref = $self->_heif_to_png($pms, $dataref);
    return [] unless defined $pngref;   # no converter, or conversion failed
    $dataref = $pngref;
  }

  my $text = $self->_ocr($pms, $dataref, $node->{type});
  return [] unless defined $text;

  # Normalise: collapse the trailing whitespace tesseract emits.
  $text =~ s/\s+\z//;
  return [] unless length $text;

  # Render the text under the part's own (image) type, not the default
  # text/plain.  This mirrors ExtractText: it keeps the body-text assembly from
  # discarding the OCR text as a "text attachment" when the image carried
  # Content-Disposition: attachment (the common case for image attachments) --
  # that skip only fires for rendered types matching text/*.
  $node->set_rendered($text, $node->effective_type);
  # Accumulate per-message OCR image and word counts (used by
  # check_image_text_ratio to spot a mostly-text "image").
  my $word_count = () = $text =~ /\S+/g;
  $pms->{plugins}{Image}{ocr_image_count}++;
  $pms->{plugins}{Image}{ocr_word_count} += $word_count;
  # Stash the text for imagetext rules (see _run_imagetext_rules); one entry per
  # OCR'd image, in document order.
  push @{$pms->{plugins}{Image}{text}}, $text;
  dbg("image: OCR'd %d bytes (%d words) of text from %s",
      length $text, $word_count, $node->{type} || '?');

  return [];
}

# Resolve the tesseract binary lazily, on first use, and cache the result.
# Deferred out of new() on purpose: the plugin is constructed during config
# parsing, possibly BEFORE image_tesseract_path has been seen, so reading config
# in new() would be order-dependent.  By first handle_image() time all config is
# parsed.  Returns the path, or undef (OCR then no-ops) if unavailable.
sub _tesseract {
  my ($self, $conf) = @_;
  return $self->{tesseract} if exists $self->{tesseract};
  $self->{tesseract} = $self->_resolve_binary(
    'tesseract', $conf->{image_tesseract_path}, 'tesseract',
    'Image disabled, tesseract executable not found (set image_tesseract_path)');
  return $self->{tesseract};
}

# heif-convert turns HEIC/HEIF (which tesseract/leptonica can't read) into PNG.
# Optional: if absent, HEIF images are simply skipped, everything else still
# OCRs.  Resolved lazily and cached, like the tesseract path.
sub _heif_convert {
  my ($self, $conf) = @_;
  return $self->{heif_convert} if exists $self->{heif_convert};
  $self->{heif_convert} = $self->_resolve_binary(
    'heif-convert', $conf->{image_heif_convert_path}, 'heif-convert', undef);
  return $self->{heif_convert};
}

# Resolve an external binary: explicit config path first, else search PATH.
# Returns the untainted path or undef.  $warn_msg, if set, is warned once when
# the binary is missing (used for the required tesseract; omitted for optional
# converters, which fail quietly).
sub _resolve_binary {
  my ($self, $label, $cfg_path, $exe, $warn_msg) = @_;
  my $path = $cfg_path;
  if (!defined $path || $path eq '') {
    $path = Mail::SpamAssassin::Util::find_executable_in_env_path($exe);
  }
  if (defined $path && -x $path) {
    $path = untaint_file_path($path);
    dbg("image: using $label at $path");
    return $path;
  }
  warn "image: $warn_msg\n" if defined $warn_msg;
  dbg("image: $label not found, related conversions disabled")
    if !defined $warn_msg;
  return undef;
}

# Identify an image's real type and pixel dimensions from its leading bytes.
# The declared Content-Type / filename extension is attacker-controlled and
# routinely mismatched to dodge OCR, so we read the bytes directly.  Takes a
# scalar ref to the (possibly large) bytes to avoid copying.  Returns
# ($type, $width, $height):
#   $type   - 'png'/'jpeg'/'gif'/'webp'/'bmp'/'heif', or undef if unrecognized.
#   $width  - pixels, or undef if not parseable (HEIF, or a corrupt/truncated
#   $height   header).  HEIF is identified for conversion but its dimensions are
#             not read here (we OCR the converted PNG instead).
# Byte offsets adapted from Plugin::ImageInfo; defensive throughout.
sub _image_info {
  my ($self, $dataref) = @_;
  my $len = defined $$dataref ? length $$dataref : 0;
  return (undef, undef, undef) unless $len >= 16;

  # PNG: 8-byte signature, then IHDR with width/height as big-endian uint32.
  if (substr($$dataref, 0, 8) eq "\x89PNG\x0d\x0a\x1a\x0a") {
    my ($w, $h) = unpack('NN', substr($$dataref, 16, 8));
    return ('png', ($w && $h) ? ($w, $h) : (undef, undef));
  }

  # GIF: "GIF87a"/"GIF89a", then width/height as little-endian uint16.
  if (substr($$dataref, 0, 6) =~ /^GIF8[79]a$/) {
    my ($w, $h) = unpack('vv', substr($$dataref, 6, 4));
    return ('gif', ($w && $h) ? ($w, $h) : (undef, undef));
  }

  # JPEG: SOI (FFD8), then walk segments to a Start-Of-Frame marker, whose
  # payload is precision(1) height(2 BE) width(2 BE).
  if (substr($$dataref, 0, 2) eq "\xFF\xD8") {
    my $pos = 2;
    while ($pos + 4 <= $len) {
      my ($ff, $mark, $seg) = unpack('CCn', substr($$dataref, $pos, 4));
      last if $ff != 0xFF || $mark == 0xDA || $mark == 0xD9 || $seg < 2;
      if ( ($mark >= 0xC0 && $mark <= 0xC3) || ($mark >= 0xC5 && $mark <= 0xC7) ||
           ($mark >= 0xC9 && $mark <= 0xCB) || ($mark >= 0xCD && $mark <= 0xCF) ) {
        last if $pos + 9 > $len;
        my (undef, $h, $w) = unpack('Cnn', substr($$dataref, $pos + 4, 5));
        return ('jpeg', ($w && $h) ? ($w, $h) : (undef, undef));
      }
      $pos += 2 + $seg;   # 2-byte marker + segment length (which includes itself)
    }
    return ('jpeg', undef, undef);
  }

  # WebP: "RIFF"...."WEBP", then a chunk fourcc selecting the dimension layout.
  if (substr($$dataref, 0, 4) eq 'RIFF' && substr($$dataref, 8, 4) eq 'WEBP') {
    my $fourcc = substr($$dataref, 12, 4);
    if ($fourcc eq 'VP8 ' && $len >= 30) {       # lossy
      my ($w, $h) = unpack('vv', substr($$dataref, 26, 4));
      $w &= 0x3fff; $h &= 0x3fff;
      return ('webp', ($w && $h) ? ($w, $h) : (undef, undef));
    }
    if ($fourcc eq 'VP8L' && $len >= 25) {       # lossless
      my $b = unpack('V', substr($$dataref, 21, 4));
      my $w = ($b & 0x3fff) + 1;
      my $h = (($b >> 14) & 0x3fff) + 1;
      return ('webp', $w, $h);
    }
    if ($fourcc eq 'VP8X' && $len >= 30) {       # extended
      my $wb = substr($$dataref, 24, 3) . "\x00";
      my $hb = substr($$dataref, 27, 3) . "\x00";
      my $w = unpack('V', $wb) + 1;
      my $h = unpack('V', $hb) + 1;
      return ('webp', $w, $h);
    }
    return ('webp', undef, undef);
  }

  # BMP: "BM", width/height as little-endian int32 (height may be negative for
  # top-down bitmaps).
  if (substr($$dataref, 0, 2) eq 'BM' && $len >= 26) {
    my $w = unpack('l<', substr($$dataref, 18, 4));
    my $h = unpack('l<', substr($$dataref, 22, 4));
    $w = abs $w; $h = abs $h;
    return ('bmp', ($w && $h) ? ($w, $h) : (undef, undef));
  }

  # TIFF: "II\x2a\x00" (little-endian) or "MM\x00\x2a" (big-endian), then the
  # offset of the first IFD.  Dimensions come from the ImageWidth (256) and
  # ImageLength (257) tags, which may be SHORT or LONG.  Only the first IFD is
  # read: a multi-page TIFF is measured by its first page, which is what an image
  # reader shows and enough for the size gate.
  if (substr($$dataref, 0, 4) eq "II\x2a\x00" ||
      substr($$dataref, 0, 4) eq "MM\x00\x2a") {
    my $le = substr($$dataref, 0, 2) eq 'II';
    my $ifd = unpack($le ? 'V' : 'N', substr($$dataref, 4, 4));
    my ($w, $h);
    # Guard every read against a truncated or bogus offset; a malformed TIFF must
    # fall through as a known type with unknown dimensions, not die.
    if ($ifd >= 8 && $ifd + 2 <= $len) {
      my $count = unpack($le ? 'v' : 'n', substr($$dataref, $ifd, 2));
      $count = 512 if $count > 512;         # sanity cap on entries to walk
      for my $i (0 .. $count - 1) {
        my $e = $ifd + 2 + $i * 12;
        last if $e + 12 > $len;
        my ($tag, $type) = unpack($le ? 'vv' : 'nn', substr($$dataref, $e, 4));
        next unless $tag == 256 || $tag == 257;
        # SHORT (3) sits in the low half of the value field; LONG (4) fills it.
        my $v = $type == 3 ? unpack($le ? 'v' : 'n', substr($$dataref, $e + 8, 2))
              : $type == 4 ? unpack($le ? 'V' : 'N', substr($$dataref, $e + 8, 4))
              : undef;
        next unless defined $v;
        $tag == 256 ? ($w = $v) : ($h = $v);
        last if defined $w && defined $h;
      }
    }
    return ('tiff', ($w && $h) ? ($w, $h) : (undef, undef));
  }

  # ISO-BMFF / HEIF: bytes 4-7 are 'ftyp', bytes 8-11 a brand code.  Identified
  # for conversion; dimensions read from the converted PNG, not here.
  if (substr($$dataref, 4, 4) eq 'ftyp') {
    my $brand = substr($$dataref, 8, 4);
    return ('heif', undef, undef)
      if $brand =~ /^(?:heic|heix|hevc|hevx|heim|heis|hevm|hevs|
                        mif1|msf1|heif)$/x;
  }

  return (undef, undef, undef);
}

# Run tesseract on the decoded image bytes, mirroring ExtractText's invocation:
# write bytes to a secure temp file, run "tesseract <file> - -l <lang>", read the
# recognised text from the pipe.  Returns the text, or undef on failure.
sub _ocr {
  my ($self, $pms, $dataref, $type) = @_;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $lang = $conf->{image_ocr_lang} || 'eng';
  my $secs = $conf->{handler_time_limit} || 10;

  my ($tmp_file, $err_file, $pid, $resp, $errno);

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($pms);

  # tesseract uses OpenMP; one thread keeps it from fighting the MTA for cores.
  local $ENV{OMP_THREAD_LIMIT} = 1;

  my $timer = Mail::SpamAssassin::Timeout->new(
    { secs => $secs, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($tmp_file, my $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $tmp_file or die "failed to create a temporary file\n";
    print $tmp_fh $$dataref;
    close($tmp_fh);
    $tmp_file = untaint_file_path($tmp_file);

    ($err_file, my $err_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $err_file or die "failed to create a temporary file\n";
    close($err_fh);
    $err_file = untaint_file_path($err_file);

    # tesseract <imagefile> <outputbase> ...; outputbase "-" means stdout.
    my @cmd = ($self->{tesseract}, $tmp_file, '-',
               '-l', untaint_var($lang), '-c', 'page_separator=');

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
             *IMAGE_OCR, undef, ">$err_file", @cmd);
    $pid or die "$!\n";

    my ($inbuf, $nread);
    $resp = '';
    while ($nread = read(IMAGE_OCR, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread or die "error reading from pipe: $!\n";

    $errno = 0;
    close IMAGE_OCR or $errno = $!;

    if (proc_status_ok($?, $errno)) {
      dbg("image: tesseract [%s] finished successfully", $pid);
    } else {
      dbg("image: tesseract [%s] finished: %s",
          $pid, exit_status_str($?, $errno));
    }
  });

  # Reap a stale child if the timer fired mid-run.
  if (defined(fileno(*IMAGE_OCR))) {
    if ($pid) {
      kill('TERM', $pid)
        and dbg("image: killed stale tesseract [$pid]");
    }
    close IMAGE_OCR or 1;
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($pms);

  unlink($tmp_file) if defined $tmp_file;
  my $err_resp = (defined $err_file && -s $err_file) ?
    do { open(my $efh, '<', $err_file); local $/; my $e = <$efh>;
         close($efh); $e; } : '';
  unlink($err_file) if defined $err_file;

  if ($err) {
    if ($err =~ /__brokenpipe__ignore__/) {
      dbg("image: tesseract broken pipe, ignoring");
    } elsif ($timer->timed_out) {
      dbg("image: tesseract timed out after ${secs}s");
    } else {
      chomp(my $e = $err);
      info("image: tesseract error: %s", $e);
    }
    return undef;
  }

  return $resp;
}

# Convert HEIF/HEIC bytes to PNG with heif-convert.  Unlike tesseract,
# heif-convert writes to an output FILE rather than stdout, so we run it to a
# second temp file and read the PNG bytes back.  Returns the PNG bytes, or undef
# if no converter is available or the conversion fails.
sub _heif_to_png {
  my ($self, $pms, $dataref) = @_;

  my $conf = $pms->{conf} || $self->{main}->{conf};
  my $convert = $self->_heif_convert($conf);
  if (!$convert) {
    dbg("image: cannot OCR HEIF, heif-convert not available");
    return undef;
  }
  my $secs = $conf->{handler_time_limit} || 10;

  my ($in_file, $out_file, $err_file, $pid, $errno, $png);

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($pms);

  my $timer = Mail::SpamAssassin::Timeout->new(
    { secs => $secs, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($in_file, my $in_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $in_file or die "failed to create a temporary file\n";
    print $in_fh $$dataref;
    close($in_fh);
    # heif-convert (libheif) infers the input format from the filename
    # extension, and secure_tmpfile() produces extensionless names -- so give it
    # a .heic name (a rename within the same secure tmpdir keeps our ownership).
    my $heic_in = "$in_file.heic";
    rename($in_file, $heic_in) or die "cannot rename temp file: $!\n";
    $in_file = untaint_file_path($heic_in);

    # heif-convert picks the OUTPUT format from the extension too, so name it
    # .png.  We made the file with secure_tmpfile() to reserve the name, then
    # rename to add the extension (heif-convert overwrites it).
    ($out_file, my $out_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $out_file or die "failed to create a temporary file\n";
    close($out_fh);
    my $png_out = "$out_file.png";
    rename($out_file, $png_out) or die "cannot rename temp file: $!\n";
    $out_file = untaint_file_path($png_out);

    ($err_file, my $err_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $err_file or die "failed to create a temporary file\n";
    close($err_fh);
    $err_file = untaint_file_path($err_file);

    my @cmd = ($convert, '-q', '90', $in_file, $out_file);
    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(
             *HEIF_CONV, undef, ">$err_file", @cmd);
    $pid or die "$!\n";

    # Drain stdout (we don't need it) so the child can exit.
    my ($inbuf, $nread);
    while ($nread = read(HEIF_CONV, $inbuf, 8192)) { }
    defined $nread or die "error reading from pipe: $!\n";

    $errno = 0;
    close HEIF_CONV or $errno = $!;
    dbg("image: heif-convert [%s] finished: %s",
        $pid, exit_status_str($?, $errno));
  });

  if (defined(fileno(*HEIF_CONV))) {
    kill('TERM', $pid) if $pid;
    close HEIF_CONV or 1;
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($pms);

  # Slurp the converted PNG if it was produced.
  if (!$err && defined $out_file && -s $out_file) {
    if (open(my $pfh, '<', $out_file)) {
      binmode $pfh;
      local $/;
      $png = <$pfh>;
      close($pfh);
    }
  }

  unlink($in_file)  if defined $in_file;
  unlink($out_file) if defined $out_file;
  unlink($err_file) if defined $err_file;

  if ($err) {
    if ($timer->timed_out) {
      dbg("image: heif-convert timed out after ${secs}s");
    } else {
      chomp(my $e = $err);
      info("image: heif-convert error: %s", $e);
    }
    return undef;
  }

  # Return a ref to the converted bytes (handle_image threads it on by ref).
  return (defined $png && length $png) ? \$png : undef;
}

=over 4

=item check_image_text_ratio(MIN_RATIO)

Eval rule: true if the fraction of the message's body text that came from images
is greater than or equal to MIN_RATIO.  The numerator is the number of words
OCR'd from all image parts; the denominator is the total number of words in the
rendered body (which, since OCR text is injected into the body, includes those
image words).  A high fraction means the readable content is mostly text
rendered as a picture -- a classic image-spam evasion.  MIN_RATIO is a fraction
from 0 to 1 and defaults to 0.5.

=cut

sub check_image_text_ratio {
  my ($self, $pms, $body, $min_ratio) = @_;

  my $image_words = $pms->{plugins}{Image}{ocr_word_count} || 0;
  return 0 unless $image_words;

  $min_ratio = 0.5 unless defined $min_ratio && $min_ratio ne '';

  # $body is the rendered body text array passed to every body eval; since
  # handle_image injects the OCR text via set_rendered, it already includes the
  # image words -- so this is the total-body-word denominator.
  my $body_words = 0;
  $body_words += () = $_ =~ /\S+/g for @$body;
  return 0 unless $body_words;

  my $ratio = $image_words / $body_words;
  dbg("image: text ratio %.3f (image_words=%d body_words=%d min=%s)",
      $ratio, $image_words, $body_words, $min_ratio);
  return ($ratio >= $min_ratio) ? 1 : 0;
}

=back

=cut

1;
