#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_heic");

use Test::More;

# ---------------------------------------------------------------------------
# Test Handler::Image's HEIF/HEIC support: an image part whose bytes are HEIC
# but whose declared Content-Type is image/png (the spammer mislabel trick) is
# detected by magic number, converted to PNG via heif-convert, and OCR'd.  The
# rendered text "HEICSENTINEL" must reach body rules.
#
# Requires both tesseract and heif-convert; skip cleanly if either is missing.

sub find_bin {
  my ($name) = @_;
  for my $dir (split(/:/, $ENV{PATH}),
               qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
    return "$dir/$name" if -x "$dir/$name";
  }
  return undef;
}

my $tesseract = find_bin('tesseract');
my $heif      = find_bin('heif-convert');

if (!$tesseract || !$heif) {
  plan skip_all => "tesseract and heif-convert both required";
}
else {
  plan tests => 6;
}

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
  image_heif_convert_path $heif
");

tstlocalrules ('
  body HANDLER_HEIC      /HEICSENTINEL/
  score HANDLER_HEIC     1.0
  describe HANDLER_HEIC  OCR text from a (mislabelled) HEIC image reached body rules

  body HANDLER_ORIG      /ORIGINAL_BODY_MARKER/
  score HANDLER_ORIG     1.0
  describe HANDLER_ORIG  original body text preserved
');

%patterns = (
  ' 1.0 HANDLER_HEIC ',  'heic_ocr_in_body',
  ' 1.0 HANDLER_ORIG ',  'original_body_preserved',
);

ok (sarun ("-L -t < data/nice/handler_image_heic", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

# Same HEIC, but declared application/octet-stream with a .heic filename.  This
# exercises effective_type's extension mapping (.heic -> image/heic): without it
# the part would never match the plugin's image/* handler and never be OCR'd.
%patterns = (
  ' 1.0 HANDLER_HEIC ',  'octet_heic_ocr_in_body',
  ' 1.0 HANDLER_ORIG ',  'octet_original_body_preserved',
);

ok (sarun ("-L -t < data/nice/handler_image_octet", \&patterns_run_cb));
ok_all_patterns();
