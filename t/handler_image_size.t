#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_size");

use Test::More;

# ---------------------------------------------------------------------------
# Test the image_ocr_min_width / image_ocr_min_height gate in Handler::Image.
# The test image (data/nice/handler_image) is 800x200 and OCRs to OCRSENTINEL.
#   - min_width 2000  -> image is below the gate -> OCR skipped (no hits)
#   - min_width 100   -> image passes the gate   -> OCR runs (hits)
# Requires tesseract; skip cleanly if not installed.

my $tesseract;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  if (-x "$dir/tesseract") { $tesseract = "$dir/tesseract"; last; }
}

if (!$tesseract) {
  plan skip_all => "tesseract not found";
}
else {
  plan tests => 6;
}

my $rules = "
  body  IMG_OCR        /OCRSENTINEL/
  score IMG_OCR        1.0
  body  IMG_HAS_OCR    eval:check_image_text_ratio(0.01)
  score IMG_HAS_OCR    1.0
";

# --- gate ABOVE the image size: OCR must be skipped -------------------------
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
  image_ocr_min_width 2000
");
tstlocalrules ($rules);

%patterns = ();
%anti_patterns = (
  ' IMG_OCR ',      'ocr_skipped_by_gate',
  ' IMG_HAS_OCR ',  'no_ocr_metadata_when_skipped',
);
ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

# --- gate BELOW the image size: OCR must run --------------------------------
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
  image_ocr_min_width 100
");
tstlocalrules ($rules);

%patterns = (
  ' 1.0 IMG_OCR ',      'ocr_runs_below_gate',
  ' 1.0 IMG_HAS_OCR ',  'ocr_metadata_present',
);
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
