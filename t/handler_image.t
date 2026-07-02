#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::Image: an image/png part
# containing the rendered text "OCRSENTINEL" is OCR'd by tesseract, the text is
# injected into the body, and both a body rule matching the OCR text and the
# handler's check_image_text_ratio() eval rule fire.
#
# Requires the tesseract binary; skip cleanly if it is not installed so the
# suite stays green on machines without it.

# SATest scrubs PATH to a hermetic default that omits e.g. /opt/homebrew/bin,
# so search both that PATH and a few common install locations, then pass the
# binary to the handler explicitly via image_tesseract_path.  Skip cleanly if
# tesseract really isn't installed.
my $tesseract;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  my $cand = "$dir/tesseract";
  if (-x $cand) { $tesseract = $cand; last; }
}

if (!$tesseract) {
  plan skip_all => "tesseract not found";
}
else {
  plan tests => 4;
}

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
");

tstlocalrules ('
  body HANDLER_OCR       /OCRSENTINEL/
  score HANDLER_OCR      1.0
  describe HANDLER_OCR   OCR text from an image reached body rules

  body HANDLER_ORIG      /ORIGINAL_BODY_MARKER/
  score HANDLER_ORIG     1.0
  describe HANDLER_ORIG  original body text preserved alongside OCR

  body HANDLER_IMG_RATIO eval:check_image_text_ratio(0.01)
  score HANDLER_IMG_RATIO  1.0
  describe HANDLER_IMG_RATIO  Image handler reported OCR text
');

%patterns = (
  ' 1.0 HANDLER_OCR ',        'ocr_text_in_body',
  ' 1.0 HANDLER_ORIG ',       'original_body_preserved',
  ' 1.0 HANDLER_IMG_RATIO ',  'image_text_ratio_eval',
);

ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
