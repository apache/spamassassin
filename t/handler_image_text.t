#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("imagetext");

use Test::More;

# ---------------------------------------------------------------------------
# Test the imagetext rule type provided by Handler::Image: a regex written with
# the "imagetext RULE /re/" directive matches against text OCR'd from image
# parts.  Requires tesseract; skip cleanly if it is not installed.

my $tesseract;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  if (-x "$dir/tesseract") { $tesseract = "$dir/tesseract"; last; }
}

if (!$tesseract) {
  plan skip_all => "tesseract not found";
}
else {
  plan tests => 5;
}

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
");

tstlocalrules ('
  imagetext IMGTEXT_HIT   /OCRSENTINEL/
  score     IMGTEXT_HIT   1.0
  describe  IMGTEXT_HIT   imagetext rule matched OCR text

  imagetext IMGTEXT_MISS  /NOTINTHEIMAGE/
  score     IMGTEXT_MISS  1.0
  describe  IMGTEXT_MISS  imagetext rule that should not match

  body HANDLER_HAS_OCR    eval:check_image_text_ratio(0.01)
  score HANDLER_HAS_OCR   1.0

  imagetext __IMGTEXT_M   /SENTINEL/
  tflags    __IMGTEXT_M   multiple maxhits=3
  meta      IMGTEXT_MULTI (__IMGTEXT_M >= 1)
  score     IMGTEXT_MULTI 1.0
  describe  IMGTEXT_MULTI multiple/maxhits imagetext path works
');

%patterns = (
  ' 1.0 IMGTEXT_HIT ',     'imagetext_matched',
  ' 1.0 HANDLER_HAS_OCR ', 'ocr_ran',
  ' 1.0 IMGTEXT_MULTI ',   'imagetext_multiple_path',
);
%anti_patterns = (
  ' IMGTEXT_MISS ',  'imagetext_no_false_match',
);

ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
