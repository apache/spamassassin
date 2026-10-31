#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_words");

use Test::More;

# ---------------------------------------------------------------------------
# Test check_image_word_count in Handler::Image.  It reports the number of words
# OCR'd from all image parts, so it needs tesseract to have actually run; skip
# cleanly when tesseract is not installed.
#
# The test image (data/nice/handler_image) OCRs to some words (at least the
# "OCRSENTINEL" token).  We avoid asserting an exact count -- tesseract output
# varies by version -- and instead check robust bounds:
#   - min 1       -> some words were OCR'd            -> hit
#   - min 1 max 10000 -> count is within a wide range -> hit
#   - min 10000   -> far more words than any logo has -> no hit
#   - max 0       -> impossible upper bound           -> no hit
# ---------------------------------------------------------------------------

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

my $rules = "
  body  IMG_WC_MIN    eval:check_image_word_count(1)
  score IMG_WC_MIN    1.0
  body  IMG_WC_RANGE  eval:check_image_word_count(1, 10000)
  score IMG_WC_RANGE  1.0
  body  IMG_WC_HIMIN  eval:check_image_word_count(10000)
  score IMG_WC_HIMIN  1.0
  body  IMG_WC_LOMAX  eval:check_image_word_count(0, 0)
  score IMG_WC_LOMAX  1.0
";

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_tesseract_path $tesseract
");
tstlocalrules ($rules);

%patterns = (
  ' 1.0 IMG_WC_MIN ',    'word_count_meets_min',
  ' 1.0 IMG_WC_RANGE ',  'word_count_within_range',
);
%anti_patterns = (
  ' IMG_WC_HIMIN ',      'word_count_below_high_min',
  ' IMG_WC_LOMAX ',      'word_count_above_zero_max',
);
ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
