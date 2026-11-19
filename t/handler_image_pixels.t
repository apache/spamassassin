#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_pixels");

use Test::More tests => 7;

# ---------------------------------------------------------------------------
# Test check_image_pixel_count in Handler::Image.
# The test image (data/nice/handler_image) is 800x200 = 160000 pixels.
# Pixel area is accumulated from the image header before any OCR gate, so this
# needs no tesseract: it runs the same whether or not OCR is available.
#   - min 100000           -> 160000 >= min            -> hit
#   - min 100000 max 200000 -> 100000 <= 160000 <= max -> hit
#   - min 500000           -> 160000 below min         -> no hit
#   - max 100000           -> 160000 above max         -> no hit
# ---------------------------------------------------------------------------

my $rules = "
  body  IMG_PX_MIN    eval:check_image_pixel_count(100000)
  score IMG_PX_MIN    1.0
  body  IMG_PX_RANGE  eval:check_image_pixel_count(100000, 200000)
  score IMG_PX_RANGE  1.0
  body  IMG_PX_HIMIN  eval:check_image_pixel_count(500000)
  score IMG_PX_HIMIN  1.0
  body  IMG_PX_LOMAX  eval:check_image_pixel_count(0, 100000)
  score IMG_PX_LOMAX  1.0
";

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
");
tstlocalrules ($rules);

# The 160000-pixel image meets the min and the range, but not the high min or
# the low max.
%patterns = (
  ' 1.0 IMG_PX_MIN ',    'pixel_count_meets_min',
  ' 1.0 IMG_PX_RANGE ',  'pixel_count_within_range',
);
%anti_patterns = (
  ' IMG_PX_HIMIN ',      'pixel_count_below_high_min',
  ' IMG_PX_LOMAX ',      'pixel_count_above_low_max',
);
ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

# A message with no image parts has zero pixels and must fire nothing, even
# with a min of 0.
my $rules0 = "
  body  IMG_PX_ZERO  eval:check_image_pixel_count(0)
  score IMG_PX_ZERO  1.0
";
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
");
tstlocalrules ($rules0);

%patterns = ();
%anti_patterns = (
  ' IMG_PX_ZERO ',  'no_hit_without_images',
);
ok (sarun ("-L -t < data/nice/base64.txt", \&patterns_run_cb));
ok_all_patterns();
