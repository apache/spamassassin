#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_count");

use Test::More tests => 11;

# ---------------------------------------------------------------------------
# Test check_image_count in Handler::Image.
# The test message (data/nice/handler_image_two) has two image/png parts.
# The count is accumulated in handle_image before any OCR gate, so this needs
# no tesseract: it runs the same whether or not OCR is available.
#   - min 1             -> 2 >= min            -> hit
#   - min 2             -> 2 >= min (boundary) -> hit
#   - min 1 max 2       -> 1 <= 2 <= max       -> hit
#   - min 3             -> 2 below min         -> no hit
#   - max 1             -> 2 above max         -> no hit
# ---------------------------------------------------------------------------

my $rules = "
  body  IMG_CNT_MIN1    eval:check_image_count(1)
  score IMG_CNT_MIN1    1.0
  body  IMG_CNT_MIN2    eval:check_image_count(2)
  score IMG_CNT_MIN2    1.0
  body  IMG_CNT_RANGE   eval:check_image_count(1, 2)
  score IMG_CNT_RANGE   1.0
  body  IMG_CNT_HIMIN   eval:check_image_count(3)
  score IMG_CNT_HIMIN   1.0
  body  IMG_CNT_LOMAX   eval:check_image_count(0, 1)
  score IMG_CNT_LOMAX   1.0
";

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
");
tstlocalrules ($rules);

# The two-image message meets the low min, the boundary min and the range, but
# not the high min or the low max.
%patterns = (
  ' 1.0 IMG_CNT_MIN1 ',   'count_meets_low_min',
  ' 1.0 IMG_CNT_MIN2 ',   'count_meets_boundary_min',
  ' 1.0 IMG_CNT_RANGE ',  'count_within_range',
);
%anti_patterns = (
  ' IMG_CNT_HIMIN ',      'count_below_high_min',
  ' IMG_CNT_LOMAX ',      'count_above_low_max',
);
ok (sarun ("-L -t < data/nice/handler_image_two", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

# A message with no image parts has a zero count and must fire nothing, even
# with a min of 0.
my $rules0 = "
  body  IMG_CNT_ZERO  eval:check_image_count(0)
  score IMG_CNT_ZERO  1.0
";
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
");
tstlocalrules ($rules0);

%patterns = ();
%anti_patterns = (
  ' IMG_CNT_ZERO ',  'no_hit_without_images',
);
ok (sarun ("-L -t < data/nice/base64.txt", \&patterns_run_cb));
ok_all_patterns();

# A message with a single image part counts exactly one: min 1 hits, min 2 does
# not (confirms the tally is per-part, not a boolean "has images").
clear_pattern_counters();
my $rules1 = "
  body  IMG_CNT_ONE_MIN1  eval:check_image_count(1)
  score IMG_CNT_ONE_MIN1  1.0
  body  IMG_CNT_ONE_MIN2  eval:check_image_count(2)
  score IMG_CNT_ONE_MIN2  1.0
";
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
");
tstlocalrules ($rules1);

%patterns = (
  ' 1.0 IMG_CNT_ONE_MIN1 ',  'single_image_meets_min1',
);
%anti_patterns = (
  ' IMG_CNT_ONE_MIN2 ',      'single_image_below_min2',
);
ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
