#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_image_qr");

use Test::More;

# ---------------------------------------------------------------------------
# Test QR-code decoding in Handler::Image: a URL encoded in a QR code in an
# image part is decoded with zbarimg and added to the message's URI list with
# type "qr", so uri_detail (and ordinary uri) rules can match it.
# Requires zbarimg (from ZBar); skip cleanly if it is not installed.
# ---------------------------------------------------------------------------

my $zbarimg;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  if (-x "$dir/zbarimg") { $zbarimg = "$dir/zbarimg"; last; }
}

if (!$zbarimg) {
  plan skip_all => "zbarimg not found";
}
else {
  plan tests => 5;
}

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_zbarimg_path $zbarimg
");

# The fixture data/nice/handler_image_qr carries a QR code encoding the URL
# https://qr-sentinel.example/abc123 .  QR_URI_TYPE matches any URI tagged with
# the "qr" type (i.e. one that came from a QR code), and QR_URI_TEXT matches the
# decoded URL itself -- together they prove the decoded URL reached the URI list.
tstlocalrules ('
  uri_detail QR_URI_TYPE  type =~ /^qr$/
  score      QR_URI_TYPE  1.0
  describe   QR_URI_TYPE  a URI tagged as coming from a QR code

  uri        QR_URI_TEXT  /qr-sentinel\.example/
  score      QR_URI_TEXT  1.0
  describe   QR_URI_TEXT  the decoded QR URL reached the URI list
');

%patterns = (
  ' 1.0 QR_URI_TYPE ',  'qr_uri_type_tagged',
  ' 1.0 QR_URI_TEXT ',  'qr_url_decoded',
);

ok (sarun ("-L -t < data/nice/handler_image_qr", \&patterns_run_cb));
ok_all_patterns();
clear_pattern_counters();

# An image with no QR code must fire nothing (and must not error on zbarimg's
# exit status 4, "no barcode found").
tstpre ("
  loadhandler Mail::SpamAssassin::Handler::Image
  image_zbarimg_path $zbarimg
");
tstlocalrules ('
  uri_detail QR_NONE  type =~ /^qr$/
  score      QR_NONE  1.0
  describe   QR_NONE  should not fire on an image with no QR code
');

%patterns = ();
%anti_patterns = (
  ' QR_NONE ',  'no_qr_no_hit',
);

ok (sarun ("-L -t < data/nice/handler_image", \&patterns_run_cb));
ok_all_patterns();
