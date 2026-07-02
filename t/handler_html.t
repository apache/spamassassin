#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_html");

use Test::More tests => 3;

# ---------------------------------------------------------------------------
# Prove that inline data: images embedded in HTML are surfaced to the MIME-part
# handler framework as pseudo parts:
#   - the message body is text/html containing an <img src="data:image/png;
#     base64,...">, with no real MIME part for the image,
#   - a plugin registers an image/* handler; the HTML renderer extracts the
#     inline image, builds a synthetic part, and apply_handlers() dispatches it
#     to the handler, which verifies the decoded PNG bytes + content type and
#     sets a per-message flag its eval rule reads (DATA_IMAGE_SEEN),
#   - the original HTML body text still reaches body rules (HANDLER_ORIG).

tstpre ('
  loadhandler Mail::SpamAssassin::Handler::HTML
  loadhandler myTestImageHandler ../../../data/mockimagehandler.pm
');

tstlocalrules ('
  body HANDLER_ORIG       /ORIGINAL_BODY_MARKER/
  score HANDLER_ORIG      1.0
  describe HANDLER_ORIG   original HTML body text is preserved

  header DATA_IMAGE_SEEN  eval:check_data_image_handler()
  score DATA_IMAGE_SEEN   1.0
  describe DATA_IMAGE_SEEN inline data: image reached image/* handler
');

%patterns = (
  ' 1.0 HANDLER_ORIG ',     'original_body_preserved',
  ' 1.0 DATA_IMAGE_SEEN ',  'data_image_handler_fired',
);

ok (sarun ("-L -t < data/nice/handler_html", \&patterns_run_cb));
ok_all_patterns();
