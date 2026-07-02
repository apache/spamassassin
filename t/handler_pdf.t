#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("handler_pdf");

use Test::More;

# ---------------------------------------------------------------------------
# End-to-end test of Mail::SpamAssassin::Handler::PDF.
#
#  * handler_pdf            - a plaintext PDF (application/pdf) with one page and
#                             one link to www.google.com.  Exercises pdf2_count,
#                             pdf2_page_count, pdf2_link_count, pdf2_match_details
#                             and the pdf-type uri-detail rule.
#  * handler_pdf_octet      - the same PDF mislabelled application/octet-stream
#                             but named *.pdf.  Proves the filename->type mapping
#                             in Message::Node::effective_type routes it to the
#                             handler anyway.
#  * handler_pdf_encrypted  - the same PDF encrypted with a blank password
#                             (AES-256).  Exercises pdf2_is_encrypted and
#                             pdf2_is_encrypted_blank_pw; the parser decrypts it
#                             transparently so the link is still found.
#
# The parser is pure Perl, so the metadata tests run everywhere.  The text
# extraction tests additionally need pdftotext; they are skipped (not failed)
# when it is not installed.
#
# SATest scrubs PATH to a hermetic default that omits e.g. /opt/homebrew/bin, so
# search both that PATH and a few common install locations, then pass the binary
# to the handler explicitly via pdf_pdftotext_path.
my $pdftotext;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  my $cand = "$dir/pdftotext";
  if (-x $cand) { $pdftotext = $cand; last; }
}

# Image-OCR-of-embedded-images test needs BOTH the image handler (a separate
# plugin, only present once that branch is merged) and tesseract.  Detect both;
# skip the block cleanly otherwise.
my $tesseract;
for my $dir (split(/:/, $ENV{PATH}),
             qw(/usr/bin /usr/local/bin /opt/homebrew/bin /opt/local/bin)) {
  my $cand = "$dir/tesseract";
  if (-x $cand) { $tesseract = $cand; last; }
}
my $have_image_handler = eval { require Mail::SpamAssassin::Handler::Image; 1 };
my $can_ocr_images = $tesseract && $have_image_handler;

# 16 metadata assertions always run; +3 text assertions when pdftotext is found;
# +1 image-OCR assertion when both the image handler and tesseract are present.
plan tests => 16 + ($pdftotext ? 3 : 0) + ($can_ocr_images ? 1 : 0);

tstpre ("
  loadhandler Mail::SpamAssassin::Handler::PDF
" . ($pdftotext ? "  pdf_pdftotext_path $pdftotext\n" : "")
  . ($can_ocr_images ? "  loadhandler Mail::SpamAssassin::Handler::Image\n"
                       ."  image_tesseract_path $tesseract\n" : ""));

tstlocalrules ('
  body PDF_PRESENT     eval:pdf2_count(1)
  score PDF_PRESENT    1.0
  describe PDF_PRESENT Message has a PDF attachment

  body PDF_PAGES       eval:pdf2_page_count(1,1)
  score PDF_PAGES      1.0
  describe PDF_PAGES   PDF has exactly one page

  body PDF_LINKS       eval:pdf2_link_count(1)
  score PDF_LINKS      1.0
  describe PDF_LINKS   PDF has at least one link

  body PDF_PRODUCER    eval:pdf2_match_details("Producer","Quartz")
  score PDF_PRODUCER   1.0
  describe PDF_PRODUCER PDF Producer matches Quartz

  uri-detail PDF_GOOGLE  type =~ /^pdf$/  raw =~ /google\.com/
  score PDF_GOOGLE     1.0
  describe PDF_GOOGLE  google.com link found inside the PDF

  body PDF_ENCRYPTED   eval:pdf2_is_encrypted()
  score PDF_ENCRYPTED  1.0
  describe PDF_ENCRYPTED PDF attachment is encrypted

  body PDF_BLANK_PW    eval:pdf2_is_encrypted_blank_pw()
  score PDF_BLANK_PW   1.0
  describe PDF_BLANK_PW PDF is encrypted with a blank password

  body PDF_ORIG        /ORIGINAL_BODY_MARKER/
  score PDF_ORIG       1.0
  describe PDF_ORIG    original body text preserved alongside the PDF

  body PDF_SENTINEL_BODY /PDFSENTINEL/
  score PDF_SENTINEL_BODY 1.0
  describe PDF_SENTINEL_BODY pdftotext text reached body rules

  pdftext PDF_SENTINEL_TEXT /PDFSENTINEL/
  score PDF_SENTINEL_TEXT 1.0
  describe PDF_SENTINEL_TEXT pdftext rule matched extracted text

  body PDF_HASWORDS    eval:pdf2_word_count(1)
  score PDF_HASWORDS   1.0
  describe PDF_HASWORDS PDF has extracted words

  body PDF_IMG_OCR     /OCRSENTINEL/
  score PDF_IMG_OCR    1.0
  describe PDF_IMG_OCR OCR text from a PDF-embedded image reached body rules
');

# --- Plaintext PDF (application/pdf) ---------------------------------------
%patterns = (
  ' 1.0 PDF_PRESENT ',   'pdf_present',
  ' 1.0 PDF_PAGES ',     'pdf_page_count',
  ' 1.0 PDF_LINKS ',     'pdf_link_count',
  ' 1.0 PDF_PRODUCER ',  'pdf_match_details',
  ' 1.0 PDF_GOOGLE ',    'pdf_uri_detail',
  ' 1.0 PDF_ORIG ',      'original_body_preserved',
);
%anti_patterns = (
  ' PDF_ENCRYPTED ',     'plaintext_not_encrypted',
);
ok (sarun ("-L -t < data/nice/handler_pdf", \&patterns_run_cb));
ok_all_patterns();

# --- Same PDF mislabelled application/octet-stream (file_type_map dispatch) -
%patterns = (
  ' 1.0 PDF_PRESENT ',   'pdf_present_octet',
  ' 1.0 PDF_GOOGLE ',    'pdf_uri_detail_octet',
);
%anti_patterns = ();
ok (sarun ("-L -t < data/nice/handler_pdf_octet", \&patterns_run_cb));
ok_all_patterns();

# --- Encrypted (blank password) PDF ----------------------------------------
%patterns = (
  ' 1.0 PDF_PRESENT ',   'pdf_present_enc',
  ' 1.0 PDF_ENCRYPTED ', 'pdf_encrypted',
  ' 1.0 PDF_BLANK_PW ',  'pdf_encrypted_blank_pw',
  ' 1.0 PDF_GOOGLE ',    'pdf_uri_detail_enc',
);
ok (sarun ("-L -t < data/nice/handler_pdf_encrypted", \&patterns_run_cb));
ok_all_patterns();

# --- Text extraction via pdftotext (only when the binary is available) ------
# sample.pdf contains the text "PDFSENTINEL".  Confirm pdftotext output reaches
# both ordinary body rules (via set_rendered) and the pdftext rule type, and
# that pdf2_word_count sees the words.
if ($pdftotext) {
  %patterns = (
    ' 1.0 PDF_SENTINEL_BODY ', 'pdftext_in_body',
    ' 1.0 PDF_SENTINEL_TEXT ', 'pdftext_rule',
    ' 1.0 PDF_HASWORDS ',      'pdf_word_count',
  );
  %anti_patterns = ();
  sarun ("-L -t < data/nice/handler_pdf", \&patterns_run_cb);
  ok_all_patterns();
}

# --- Image extraction -> OCR (needs the image handler AND tesseract) ---------
# handler_pdf_ocrimage embeds a PDF whose only content is a raster image of the
# text "OCRSENTINEL".  The PDF handler extracts it as an image/png sub-part, the
# framework dispatches that to the image handler, which OCRs it, and the text
# reaches body rules.
if ($can_ocr_images) {
  %patterns = (
    ' 1.0 PDF_IMG_OCR ', 'pdf_image_ocr',
  );
  %anti_patterns = ();
  sarun ("-L -t < data/nice/handler_pdf_ocrimage", \&patterns_run_cb);
  ok_all_patterns();
}
