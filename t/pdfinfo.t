#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("pdfinfo");

use Test::More;

plan tests => 17;

%patterns = (
 q{ 1.0 PDFINFO_NAMED_REANY }, '',
 q{ 1.0 PDFINFO_DETAILS_CREATED }, '',
 q{ 1.0 PDFINFO_DETAILS_PRODUCER }, '',
 q{ 1.0 PDFINFO_DETAILS_CREATOR }, '',
 q{ 1.0 PDFINFO_COUNT_1 }, '',
 q{ 1.0 PDFINFO_EMPTY_BODY_0 }, '',
 q{ 1.0 PDFINFO_EMPTY_BODY_1000 }, '',
);
%anti_patterns = (
 q{ PDFINFO_DETAILS_AUTHOR }, '',
 q{ PDFINFO_DETAILS_TITLE }, '',
 q{ PDFINFO_COUNT_2_3 }, '',
 q{ PDFINFO_IMAGE_COUNT }, '',
 q{ PDFINFO_NAMED_FOO }, '',
 q{ PDFINFO_DETAILS_MODIFIED }, '',
 q{ PDFINFO_ENCRYPTED }, '',
 q{ PDFINFO_DETAILS_MODIFIED }, '',
 q{ PDFINFO_ENCRYPTED }, '',
 q{ PDFINFO_MD5 }, '',
 q{ PDFINFO_FUZZY_MD5 }, '',
 q{ PDFINFO_PC }, ''
);

tstprefs("
body PDFINFO_COUNT_1 eval:pdf_count(1)
body PDFINFO_COUNT_2_3 eval:pdf_count(2,3)
body PDFINFO_IMAGE_COUNT_1 eval:pdf_image_count(1)
body PDFINFO_IMAGE_COUNT_2_3 eval:pdf_image_count(2,3)
body PDFINFO_PC_1000 eval:pdf_pixel_coverage(1000)
body PDFINFO_PC_10000_100000 eval:pdf_pixel_coverage(10000,100000)
body PDFINFO_NAMED_FOO eval:pdf_named('foo.pdf')
body PDFINFO_NAMED_REANY eval:pdf_name_regex('/.+/')
body PDFINFO_MD5 eval:pdf_match_md5('XXYYZZ')
body PDFINFO_FUZZY_MD5 eval:pdf_match_md5('XXYYZZ')
body PDFINFO_DETAILS_AUTHOR eval:pdf_match_details('author', '/.+/')
body PDFINFO_DETAILS_CREATOR eval:pdf_match_details('creator', '/^Writer\$/')
body PDFINFO_DETAILS_CREATED eval:pdf_match_details('created', '/.+/')
body PDFINFO_DETAILS_MODIFIED eval:pdf_match_details('modified', '/.+/')
body PDFINFO_DETAILS_PRODUCER eval:pdf_match_details('producer', '/.+/')
body PDFINFO_DETAILS_TITLE eval:pdf_match_details('title', '/.+/')
body PDFINFO_ENCRYPTED eval:pdf_is_encrypted()
body PDFINFO_EMPTY_BODY_0 eval:pdf_is_empty_body()
body PDFINFO_EMPTY_BODY_1000 eval:pdf_is_empty_body(1000)
");

sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

