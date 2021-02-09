#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("extracttext");

use Test::More;

plan skip_all => "pdftohtml and tesseract needed" unless ( -f "/usr/bin/pdftohtml" and -f "/usr/bin/tesseract" );
plan tests => 2;

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::ExtractText
");

tstprefs("
$default_cf_lines

extracttext_external    pdftohtml       /usr/bin/pdftohtml -i -stdout -noframes {} -
extracttext_use         pdftohtml       .pdf application/pdf

extracttext_external    tesseract       /usr/bin/tesseract {} -
extracttext_use         tesseract       .bmp .jpg .png .tif
");

%patterns_gtube = (
   q{ BODY: Generic Test for Unsolicited Bulk Email }, 'gtube',
            );

%patterns = %patterns_gtube;
sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();


%patterns = %patterns_gtube;
sarun ("-L -t < data/spam/extracttext/gtube_jpg.eml", \&patterns_run_cb);
ok_all_patterns();
