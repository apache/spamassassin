#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("extracttext");

use Test::More;

my $tests = 0;
foreach ((
   '/usr/bin/pdftohtml',
   '/usr/bin/pdftotext',
   '/usr/bin/tesseract',
)) {
   if (-x $_) {
      $tests++;
   } else {
      print STDERR "SKIPPING A TEST, $_ not found\n";
   }
}

plan skip_all => "no needed binaries found" unless $tests;
plan tests => $tests;

%patterns_gtube = (
   q{ BODY: Generic Test for Unsolicited Bulk Email }, 'gtube',
            );

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::ExtractText
");


if (-x "/usr/bin/pdftohtml") {
   tstprefs("
   $default_cf_lines
   extracttext_external    pdftohtml       /usr/bin/pdftohtml -i -stdout -noframes {} -
   extracttext_use         pdftohtml       .pdf application/pdf
   extracttext_timeout 5
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (-x "/usr/bin/pdftotext") {
   tstprefs("
   $default_cf_lines
   extracttext_external    pdftotext       /usr/bin/pdftotext -q -nopgbrk -enc UTF-8 {} -
   extracttext_use         pdftotext       .pdf application/pdf
   extracttext_timeout 5 10
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (-x "/usr/bin/tesseract") {
   tstprefs("
   extracttext_external    tesseract       /usr/bin/tesseract -c page_separator= {} -
   extracttext_use         tesseract       .bmp .jpg .png .tif
   extracttext_timeout 20
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_jpg.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

