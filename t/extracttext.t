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

if (-x "/usr/bin/pdftohtml") {
   tstprefs("
     extracttext_external  pdftohtml  /usr/bin/pdftohtml -i -stdout -noframes -nodrm {} -
     extracttext_use       pdftohtml  .pdf application/pdf
     extracttext_timeout 30
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (-x "/usr/bin/pdftotext") {
   tstprefs("
     extracttext_external  pdftotext  /usr/bin/pdftotext -q -nopgbrk -enc UTF-8 {} -
     extracttext_use       pdftotext  .pdf application/pdf
     extracttext_timeout 30 40
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (-x "/usr/bin/tesseract") {
   tstprefs("
     extracttext_external  tesseract  {OMP_THREAD_LIMIT=1} /usr/bin/tesseract -c page_separator= {} -
     extracttext_use       tesseract  .bmp .jpg .png .tif
     extracttext_timeout 30 1
   ");
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_jpg.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

