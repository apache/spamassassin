#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("extracttext");

use Test::More;

use constant HAS_PDFTOTEXT => eval { $_ = untaint_cmd("which pdftotext"); chomp; -x };
use constant HAS_TESSERACT => eval { $_ = untaint_cmd("which tesseract"); chomp; -x };

my $tests = 0;
$tests += 2 if (HAS_PDFTOTEXT);
$tests += 1 if (HAS_TESSERACT);
if ($tests && $tests < 3) { diag("some binaries missing, not running all tests\n"); }

plan skip_all => "no needed binaries found" unless $tests;
plan tests => $tests;

%patterns_gtube = (
  q{ 1000 GTUBE }, 'gtube',
);

if (HAS_PDFTOTEXT) {
   tstprefs("
     extracttext_external  pdftotext  /usr/bin/pdftotext -nopgbrk -layout -enc UTF-8 {} -
     extracttext_use       pdftotext  .pdf
     extracttext_timeout 30 40
   ");
   %anti_patterns = ();
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();

   # Should fail
   tstprefs("
     extracttext_external  pdftotext  /usr/bin/pdftotext -nopgbrk -layout -enc UTF-8 {} -
     extracttext_use       pdftotext  .FOO
     extracttext_timeout 30 40
   ");
   %anti_patterns = %patterns_gtube;
   %patterns = ();
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (HAS_TESSERACT) {
   tstprefs("
     extracttext_external  tesseract  {OMP_THREAD_LIMIT=1} /usr/bin/tesseract -c page_separator= {} -
     extracttext_use       tesseract  .jpg .png .bmp .tif .tiff image/(?:jpeg|png|x-ms-bmp|tiff)
     extracttext_timeout 30 1
   ");
   %anti_patterns = ();
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_jpg.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

