#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("extracttext");
use Mail::SpamAssassin::Util;
use Test::More;

use constant PDFTOTEXT => Mail::SpamAssassin::Util::find_executable_in_env_path('pdftotext');
use constant TESSERACT => Mail::SpamAssassin::Util::find_executable_in_env_path('tesseract');
use constant CAT => Mail::SpamAssassin::Util::find_executable_in_env_path('cat');

my $tests = 0;
$tests += 2 if (PDFTOTEXT);
$tests += 1 if (TESSERACT);
$tests += 1 if (CAT);
if ($tests && $tests < 4) { diag("some binaries missing, not running all tests\n"); }

plan skip_all => "no needed binaries found, pdftotext, tesseract, or cat" unless $tests;
plan tests => $tests;

%patterns_gtube = (
  q{ 1000 GTUBE }, 'gtube',
);

if (PDFTOTEXT) {
   tstprefs("
     extracttext_external  pdftotext  ".PDFTOTEXT." -nopgbrk -layout -enc UTF-8 {} -
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
     extracttext_external  pdftotext  ".PDFTOTEXT." -nopgbrk -layout -enc UTF-8 {} -
     extracttext_use       pdftotext  .FOO
     extracttext_timeout 30 40
   ");
   %anti_patterns = %patterns_gtube;
   %patterns = ();
   sarun ("-L -t < data/spam/extracttext/gtube_pdf.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (TESSERACT) {
   tstprefs("
     extracttext_external  tesseract  {OMP_THREAD_LIMIT=1} ".TESSERACT." -c page_separator= {} -
     extracttext_use       tesseract  .jpg .png .bmp .tif .tiff image/(?:jpeg|png|x-ms-bmp|tiff)
     extracttext_timeout 30 1
   ");
   %anti_patterns = ();
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_png.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

if (CAT) {
   tstprefs("
     extracttext_external  cat  ".CAT." {}
     extracttext_use       cat  .txt .html .shtml .xhtml octet/stream
     extracttext_timeout 30 1
   ");
   %anti_patterns = ();
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_b64_oct.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

