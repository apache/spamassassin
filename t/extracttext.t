#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("extracttext");
use Mail::SpamAssassin::Util;
use Test::More;

use constant PDFTOTEXT => eval { my $f = Mail::SpamAssassin::Util::find_executable_in_env_path('pdftotext'); ($f !~ /\s/)?$f:'"'.$f.'"'};
use constant TESSERACT => eval { my $f = Mail::SpamAssassin::Util::find_executable_in_env_path('tesseract'); ($f !~ /\s/)?$f:'"'.$f.'"'};
use constant CAT => eval { my $f = Mail::SpamAssassin::Util::find_executable_in_env_path('cat'); ($f !~ /\s/)?$f:'"'.$f.'"'};
use constant HAS_DBI        => eval { require DBI; };
use constant HAS_DBD_SQLITE => eval { require DBD::SQLite; DBD::SQLite->VERSION(1.59_01); };
use constant SQLITE         => (HAS_DBI && HAS_DBD_SQLITE);

my $tests = 0;
$tests += 2 if (PDFTOTEXT);
$tests += 1 if (TESSERACT);
$tests += 1 if (CAT);
$tests += 4 if (CAT && SQLITE);
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
     extracttext_use       cat  .txt
     extracttext_timeout 30 1
   ");
   %anti_patterns = ();
   %patterns = %patterns_gtube;
   sarun ("-L -t < data/spam/extracttext/gtube_b64_oct.eml", \&patterns_run_cb);
   ok_all_patterns();
   clear_pattern_counters();
}

###
### With SQLITE caching
###

if (CAT && SQLITE) {

tstprefs("
  extracttext_external  cat  ".CAT." {}
  extracttext_use       cat  .txt
  extracttext_timeout 30 1
  extracttext_cache_type dbi
  extracttext_cache_dsn dbi:SQLite:dbname=$workdir/ExtractText.db
  extracttext_cache_ttl 86400
  extracttext_cache_autoclean 0
");

%anti_patterns = ();
%patterns = %patterns_gtube;
sarun ("-L -t < data/spam/extracttext/gtube_b64_oct.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

my $dbh = DBI->connect("dbi:SQLite:dbname=$workdir/ExtractText.db","","");
my @row = $dbh->selectrow_array("SELECT file_text FROM extracttext_cache LIMIT 1");
like($row[0], qr/GTUBE/, 'cache stores extracted text');

# Second run must still match (text served from cache)
%patterns = %patterns_gtube;
sarun ("-L -t < data/spam/extracttext/gtube_b64_oct.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

$dbh = DBI->connect("dbi:SQLite:dbname=$workdir/ExtractText.db","","");
@row = $dbh->selectrow_array("SELECT hits FROM extracttext_cache LIMIT 1");
is($row[0], 1, 'second run served from cache without re-extraction');

}

