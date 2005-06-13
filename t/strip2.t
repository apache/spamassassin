#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");
use Test;

# ---------------------------------------------------------------------------

use File::Copy;
use File::Compare qw(compare_text);

my @files = qw(
	data/spam/002
	data/spam/004
	data/spam/011
	data/spam/badmime2.txt
	data/spam/015
	data/spam/016
	data/spam/017
	);
my $MUNGED = 'log/strip2.munged';
my $INPUT;

plan tests => 2 + 2 * @files;

# Make sure all the files can do "report_safe 0" and "report_safe 1"
foreach $INPUT (@files) {
  tstprefs ("
        $default_cf_lines
        report_safe 0
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 0 output
  sarun ("-L < $INPUT");
  if (move("log/$testname.${Test::ntest}", $MUNGED)) {
    sarun ("-d < $MUNGED");
    ok(!compare_text($INPUT,"log/$testname.${Test::ntest}"));
  }
  else {
    warn "move failed: $!\n";
    ok(0);
  }

  tstprefs ("
        $default_cf_lines
        report_safe 1
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 1 and -t output
  sarun ("-L -t < $INPUT");
  if (move("log/$testname.${Test::ntest}", $MUNGED)) {
    sarun ("-d < $MUNGED");
    ok(!compare_text($INPUT,"log/$testname.${Test::ntest}"));
  }
  else {
    warn "move failed: $!\n";
    ok(0);
  }
}

# "report_safe 2" will work if "report_safe 1" works.
# normal mode should always work, don't test multiple files.
$INPUT = $files[0];

tstprefs ("
        $default_cf_lines
        report_safe 2
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

# create report_safe 2 output
sarun ("-L < $INPUT");
if (move("log/$testname.${Test::ntest}", $MUNGED)) {
  sarun ("-d < $MUNGED");
  ok(!compare_text($INPUT,"log/$testname.${Test::ntest}"));
}
else {
  warn "move failed: $!\n";
  ok(0);
}

# Work directly on regular message, as though it was not spam
sarun ("-d < $INPUT");
ok(!compare_text($INPUT,"log/$testname.${Test::ntest}"));

