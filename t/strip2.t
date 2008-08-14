#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");
use Test;

use constant TEST_ENABLED => conf_bool('run_long_tests');

BEGIN { plan tests => TEST_ENABLED ? 98 : 0 };
exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

use File::Copy;
use File::Compare qw(compare_text);

my @files = qw(
	data/nice/crlf-endings
	data/nice/no_body
	data/spam/002
	data/spam/004
	data/spam/011
	data/spam/badmime2.txt
	data/spam/015
	data/spam/016
	data/spam/017
	);
my $input;

# Make sure all the files can do "report_safe 0" and "report_safe 1"
foreach $input (@files) {
  tstprefs ("
        $default_cf_lines
        report_safe 0
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 0 output
  my $d_input = "log/d.$testname/${Test::ntest}";
  unlink $d_input;
  ok sarun ("-L < $input");

  # test for existence; compare_text() will _create_ files!  wtf
  ok (-f $d_input);

  {
    print "output: $d_input\n";
    my $d_output = "log/d.$testname/${Test::ntest}";
    unlink $d_output;
    ok sarun ("-d < $d_input");
    ok (-f $d_output);
    ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
  }

  tstprefs ("
        $default_cf_lines
        report_safe 1
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 1 and -t output
  $d_input = "log/d.$testname/${Test::ntest}";
  unlink $d_input;
  ok sarun ("-L -t < $input");
  ok (-f $d_input);
  {
    print "output: $d_input\n";
    my $d_output = "log/d.$testname/${Test::ntest}";
    unlink $d_output;
    ok sarun ("-d < $d_input");
    ok (-f $d_output);
    ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
  }
}

# "report_safe 2" will work if "report_safe 1" works.
# normal mode should always work, do not test multiple files.
$input = $files[0];

tstprefs ("
        $default_cf_lines
        report_safe 2
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

# create report_safe 2 output
$d_input = "log/d.$testname/${Test::ntest}";
unlink $d_input;
ok sarun ("-L < $input");
ok (-f $d_input);
{
  print "output: $d_input\n";
  my $d_output = "log/d.$testname/${Test::ntest}";
  unlink $d_output;
  ok sarun ("-d < $d_input");
  ok (-f $d_output);
  ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
}

# Work directly on regular message, as though it was not spam
my $d_output = "log/d.$testname/${Test::ntest}";
unlink $d_output;
ok sarun ("-d < $input");
ok (-f $d_output);
ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );


sub diffwarn {
  my ($f1, $f2) = @_;
  print "# Diff is as follows:\n";
  system "diff -u $f1 $f2";
  print "\n\n";
}

