#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");

use Test::More;
plan skip_all => 'Long running tests disabled' unless conf_bool('run_long_tests');
plan tests => 98;

# ---------------------------------------------------------------------------

use File::Copy;
use File::Compare qw(compare_text);
use Text::Diff;

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
        report_safe 0
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 0 output
  my $test_number = test_number();
  my $d_input = "$workdir/d.$testname/$test_number";
  unlink $d_input;
  ok sarun ("-L < $input");

  # test for existence; compare_text() will _create_ files!  wtf
  ok (-f $d_input);

  {
    print "output: $d_input\n";
		$test_number = test_number();
    my $d_output = "$workdir/d.$testname/$test_number";
    unlink $d_output;
    ok sarun ("-L -d < $d_input");
    ok (-f $d_output);
    ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
  }

  tstprefs ("
        report_safe 1
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

  # create report_safe 1 and -t output
	$test_number = test_number();
  $d_input = "$workdir/d.$testname/$test_number";
  unlink $d_input;
  ok sarun ("-L -t < $input");
  ok (-f $d_input);
  {
    print "output: $d_input\n";
		$test_number = test_number();
    my $d_output = "$workdir/d.$testname/$test_number";
    unlink $d_output;
    ok sarun ("-L -d < $d_input");
    ok (-f $d_output);
    ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
  }
}

# "report_safe 2" will work if "report_safe 1" works.
# normal mode should always work, do not test multiple files.
$input = $files[0];

tstprefs ("
        report_safe 2
        body TEST_ALWAYS /./
        score TEST_ALWAYS 100
	");

# create report_safe 2 output
my $test_number = test_number();
$d_input = "$workdir/d.$testname/$test_number";
unlink $d_input;
ok sarun ("-L < $input");
ok (-f $d_input);
{
  print "output: $d_input\n";
  $test_number = test_number();
  my $d_output = "$workdir/d.$testname/$test_number";
  unlink $d_output;
  ok sarun ("-L -d < $d_input");
  ok (-f $d_output);
  ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );
}

# Work directly on regular message, as though it was not spam
$test_number = test_number();
my $d_output = "$workdir/d.$testname/$test_number";
unlink $d_output;
ok sarun ("-L -d < $input");
ok (-f $d_output);
ok(!compare_text($input,$d_output))
        or diffwarn( $input, $d_output );

sub diffwarn {
  my ($f1, $f2) = @_;
  print STDERR "# Diff is as follows:\n";
  diff ($f1, $f2, { STYLE => 'unified', OUTPUT => \*STDERR });
  print "\n\n";
}

