#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("strip_no_subject");

use Test::More;
plan tests => 4;

# ---------------------------------------------------------------------------

use File::Copy;
use File::Compare qw(compare_text);

my $INPUT = 'data/spam/014';
my $MUNGED = "$workdir/strip_no_subject.munged";

tstprefs ("
        report_safe 1
        rewrite_header subject ***SPAM***
	");

# create report_safe 1 and -t output
sarun ("-L -t < $INPUT");
my $test_number = test_number();
if (move("$workdir/d.$testname/$test_number", $MUNGED)) {
  sarun ("-d < $MUNGED");
  ok(!compare_text($INPUT,"$workdir/d.$testname/$test_number"));
}
else {
  warn "move failed: $!\n";
  ok(0);
}

tstprefs ("
        report_safe 2
        rewrite_header subject ***SPAM***
	");

# create report_safe 2 output
sarun ("-L < $INPUT");
$test_number = test_number();
if (move("$workdir/d.$testname/$test_number", $MUNGED)) {
  sarun ("-d < $MUNGED");
  ok(!compare_text($INPUT,"$workdir/d.$testname/$test_number"));
}
else {
  warn "move failed: $!\n";
  ok(0);
}

tstprefs ("
        report_safe 0
        rewrite_header subject ***SPAM***
	");

# create report_safe 0 output
sarun ("-L < $INPUT");
$test_number = test_number();
if (move("$workdir/d.$testname/$test_number", $MUNGED)) {
  sarun ("-d < $MUNGED");
  ok(!compare_text($INPUT,"$workdir/d.$testname/$test_number"));
}
else {
  warn "move failed: $!\n";
  ok(0);
}

# Work directly on regular message, as though it was not spam
sarun ("-d < $INPUT");
$test_number = test_number();
ok(!compare_text($INPUT,"$workdir/d.$testname/$test_number"));
