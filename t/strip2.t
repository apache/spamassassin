#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("strip2");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

use File::Copy;

sub diff {
  my ($f1, $f2) = @_;
  system ("diff $f1 $f2 > /dev/null");
  return ($? >> 8);
}

my $INPUT = 'data/spam/002';
my $MUNGED = 'log/strip2.munged';
my $OUTPUT = 'log/strip2.output';

# create the -t output
sarun ("-L -t < $INPUT > $MUNGED", \&patterns_run_cb);
sarun ("-d < $MUNGED > $OUTPUT", \&patterns_run_cb);
ok(diff($INPUT,$OUTPUT));

# create the -P output
sarun ("-L < $INPUT > $MUNGED", \&patterns_run_cb);
sarun ("-d < $MUNGED > $OUTPUT", \&patterns_run_cb);
ok(diff($INPUT,$OUTPUT));

# Work directly on regular message, as though it was not spam
sarun ("-d < $INPUT > $OUTPUT", \&patterns_run_cb);
ok(diff($INPUT,$OUTPUT));
