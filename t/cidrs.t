#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use Test;
use Mail::SpamAssassin;

use Mail::SpamAssassin::NetSet;

my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/rules",
});

$sa->init(0); # parse rules

Mail::SpamAssassin::NetSet::test_load_code();
plan tests => $Mail::SpamAssassin::NetSet::NUMTESTS;
Mail::SpamAssassin::NetSet::test(\&ok);

