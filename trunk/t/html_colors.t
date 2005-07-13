#!/usr/bin/perl -w

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
use Mail::SpamAssassin::HTML;

plan tests => 24;

sub try {
  my ($data, $want) = @_;

  my $rgb = Mail::SpamAssassin::HTML::name_to_rgb($data);
  if ($want ne $rgb) {
    print "color mismatch: $data -> $rgb but wanted $want\n";
    return 0;
  }
  return 1;
}

# normal colors with various whitespace
ok(try('black', '#000000'));
ok(try('white', '#ffffff'));
ok(try('peachpuff', '#ffdab9'));
ok(try('#abcdef', '#abcdef'));
ok(try('123456', '#123456'));

# Flex Hex
ok(try('black ', '#b0ac00'));
ok(try(' white ', '#000000'));
ok(try(' peachpuff', '#00c0ff'));
ok(try('#peachpuff', '#0ec00f'));
ok(try('#0f0', '#000f00'));
ok(try('0f0f', '#0f0f00'));
ok(try('#1234567890abcde1234567890abcde', '#34cd89'));
ok(try('6db6ec49efd278cd0bc92d1e5e072d68', '#6ecde0'));
ok(try('#f', '#0f0000'));
ok(try('zft', '#000f00'));
ok(try('#zftygn', '#0f0000'));
ok(try('zqbttv', '#00b000'));
ok(try('fffffff', '#fffff0'));
ok(try('fffff39', '#ffff90'));
ok(try('fffffg', '#fffff0'));
ok(try('fffff', '#fffff0'));
ok(try('fxfefu', '#f0fef0'));
ok(try('fafufb', '#faf0fb'));
ok(try('fofcff', '#f0fcff'));
