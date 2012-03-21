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

plan tests => 28;

sub try {
  my ($data, $want) = @_;

  my $rgb = Mail::SpamAssassin::HTML::name_to_rgb($data);
  if ($want ne $rgb) {
    print "color mismatch: $data -> $rgb but wanted $want\n";
    return 0;
  }
  return 1;
}

#Tests were based on Flex Hex: John Graham-Cumming, http://www.jgc.org/pdf/lisa2004.pdf until 2012-03-08
# SEE BUG 6760

ok(try('black', '#000000'));
ok(try('white', '#ffffff'));
ok(try('peachpuff', '#ffdab9'));
ok(try('#abcdef', '#abcdef'));
ok(try('123456', 'invalid'));
ok(try(' peachpuff', '#ffdab9'));
ok(try('#peachpuff', 'invalid'));
ok(try('#0f0', '#00ff00'));
ok(try('0f0f', 'invalid'));
ok(try('#1234567890abcde1234567890abcde', '#123456'));
ok(try('6db6ec49efd278cd0bc92d1e5e072d68', 'invalid'));
ok(try('#f', '#ff0000')); 
ok(try('zft', 'invalid'));
ok(try('#789', '#778899'));
ok(try('#zftygn', 'invalid'));
ok(try('zqbttv', 'invalid'));
ok(try('fffffff', 'invalid'));
ok(try('fffff39', 'invalid'));
ok(try('fffffg', 'invalid'));
ok(try('fffff', 'invalid'));
ok(try('fxfefu', 'invalid'));
ok(try('fafufb', 'invalid'));
ok(try('fofcff', 'invalid'));
ok(try('#black', 'invalid'));
ok(try('rgb(100%,100%,100%)', '#ffffff'));
ok(try('rgb(100,100,100)', '#646464'));
ok(try('rgb(33%,33%,33%)', '#545454'));
ok(try('rgb(255,100,100)', '#ff6464'));
