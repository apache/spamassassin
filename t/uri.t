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

plan tests => 42;

sub try {
  my ($base, $uri, $want) = @_;

  my $target = Mail::SpamAssassin::HTML::target_uri($base, $uri);

  if ($target ne $want) {
    print "URI mismatch: $base and $uri -> $target but wanted $want\n";
    return 0;
  }
  return 1;
}

my $base = 'http://a/b/c/d;p?q';

# tests from RFC 2396 draft
# http://www.gbiv.com/protocols/uri/rev-2002/rfc2396bis.html
ok(try($base, "g:h", "g:h"));
ok(try($base, "g", "http://a/b/c/g"));
ok(try($base, "./g", "http://a/b/c/g"));
ok(try($base, "g/", "http://a/b/c/g/"));
ok(try($base, "/g", "http://a/g"));
ok(try($base, "//g", "http://g"));
ok(try($base, "?y", "http://a/b/c/d;p?y"));
ok(try($base, "g?y", "http://a/b/c/g?y"));
ok(try($base, "#s", "http://a/b/c/d;p?q#s"));
ok(try($base, "g#s", "http://a/b/c/g#s"));
ok(try($base, "g?y#s", "http://a/b/c/g?y#s"));
ok(try($base, ";x", "http://a/b/c/;x"));
ok(try($base, "g;x", "http://a/b/c/g;x"));
ok(try($base, "g;x?y#s", "http://a/b/c/g;x?y#s"));
ok(try($base, ".", "http://a/b/c/"));
ok(try($base, "./", "http://a/b/c/"));
ok(try($base, "..", "http://a/b/"));
ok(try($base, "../", "http://a/b/"));
ok(try($base, "../g", "http://a/b/g"));
ok(try($base, "../..", "http://a/"));
ok(try($base, "../../", "http://a/"));
ok(try($base, "../../g", "http://a/g"));

ok(try($base, "", "http://a/b/c/d;p?q"));
ok(try($base, "../../../g", "http://a/g"));
ok(try($base, "../../../../g", "http://a/g"));
ok(try($base, "/./g", "http://a/g"));
ok(try($base, "/../g", "http://a/g"));
ok(try($base, "g.", "http://a/b/c/g."));
ok(try($base, ".g", "http://a/b/c/.g"));
ok(try($base, "g..", "http://a/b/c/g.."));
ok(try($base, "..g", "http://a/b/c/..g"));
ok(try($base, "./../g", "http://a/b/g"));
ok(try($base, "./g/.", "http://a/b/c/g/"));
ok(try($base, "g/./h", "http://a/b/c/g/h"));
ok(try($base, "g/../h", "http://a/b/c/h"));
ok(try($base, "g;x=1/./y", "http://a/b/c/g;x=1/y"));
ok(try($base, "g;x=1/../y", "http://a/b/c/y"));
ok(try($base, "g?y/./x", "http://a/b/c/g?y/./x"));
ok(try($base, "g?y/../x", "http://a/b/c/g?y/../x"));
ok(try($base, "g#s/./x", "http://a/b/c/g#s/./x"));
ok(try($base, "g#s/../x", "http://a/b/c/g#s/../x"));
ok(try($base, "http:g", "http://a/b/c/g"));
