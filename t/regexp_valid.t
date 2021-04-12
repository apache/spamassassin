#!/usr/bin/perl -w -T
# test regexp validation

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("regexp_valid");
use Mail::SpamAssassin::Util qw(compile_regexp);

use Test::More tests => 39;

my $showerr;
sub tryone {
  my ($re, $strip) = @_;
  $strip = 1 if !defined $strip;
  my ($rec, $err) = compile_regexp($re, $strip, 1);
  if (!$rec && $showerr) { print STDERR "invalid regex '$re': $err\n"; }
  return $rec;
}

# test valid regexps with this sub
sub goodone {
  my ($re, $strip) = @_;
  $showerr = 1;
  return tryone($re, $strip);
}

# test invalid regexps with this sub
sub badone {
  my ($re, $strip) = @_;
  $showerr = 0;
  return !tryone($re, $strip);
}


ok goodone 'qr/foo bar/';
ok goodone 'qr/foo bar/im';
ok goodone 'qr!foo bar!';
ok goodone 'qr!foo bar!im';
ok goodone '/^foo bar$/';

ok goodone '/foo bar/';
ok goodone '/foo bar/im';
ok goodone 'm!foo bar!is';
ok goodone 'm{foo bar}is';
ok goodone 'm(foo bar)is';

ok goodone 'm<foo bar>is';
ok goodone 'foo bar', 0;
ok goodone 'foo/bar', 0;
ok badone 'foo(bar', 0;

ok badone 'foo(?{1})bar';
ok badone 'foo(??{1})bar';
ok badone '/foo(?{1})bar/';
ok badone '/foo(??{1})bar/';
ok badone 'm!foo(?{1})bar!';

ok goodone '/test\//';
ok badone '/test//';  # removed for bug 4700 - and back from 7648
ok badone 'm!test!xyz!i';
ok badone '//';
ok badone 'm!|foo!';
ok goodone 'm!\|foo!';
ok badone 'm{bar||y}';

ok goodone 'm{test}}'; # it's actually bad, but no way to parse this with simple code
ok goodone 'm}test}}'; # it's actually bad, but no way to parse this with simple code
# left brace test depends on perl version, don't bother
#ok goodone 'm{test{}'; # it's good even though perl warns unescaped { is deprecated
#ok goodone 'm}test{}';
ok goodone 'm{test.{0,10}}';
ok goodone 'm}test.{0,10}}';
ok goodone 'm[foo[bar]]';
ok badone 'm[foo[bar\]]';
ok goodone 'm(foo(?:bar)x)';
ok badone 'm(foo\(?:bar)x)';
ok goodone 'm/test # comment/x';
ok badone 'm/test # comm/ent/x'; # well you shouldn't use comments anyway
ok goodone 'm[test # \] foo []x';

ok goodone '.*', 0;
ok goodone 'm*<a[^<]{0,60} onMouseMove=(?:3D)?"window.status=(?:3D)?\'https?://*';

