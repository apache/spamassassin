#!/usr/bin/perl -w
# test regexp validation

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
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
use SATest; sa_t_init("regexp_valid");
use Test;

# settings
plan tests => 25;

# initialize SpamAssassin
use Mail::SpamAssassin;
my $sa = create_saobj({'dont_copy_prefs' => 1});
$sa->init(0); # parse rules


sub tryone {
  my $re = shift;
  return $sa->{conf}->{parser}->is_regexp_valid('test', $re);
}

ok tryone qr/foo bar/;
ok tryone qr/foo bar/i;
ok tryone qr/foo bar/is;
ok tryone qr/foo bar/im;
ok tryone qr!foo bar!im;
ok tryone 'qr/foo bar/';
ok tryone 'qr/foo bar/im';
ok tryone 'qr!foo bar!';
ok tryone 'qr!foo bar!im';
ok tryone '/^foo bar$/';
ok tryone '/foo bar/';
ok tryone '/foo bar/im';
ok tryone 'm!foo bar!is';
ok tryone 'm{foo bar}is';
ok tryone 'm(foo bar)is';
ok tryone 'm<foo bar>is';
ok tryone 'foo bar';
ok tryone 'foo/bar';
ok !tryone 'foo(bar';
ok !tryone 'foo(?{1})bar';
ok !tryone '/foo(?{1})bar/';
ok !tryone 'm!foo(?{1})bar!';

ok !tryone '/test//';
ok tryone '.*';

ok tryone 'm*<a[^<]{0,60} onMouseMove=(?:3D)?"window.status=(?:3D)?\'https?://*';

