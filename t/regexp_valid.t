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
plan tests => 24;

# initialize SpamAssassin
use Mail::SpamAssassin;
my $sa = create_saobj({'dont_copy_prefs' => 1});
$sa->init(0); # parse rules


# make a _copy_ of the STDERR file descriptor
# (so we can restore it after redirecting it)
open(OLDERR, ">&STDERR") || die "Cannot copy STDERR file handle";

# create a file descriptior for logging STDERR
# (we do not want warnings for regexps we know are invalid)
my $fh = IO::File->new_tmpfile();
open(LOGERR, ">&".fileno($fh)) || die "Cannot create LOGERR temp file";

# quiet "used only once" warnings
1 if *OLDERR;
1 if *LOGERR;


sub tryone {
  my $re = shift;
  return $sa->{conf}->{parser}->is_regexp_valid('test', $re);
}

# test valid regexps with this sub
sub goodone {
  my $re = shift;
  open(STDERR, ">&=OLDERR") || die "Cannot reopen STDERR";
  return tryone $re;
}

# test invalid regexps with this sub
sub badone {
  my $re = shift;
  open(STDERR, ">&=LOGERR") || die "Cannot reopen STDERR (for logging)";
  return !tryone $re;
}


ok goodone qr/foo bar/;
ok goodone qr/foo bar/i;
ok goodone qr/foo bar/is;
ok goodone qr/foo bar/im;
ok goodone qr!foo bar!im;

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
ok goodone 'foo bar';
ok goodone 'foo/bar';
ok badone 'foo(bar';
ok badone 'foo(?{1})bar';

ok badone '/foo(?{1})bar/';
ok badone 'm!foo(?{1})bar!';
# ok badone '/test//';          # removed for bug 4700
ok goodone '.*';
ok goodone 'm*<a[^<]{0,60} onMouseMove=(?:3D)?"window.status=(?:3D)?\'https?://*';

