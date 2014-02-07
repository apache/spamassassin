#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("util_wrap");
use Test; BEGIN { plan tests => 5 };


use strict;
require Mail::SpamAssassin::Util;

my @data = (

# ---------------------------------------------------------------------------
# basic short line

  q{
  code:
    $out = Mail::SpamAssassin::Util::wrap($in, "\t", "", 79, 0, '(?<=[\s,])');
  
    Foo Bar Baz

  }, q{
    
    Foo Bar Baz

  },

# ---------------------------------------------------------------------------
# basic long line

  q{
  code:
    $out = Mail::SpamAssassin::Util::wrap($in, "\t", "", 79, 0, '(?<=[\s,])');
    
    X-Spam-Checker-Version!!SpamAssassin 3.2.0-r492202 (2007-01-03) on radish.jmason.org

  }, q{
    
    X-Spam-Checker-Version!!SpamAssassin 3.2.0-r492202 (2007-01-03) on\n\tradish.jmason.org

  },

# ---------------------------------------------------------------------------
# basic line with very long "word", overflow=1

  q{
  code:
    $out = Mail::SpamAssassin::Util::wrap($in, "\t", "", 79, 1, '(?<=[\s,])');
    
    id=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca

  }, q{
    
    id=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca

  },

# ---------------------------------------------------------------------------
# basic line with very long "word", overflow=0

  q{
  code:
    $out = Mail::SpamAssassin::Util::wrap($in, "\t", "", 79, 0, '(?<=[\s,])');
    
    id=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca

  }, q{
    
    id=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca

  },

# ---------------------------------------------------------------------------
# bug 5272

  q{
  code:
    $out = Mail::SpamAssassin::Util::wrap($in, "\t", "", 79, 0, '(?<=[\s,])');
    
    X-Spam-Relays-External!![ ip=209.226.175.110 rdns=tomts43-srv.bellnexxia.net helo=tomts43-srv.bellnexxia.net by=dogma.boxhost.net ident= envfrom= intl=0 id=0A3C83100DF auth= ] [ ip=70.51.181.195 rdns= helo=bas1-montreal45-1177793987.dsl.bell.ca by=tomts43-srv.bellnexxia.net ident= envfrom= intl=0 id=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca auth= ]

  }, q{
    
    X-Spam-Relays-External!![ ip=209.226.175.110 rdns=tomts43-srv.bellnexxia.net\n\thelo=tomts43-srv.bellnexxia.net by=dogma.boxhost.net ident= envfrom= intl=0\n\tid=0A3C83100DF auth= ] [ ip=70.51.181.195 rdns=\n\thelo=bas1-montreal45-1177793987.dsl.bell.ca by=tomts43-srv.bellnexxia.net\n\tident= envfrom= intl=0\n\tid=20070103201045.LPQE11361.tomts43-srv.bellnexxia.net@bas1-montreal45-1177793987.dsl.bell.ca\n\tauth= ]

  },

# ---------------------------------------------------------------------------

);


while (1) {
  my $in = shift @data;
  my $expected = shift @data;
  last unless defined $expected;

  my $test_failure = 0;

  my $code = '';
  if ($in =~ s/^\s+code:\s+([^\n]+)\s+//gs) {
    $code = $1;
  }
  else {
    die "no code found in '$in'";
  }

  $in =~ s/^\s+//gs; $in =~ s/\s+$//gs;
  $expected =~ s/^\s+//gs; $expected =~ s/\s+$//gs;

  my $out;
  eval $code;
  $out =~ s/\n/\\n/gs;      # make it readable
  $out =~ s/\t/\\t/gs;

  if (!ok ($out eq $expected)) {
    print "code    : $code\n";
    print "input   : $in\n";
    print "expected: $expected\n";
    print "got     : $out\n\n";

    # die "dying on first test failure";
  }
}

