#!/usr/bin/perl -w -T

use strict;

use lib '.'; use lib 't';
use SATest; sa_t_init("date");

use Mail::SpamAssassin;
use Mail::SpamAssassin::Util;

use Test::More tests => 14;

sub try {
  my ($data, $want) = @_;

  my $time = Mail::SpamAssassin::Util::parse_rfc822_date($data);
  if (!$time) {
    return 0;
  }
  if ($want && $want ne $time) {
    print "time mismatch: $data -> $time but wanted $want\n";
    return 0;
  }
  return 1;
}

# good dates
ok(try('Mon, 31 Oct 2005 18:44:29 -0800', 1130813069));
ok(try('Wed, 28 Sep 2005 16:24:49 +0800 (CST)',	1127895889));
ok(try('Tue, 25 Apr 2006 02:15:29 -0700', 1145956529));
ok(try('Sun, 8 Jan 2006 13:12:04 +0100', 1136722324));
ok(try('Mon, 8 May 2006 15:49:45 -0700', 1147128585));
ok(try('Sat, 14 Jan 2037 21:03:03 -0000', 2115579783));

# invalid dates
ok(try('Mon, 20 Sep 2004 21:43:60 -0700 (PDT)'));
ok(try('Mon, 20 Sep 2004 23:60:57 -0700 (PDT)'));
ok(try('Mon, 20 Sep 2004 24:43:57 -0700 (PDT)'));
ok(try('Mon, 31 Sep 2004 21:43:57 -0700 (PDT)'));
ok(try('Mon, 32 Dec 2004 21:43:57 -0700 (PDT)'));
ok(try('Mon, 32 Jan 2004 21:43:57 -0700 (PDT)'));
ok(try('Sun, 29 Feb 2006 21:43:57 -0800 (PST)'));
ok(try('Sun, 30 Feb 2006 21:43:57 -0800 (PST)'));
