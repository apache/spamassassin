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

use Digest::SHA1;

plan tests => 15;

sub try {
  my ($data, $want) = @_;

  if ($want ne Digest::SHA1::sha1_hex($data)) {
    print "Digest::SHA1 mismatch\n";
    return 0;
  }
  return 1;
}

sub string {
  my ($seed, $length) = @_;

  my $string;
  while ($length--) {
    $seed = (736 * $seed + 364) % 33843;
    $string .= chr($seed % 256);
  }
  return $string;
}

my $habeas = <<END;
X-Habeas-SWE-1: winter into spring
X-Habeas-SWE-2: brightly anticipated
X-Habeas-SWE-3: like Habeas SWE (tm)
X-Habeas-SWE-4: Copyright 2002 Habeas (tm)
X-Habeas-SWE-5: Sender Warranted Email (SWE) (tm). The sender of this
X-Habeas-SWE-6: email in exchange for a license for this Habeas
X-Habeas-SWE-7: warrant mark warrants that this is a Habeas Compliant
X-Habeas-SWE-8: Message (HCM) and not spam. Please report use of this
X-Habeas-SWE-9: mark in spam to <http://www.habeas.com/report/>.
END

$habeas =~ tr/A-Z/a-z/;
$habeas =~ tr/ / /s;
$habeas =~ s/\/?>/\/>/;

# fixed strings
ok(try("squeamish ossifrage\n", "820550664cf296792b38d1647a4d8c0e1966af57"));
ok(try("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"));
ok(try("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "84983e441c3bd26ebaae4aa1f95129e5e54670f1"));

# garbled strings
ok(try(string(287, 1), "909f99a779adb66a76fc53ab56c7dd1caf35d0fd"));
ok(try(string(648, 16), "44793ba2b430507c5be08165e5b003977e31d0b2"));
ok(try(string(628, 76), "5ed4ded95f3104734f438db4426ac2e2941b389f"));
ok(try(string(93, 348), "a4f33e402a7c689fb3899e5ff3608a4e4ff59347"));
ok(try(string(236, 2163), "bdbe8891a6b2fbb47ee419325877b513ee897fe0"));
ok(try(string(975, 687), "80c20a5fe4065d6877cdb75de27a4ce06d5cb8ed"));
ok(try(string(826, 4280), "fd4ed5f43e128f7a12346dd194e7f5bb77ae8d2f"));
ok(try(string(584, 24869), "69396239246666faed31d6f5884c7469d915d4d8"));
ok(try(string(367, 51474), "15201559b3ffb278918a2f7a35d2b702a72fb391"));
ok(try(string(504, 64273), "73e56c49eecef44a53048e27baa42e491375eb23"));

# habeas
ok(try($habeas, "42ab3d716380503f66c4d44017c7f37b04458a9a"));

# anti-habeas
$habeas =~ s/0/O/;
ok(!try($habeas, "42ab3d716380503f66c4d44017c7f37b04458a9a"));
