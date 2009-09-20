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

use lib '.'; use lib 't';
use SATest; sa_t_init("stop_always_matching_regexps");
use Test; BEGIN { plan tests => 13 };

# ---------------------------------------------------------------------------

use strict;
require Mail::SpamAssassin;

my $sa = create_saobj({'dont_copy_prefs' => 1});
$sa->init(0);
ok($sa);

sub is_caught {
  my ($re) = @_;
  return $sa->{conf}->{parser}->is_always_matching_regexp($re, $re);
}

ok !is_caught 'foo|bar';
ok is_caught 'foo||bar';
ok is_caught '|bar';
ok is_caught 'foo|';
ok !is_caught 'foo\||bar';
ok !is_caught '\||bar';

ok !is_caught '(foo|bar)baz';
ok is_caught '(foo||bar)baz';
ok !is_caught '(|bar)baz';
ok !is_caught '(foo|)baz';
ok !is_caught '(foo\||bar)baz';
ok !is_caught '(\||bar)baz';

# ok is_caught '(\s*) +';

