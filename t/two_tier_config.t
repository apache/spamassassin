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
use SATest; sa_t_init("two_tier_config");
use Test; BEGIN { plan tests => 10 };

use strict;
require Mail::SpamAssassin;

# ---------------------------------------------------------------------------

my $sa = create_saobj({'dont_copy_prefs' => 1, post_config_text => q{

          required_score 7
          rewrite_header Subject  FOO
          add_header spam Foo Hello

}}); $sa->init(0);

ok ($sa->{conf}->{required_score}, 7);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "FOO");
ok ($sa->{conf}->{headers_spam}->{Foo}, "Hello");

# ---------------------------------------------------------------------------

$sa->{conf}->push_tier();
open OUT, ">log/localrules.tmp/tier1.cf" or die; print OUT q{

          required_score 8
          rewrite_header Subject  BAR
          remove_header spam Foo

}; close OUT or die;
$sa->read_scoreonly_config("log/localrules.tmp/tier1.cf");

ok ($sa->{conf}->{required_score}, 8);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "BAR");
ok ($sa->{conf}->{headers_spam}->{Foo}, undef);

# ---------------------------------------------------------------------------

$sa->{conf}->pop_tier();
ok ($sa->{conf}->{required_score}, 7);
ok ($sa->{conf}->{rewrite_header}->{Subject}, "FOO");
ok ($sa->{conf}->{headers_spam}->{Foo}, "Hello");

# ---------------------------------------------------------------------------

$sa->finish(); ok 1;
