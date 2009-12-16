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
use SATest; sa_t_init("timeout");
use Test; BEGIN { plan tests => 27 };

use strict;
use Time::HiRes qw(time sleep);

require Mail::SpamAssassin::Timeout;
# require Mail::SpamAssassin::Logger;
# Mail::SpamAssassin::Logger::add_facilities('all');

# attempt to circumvent an advice not to mix alarm() with sleep();
# interaction between alarms and sleeps is unspecified
#
sub mysleep($) {
  my($dt) = @_;
  sleep(0.1) for 1..int(10*$dt);
}

my($r,$t,$t1,$t2);

$t = Mail::SpamAssassin::Timeout->new;
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ });
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new;
$r = $t->run_and_catch(sub { mysleep 1; die "run_and_catch test1\n" });
ok(!$t->timed_out && $r =~ /^run_and_catch test1/);

my $caught = 0;
$t = Mail::SpamAssassin::Timeout->new;
eval {
  $r = $t->run(sub { mysleep 1; die "run_and_catch test2\n" }); 1;
} or do {
  $caught = 1  if $@ =~ /run_and_catch test2/;
};
ok(!$t->timed_out && $caught);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$r = $t->run(sub { mysleep 3; 42 });
ok($t->timed_out && !defined $r);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ deadline => time+2 });
$r = $t->run(sub { mysleep 3; 42 });
ok($t->timed_out && !defined $r);

$t = Mail::SpamAssassin::Timeout->new({ deadline => time+2 });
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2, deadline => time+5 });
$r = $t->run(sub { mysleep 3; 42 });
ok($t->timed_out && !defined $r);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2, deadline => time+5 });
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ secs => 9, deadline => time+2 });
$r = $t->run(sub { mysleep 3; 42 });
ok($t->timed_out && !defined $r);

$t = Mail::SpamAssassin::Timeout->new({ secs => 9, deadline => time+2 });
$r = $t->run(sub { mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$r = $t->run(sub { alarm 0; mysleep 1; $t->reset; mysleep 2; 42 });
ok($t->timed_out && !defined $r);

$t = Mail::SpamAssassin::Timeout->new({ secs => 3 });
$r = $t->run(sub { alarm 0; mysleep 1; $t->reset; mysleep 1; 42 });
ok(!$t->timed_out && $r == 42);

$t = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$r = $t->run(sub { alarm 0; mysleep 3; $t->reset; 42 });
ok($t->timed_out && !defined $r);

$t1 = Mail::SpamAssassin::Timeout->new({ secs => 1 });
$t2 = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$r = $t1->run(sub { $t2->run(sub { mysleep 3; 43 }); 42 });
ok($t1->timed_out);
ok(!$t2->timed_out);
ok(!defined $r);

$t1 = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$t2 = Mail::SpamAssassin::Timeout->new({ secs => 1 });
$r = $t1->run(sub { $t2->run(sub { mysleep 3; 43 }); 42 });
ok(!$t1->timed_out);
ok($t2->timed_out);
ok($r == 42);

$t1 = Mail::SpamAssassin::Timeout->new({ secs => 2 });
$t2 = Mail::SpamAssassin::Timeout->new({ secs => 1 });
$r = $t1->run(sub { $t2->run(sub { mysleep 3; 43 }); mysleep 3; 42 });
ok($t1->timed_out);
ok($t2->timed_out);
ok(!defined $r);

$t1 = Mail::SpamAssassin::Timeout->new({ secs => 1 });
$t2 = Mail::SpamAssassin::Timeout->new({ secs => 1 });
$r = $t1->run(sub { $t2->run(sub { mysleep 3; 43 }); mysleep 3; 42 });
ok($t1->timed_out);
ok($t2->timed_out);
ok(!defined $r);

# my $when = int(time + 1.5);
# $t1 = Mail::SpamAssassin::Timeout->new({ deadline => $when });
# $t2 = Mail::SpamAssassin::Timeout->new({ deadline => $when });
# $r = $t1->run(sub { $t2->run(sub { mysleep 4; 43 }); 42 });
# ok($t1->timed_out);
# ok($t2->timed_out);
# ok(!defined $r);

1;
