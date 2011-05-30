#!/usr/bin/perl -w

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/body_mod.t", kluge around ...
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
use SATest; sa_t_init("body_mod");
use Test; BEGIN { plan tests => 3 };

use Mail::SpamAssassin;

# ---------------------------------------------------------------------------

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

$sa->init(0); # parse rules

open (IN, "<data/spam/006");
my $mail = $sa->parse(\*IN);
close IN;
my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

my $decoded_pre = join ('||', @{$msg->get_decoded_body_text_array()});
my $stripped_pre = join ('||', @{$msg->get_decoded_stripped_body_text_array()});

$msg->check();

my $decoded_post = join ('||', @{$msg->get_decoded_body_text_array()});
my $stripped_post = join ('||', @{$msg->get_decoded_stripped_body_text_array()});

my $hits = join (' ', $msg->get_names_of_tests_hit());
print "hit rules: $hits\n";
ok ($hits ne '');

if ($decoded_pre eq $decoded_post) {
  print "decoded: body renderings identical pre and post scan\n";
  ok (1);
} else {
  print "decoded: body renderings DIFFER pre and post scan\n";
  print "decoded: pre=".$decoded_pre." post=".$decoded_post."\n\n";
  ok (0);
}

if ($stripped_pre eq $stripped_post) {
  print "stripped: body renderings identical pre and post scan\n";
  ok (1);
} else {
  print "stripped: body renderings DIFFER pre and post scan\n";
  print "stripped: pre=".$stripped_pre." post=".$stripped_post."\n\n";
  ok (0);
}
