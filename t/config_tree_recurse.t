#!/usr/bin/perl -T
#
# Test that config_tree_recurse works ok in taint mode; bug 6019

delete @ENV{'PATH', 'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};
$ENV{PATH}='/bin:/usr/bin:/usr/local/bin';

use lib '.'; use lib 't';
use SATest; sa_t_init("config_tree_recurse.t");
use Test::More tests => 4;

# ---------------------------------------------------------------------------

use strict;
require Mail::SpamAssassin;

my $sa = create_saobj({'dont_copy_prefs' => 1, 'config_tree_recurse' => 1});
$sa->init(0); # parse rules
ok($sa);

open (IN, "<data/spam/009");
my $mail = $sa->parse(\*IN);
close IN;

my $status = $sa->check($mail);
my $rewritten = $status->rewrite_mail();
my $msg = $status->{msg};

ok $rewritten =~ /message\/rfc822; x-spam-type=original/;
ok $rewritten =~ /X-Spam-Flag: YES/;

$mail->finish();
$status->finish();
ok 1;
