#!/usr/bin/perl -w

use lib '.'; use lib 't';
use SATest; sa_t_init("spam");
use Test; BEGIN { plan tests => 27 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: *****SPAM***** There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ To "Undisclosed.Recipients" or similar}, 'undisc',
q{ Invalid Date: header}, 'date',
q{ Subject has lots of exclamation marks}, 'lotsaplings',
q{ From: ends in numbers}, 'endsinnums',
q{ From: does not include a real name}, 'noreal',
q{ Message-Id has no @ sign}, 'noat',
q{ BODY: /reply.*remove.*subject/i}, 'replyremovesubject',
q{ BODY: /To Be Removed,? Please/i}, 'toberemoved',
q{ BODY: /remove.*subject/i}, 'removesubj',
q{ BODY: /\"remove\"/i}, 'remove',


);

ok (sarun ("-t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
