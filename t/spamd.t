#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd");
use Test; BEGIN { plan tests => 12 };

# ---------------------------------------------------------------------------

%patterns = (

q{ Subject: *****SPAM***** There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ X-Spam-Level: **********}, 'stars',
q{ Valid-looking To "undisclosed-recipients"}, 'undisc',
q{ From: ends in numbers}, 'endsinnums',
q{ From: does not include a real name}, 'noreal',
q{ BODY: List removal information }, 'removesubject',
q{ BODY: Claims you can be removed from the list}, 'toberemoved',
q{ Says: "to be removed, reply via email" }, 'removesubj',
q{ BODY: Nobody's perfect }, 'remove',


);

ok (sdrun ("-L", "< data/spam/001", \&patterns_run_cb));
ok_all_patterns();

