#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("reportheader");
use Test; BEGIN { plan tests => 33 };

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Report: Detailed Report
SPAM: -------------------- Start SpamAssassin results ----------------------
SPAM: This mail is probably spam.  The original message has been altered
SPAM: so you can recognise or block similar unwanted mail in future.
SPAM: See http://spamassassin.org/tag/ for more details.  },
	'x-spam-report-header',

q{ Subject: *****SPAM***** There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ Valid-looking To "undisclosed-recipients"}, 'undisc',
q{ Missing Date: header}, 'date',
q{ Subject has an exclamation mark}, 'apling',
q{ From: ends in numbers}, 'endsinnums',
q{ From: does not include a real name}, 'noreal',
q{ BODY: List removal information }, 'removesubject',
q{ BODY: Claims you can be removed from the list}, 'toberemoved',
q{ Says: "to be removed, reply via email" }, 'removesubj',
q{ BODY: Nobody's perfect }, 'remove',
q{ Message-Id is not valid, according to RFC-2822 }, 'msgidnotvalid',
q{ Message-Id has no @ sign }, 'msgidnoat',
q{ BODY: Uses a dotted-decimal IP address in URL }, 'dotteddec',

); #'

tstprefs ("
	report_header 1
	");

ok (sarun ("-t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();
