#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("reportheader");
use Test; BEGIN { plan tests => 12 };

$ENV{'LC_ALL'} = 'C';             # a cheat, but we need the patterns to work

# ---------------------------------------------------------------------------

%patterns = (

q{ Spam detection software, running on the system "}, 'spam-report-body',
q{ Subject: There yours for FREE!}, 'subj',
q{ X-Spam-Status: Yes, hits=}, 'status',
q{ X-Spam-Flag: YES}, 'flag',
q{ From: ends in numbers}, 'endsinnums',
q{ From: does not include a real name}, 'noreal',
q{ BODY: List removal information }, 'removesubject',
q{ BODY: Nobody's perfect }, 'remove',
q{ Message-Id is not valid, }, 'msgidnotvalid',
q{ 'From' yahoo.com does not match }, 'fromyahoo',
q{ Invalid Date: header (not RFC 2822) }, 'invdate',
q{ Uses a dotted-decimal IP address in URL }, 'dotteddec',

); #'

tstprefs ("
        $default_cf_lines
        use_terse_report 0
	");

sarun ("-L -t < data/spam/001", \&patterns_run_cb);
ok_all_patterns();
