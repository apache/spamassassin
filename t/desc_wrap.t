#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("desc_wrap");
use Test; BEGIN { plan tests => 10 };

# ---------------------------------------------------------------------------

%patterns = (

q{ THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP }, 'rulehit',

q{ 1.0 THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP A very very long },
'report',

);

tstprefs ("
        $default_cf_lines

        report_safe 1
        header THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP Subject =~ /FREE/

        describe THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP A very very long rule name and this is a very very long description lorem ipsum etc. blah blah blah blah This mailing is done by an independent marketing co. We apologize if this message has reached you in error. Save the Planet, Save the Trees! Advertise via E mail. No wasted paper! Delete with one simple keystroke!

");

ok (sarun ("-L -t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok ($matched_output =~ /^                            name and this/m);
ok ($matched_output =~ /^                            with one simple/m);


tstprefs ("
        $default_cf_lines

        report_safe 0
        header THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP Subject =~ /FREE/

        describe THIS_IS_A_VERY_LONG_RULE_NAME_WHICH_NEEDS_WRAP A very very long rule name and this is a very very long description lorem ipsum etc. blah blah blah blah This mailing is done by an independent marketing co. We apologize if this message has reached you in error. Save the Planet, Save the Trees! Advertise via E mail. No wasted paper! Delete with one simple keystroke!

");

ok (sarun ("-L -t < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok ($matched_output =~ /^\s+\*      rule name and this is a very /m);
ok ($matched_output =~ /^\s+\*      wasted paper! Delete with one /m);


