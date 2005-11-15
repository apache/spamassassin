#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("rule_multiple");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = (

q{ META_URI_RULE }, 'uri',
q{ META_BODY_RULE }, 'body',
q{ META_RAWBODY_RULE }, 'rawbody',
q{ META_FULL_RULE }, 'full',

);

%anti_patterns = (

q{ META_BODY_RULE_2 }, 'body_2',
q{ META_FULL_RULE_2 }, 'full_2',

);

tstprefs ('

uri URI_RULE		/WWW.SUPERSITESCENTRAL.COM/i
tflags URI_RULE	multiple
meta META_URI_RULE URI_RULE > 1

body BODY_RULE		/WWW.SUPERSITESCENTRAL.COM/i
tflags BODY_RULE	multiple
meta META_BODY_RULE BODY_RULE > 2

rawbody RAWBODY_RULE	/WWW.SUPERSITESCENTRAL.COM/i
tflags RAWBODY_RULE	multiple
meta META_RAWBODY_RULE RAWBODY_RULE > 2

body BODY_RULE_2	/WWW.SUPERSITESCENTRAL.COM/i
meta META_BODY_RULE_2 BODY_RULE_2 > 2

full FULL_RULE		/WWW.SUPERSITESCENTRAL.COM/i
tflags FULL_RULE	multiple
meta META_FULL_RULE FULL_RULE > 2

full FULL_RULE_2		/WWW.SUPERSITESCENTRAL.COM/i
meta META_FULL_RULE_2 FULL_RULE_2 > 2

    ');

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
