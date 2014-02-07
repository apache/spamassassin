#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("rule_multiple");
use Test; BEGIN { plan tests => 20 };

# ---------------------------------------------------------------------------

%patterns = (

q{ META_HEADER_RULE }, 'header',
q{ META_URI_RULE }, 'uri',
q{ META_BODY_RULE }, 'body',
q{ META_RAWBODY_RULE }, 'rawbody',
q{ META_FULL_RULE }, 'full',
q{ META_META_RULE }, 'meta',
q{ META_EVAL_RULE }, 'eval',

q{ META_HEADER_RULE_MAX }, 'header_max',
q{ META_URI_RULE_MAX }, 'uri_max',
q{ META_BODY_RULE_MAX }, 'body_max',
q{ META_RAWBODY_RULE_MAX }, 'rawbody_max',
q{ META_FULL_RULE_MAX }, 'full_max',

);

%anti_patterns = (

q{ META_HEADER_RULE_2 }, 'header_2',
q{ META_BODY_RULE_2 }, 'body_2',
q{ META_FULL_RULE_2 }, 'full_2',

q{ META_HEADER_RULE_MAX_2 }, 'header_max_2',
q{ META_URI_RULE_MAX_2 }, 'uri_max_2',
q{ META_BODY_RULE_MAX_2 }, 'body_max_2',
q{ META_RAWBODY_RULE_MAX_2 }, 'rawbody_max_2',
q{ META_FULL_RULE_MAX_2 }, 'full_max_2',

);

tstlocalrules ('

header HEADER_RULE	Subject =~ /--/
tflags HEADER_RULE multiple
meta META_HEADER_RULE HEADER_RULE > 1

header HEADER_RULE_2	Subject =~ /--/
meta META_HEADER_RULE_2 HEADER_RULE_2 > 1

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

header HEADER_RULE_MAX	Subject =~ /--/
tflags HEADER_RULE_MAX multiple maxhits=2
meta META_HEADER_RULE_MAX HEADER_RULE_MAX > 1

header HEADER_RULE_MAX_2	Subject =~ /--/
tflags HEADER_RULE_MAX_2 multiple maxhits=1
meta META_HEADER_RULE_MAX_2 HEADER_RULE_MAX_2 > 1

uri URI_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
tflags URI_RULE_MAX	multiple maxhits=2
meta META_URI_RULE_MAX URI_RULE_MAX > 1

uri URI_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
tflags URI_RULE_MAX_2	multiple maxhits=1
meta META_URI_RULE_MAX_2 URI_RULE_MAX_2 > 1

body BODY_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
tflags BODY_RULE_MAX	multiple maxhits=3
meta META_BODY_RULE_MAX BODY_RULE_MAX > 2

body BODY_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
tflags BODY_RULE_MAX_2	multiple maxhits=2
meta META_BODY_RULE_MAX_2 BODY_RULE_MAX_2 > 2

rawbody RAWBODY_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
tflags RAWBODY_RULE_MAX	multiple maxhits=3
meta META_RAWBODY_RULE_MAX RAWBODY_RULE_MAX > 2

rawbody RAWBODY_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
tflags RAWBODY_RULE_MAX_2	multiple maxhits=2
meta META_RAWBODY_RULE_MAX_2 RAWBODY_RULE_MAX_2 > 2

full FULL_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
tflags FULL_RULE_MAX	multiple maxhits=3
meta META_FULL_RULE_MAX FULL_RULE_MAX > 2

full FULL_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
tflags FULL_RULE_MAX_2	multiple maxhits=2
meta META_FULL_RULE_MAX_2 FULL_RULE_MAX_2 > 2


meta META_RULE		META_BODY_RULE + META_RAWBODY_RULE
meta META_META_RULE	META_RULE > 1

loadplugin myTestPlugin ../../data/testplugin.pm
header EVAL_RULE	eval:check_return_2()
meta META_EVAL_RULE	EVAL_RULE > 1
    ');

sarun ("-L -t < data/spam/002", \&patterns_run_cb);
ok_all_patterns();
