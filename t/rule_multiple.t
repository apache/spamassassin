#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("rule_multiple");
use Test::More tests => 42;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 META_BODY_RULE }, '',
  q{ 1.0 META_BODY_RULE_MAX }, '',
  q{ 1.0 META_EVAL_RULE }, '',
  q{ 1.0 META_FULL_RULE }, '',
  q{ 1.0 META_FULL_RULE_MAX }, '',
  q{ 1.0 META_HEADER_RULE }, '',
  q{ 1.0 META_HEADER_RULE_MAX }, '',
  q{ 1.0 META_META_RULE }, '',
  q{ 1.0 META_RAWBODY_RULE }, '',
  q{ 1.0 META_RAWBODY_RULE_MAX }, '',
  q{ 1.0 META_RULE_6 }, '',
  q{ 1.0 META_URI_RULE }, '',
  q{ 1.0 META_URI_RULE_MAX }, '',
);

%anti_patterns = (
  q{ META_BODY_RULE_2 }, '',
  q{ META_BODY_RULE_MAX_2 }, '',
  q{ META_FULL_RULE_2 }, '',
  q{ META_FULL_RULE_MAX_2 }, '',
  q{ META_HEADER_RULE_2 }, '',
  q{ META_HEADER_RULE_MAX_2 }, '',
  q{ META_RAWBODY_RULE_MAX_2 }, '',
  q{ META_URI_RULE_MAX_2 }, '',
);

tstlocalrules ('
  header HEADER_RULE	Subject =~ /--/
  tflags HEADER_RULE multiple
  meta META_HEADER_RULE HEADER_RULE > 1

  header HEADER_RULE_2	Subject =~ /--/
  meta META_HEADER_RULE_2 HEADER_RULE_2 > 1

  body BODY_RULE	/WWW.SUPERSITESCENTRAL.COM/i
  tflags BODY_RULE	multiple
  meta META_BODY_RULE BODY_RULE == 3

  body BODY_RULE_2	/WWW.SUPERSITESCENTRAL.COM/i
  meta META_BODY_RULE_2 BODY_RULE_2 > 2

  rawbody RAWBODY_RULE	/WWW.SUPERSITESCENTRAL.COM/i
  tflags RAWBODY_RULE	multiple
  meta META_RAWBODY_RULE RAWBODY_RULE == 3

  full FULL_RULE	/WWW.SUPERSITESCENTRAL.COM/i
  tflags FULL_RULE	multiple
  meta META_FULL_RULE FULL_RULE == 3

  full FULL_RULE_2	/WWW.SUPERSITESCENTRAL.COM/i
  meta META_FULL_RULE_2 FULL_RULE_2 > 2

  header HEADER_RULE_MAX	Subject =~ /--/
  tflags HEADER_RULE_MAX multiple maxhits=2
  meta META_HEADER_RULE_MAX HEADER_RULE_MAX > 1

  header HEADER_RULE_MAX_2	Subject =~ /--/
  tflags HEADER_RULE_MAX_2 multiple maxhits=1
  meta META_HEADER_RULE_MAX_2 HEADER_RULE_MAX_2 > 1

  body BODY_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
  tflags BODY_RULE_MAX	multiple maxhits=3
  meta META_BODY_RULE_MAX BODY_RULE_MAX == 3

  body BODY_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
  tflags BODY_RULE_MAX_2	multiple maxhits=2
  meta META_BODY_RULE_MAX_2 BODY_RULE_MAX_2 > 2

  rawbody RAWBODY_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
  tflags RAWBODY_RULE_MAX	multiple maxhits=3
  meta META_RAWBODY_RULE_MAX RAWBODY_RULE_MAX == 3

  rawbody RAWBODY_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
  tflags RAWBODY_RULE_MAX_2	multiple maxhits=2
  meta META_RAWBODY_RULE_MAX_2 RAWBODY_RULE_MAX_2 > 2

  full FULL_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
  tflags FULL_RULE_MAX	multiple maxhits=3
  meta META_FULL_RULE_MAX FULL_RULE_MAX == 3

  full FULL_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
  tflags FULL_RULE_MAX_2	multiple maxhits=2
  meta META_FULL_RULE_MAX_2 FULL_RULE_MAX_2 > 2

  # Note that this is supposed to hit 2 times -> 2 unique urls
  uri URI_RULE		/WWW.SUPERSITESCENTRAL.COM/i
  tflags URI_RULE	multiple
  meta META_URI_RULE URI_RULE == 2

  uri URI_RULE_MAX	/WWW.SUPERSITESCENTRAL.COM/i
  tflags URI_RULE_MAX	multiple maxhits=1
  meta META_URI_RULE_MAX URI_RULE_MAX == 1

  uri URI_RULE_MAX_2	/WWW.SUPERSITESCENTRAL.COM/i
  tflags URI_RULE_MAX_2	multiple maxhits=1
  meta META_URI_RULE_MAX_2 URI_RULE_MAX_2 > 1

  meta META_RULE	META_BODY_RULE + META_RAWBODY_RULE
  meta META_META_RULE	META_RULE == 2

  meta META_RULE_6	BODY_RULE + RAWBODY_RULE == 6

  loadplugin myTestPlugin ../../../data/testplugin.pm
  header EVAL_RULE	eval:check_return_2()
  meta META_EVAL_RULE	EVAL_RULE > 1
');

sarun ("-L -t < data/spam/002 2>&1", \&patterns_run_cb);
ok_all_patterns();

# do some tests without any other rules to check meta bugs
clear_localrules();
sarun ("-L -t < data/spam/002 2>&1", \&patterns_run_cb);
ok_all_patterns();

