#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("header");
use Test::More tests => 23;

# ---------------------------------------------------------------------------

tstprefs('
  # exists
  header TEST_EXISTS1 exists:To
  header TEST_EXISTS2 exists:Not-Exist

  # if-unset
  header TEST_UNSET1 Not-Exist =~ /./
  header TEST_UNSET2 Not-Exist =~ /^UNSET$/ [if-unset: UNSET]
  header TEST_UNSET3 Not-Exist =~ /^NOT$/ [if-unset: UNSET]

  # exists should not leak to a redefined test
  header TEST_LEAK1 exists:Not-Exist
  header TEST_LEAK1 To =~ /notexist/

  # if-unset should not leak to a redefined test
  header TEST_LEAK2 Not-Exist =~ /^UNSET$/ [if-unset: UNSET]
  header TEST_LEAK2 Not-Exist =~ /^UNSET$/

  # op should not leak to a redefined test
  header TEST_LEAK3 To !~ /./
  header TEST_LEAK3 To =~ /notfound/

  # Test 4.0 :first :last parser
  header HEADER_FIRST1 X-Hashcash:first =~ /^0:040315:test@example.com:69781c87bae95c03$/
  header HEADER_LAST1 X-Hashcash:last =~ /^1:20:040806:test1@example.com:test=foo:482b788d12eb9b56:2a3349$/
  header HEADER_ALL1 X-Hashcash =~ /^0:040315:.*1:20:040806:/s

  # Meta should evaluate all
  meta TEST_META (TEST_EXISTS1 && TEST_UNSET2 && HEADER_FIRST1 && HEADER_LAST1 && HEADER_ALL1)
');

%patterns = (
  q{ 1.0 TEST_EXISTS1 }, '',
  q{ 1.0 TEST_UNSET2 }, '',
  q{ 1.0 HEADER_FIRST1 }, '',
  q{ 1.0 HEADER_LAST1 }, '',
  q{ 1.0 HEADER_ALL1 }, '',
  q{ 1.0 TEST_META }, '',
);
%anti_patterns = (
  q{ TEST_EXISTS2 }, '',
  q{ TEST_UNSET1 }, '',
  q{ TEST_UNSET3 }, '',
  q{ TEST_LEAK1 }, '',
  q{ TEST_LEAK2 }, '',
  q{ TEST_LEAK3 }, '',
);

ok (sarun ("-L -t < data/nice/001", \&patterns_run_cb));
ok_all_patterns();

##########################################

tstprefs('
  # Test 4.0 multiple :addr parser
  header TO1 To:addr =~ /(?:@.*?){1}/s
  header TONEG1 To:addr =~ /(?:@.*?){2}/s
  header CC1 Cc:addr =~ /(?:@.*?){5}/s
  header CCNEG1 Cc:addr =~ /(?:@.*?){6}/s
  header TOCC1 ToCc:addr =~ /(?:@.*?){6}/s
  header TOCCNEG1 ToCc:addr =~ /(?:@.*?){7}/s
  header __TO_COUNT To:addr =~ /^.+$/m
  tflags __TO_COUNT multiple
  meta TO2 __TO_COUNT == 1
  header __CC_COUNT Cc:addr =~ /^.+$/m
  tflags __CC_COUNT multiple
  meta CC2 __CC_COUNT == 5
  header __TOCC_COUNT ToCc:addr =~ /^.+$/m
  tflags __TOCC_COUNT multiple
  meta TOCC2 __TOCC_COUNT == 6
');

%patterns = (
  q{ 1.0 TO1 }, '',
  q{ 1.0 CC1 }, '',
  q{ 1.0 TOCC1 }, '',
  q{ 1.0 TO2 }, '',
  q{ 1.0 CC2 }, '',
  q{ 1.0 TOCC2 }, '',
);
%anti_patterns = (
  q{ TONEG }, '',
  q{ CCNEG }, '',
  q{ TOCCNEG }, '',
);

ok (sarun ("-L -t < data/nice/006", \&patterns_run_cb));
ok_all_patterns();

