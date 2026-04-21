#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("regexp_named_capture_spamd");

use Test::More;
plan skip_all => "Spamd tests disabled" if $SKIP_SPAMD_TESTS;
plan tests => 3;

# bz #8388
# Regression test for the CAPTURING TAGS feature in spamd mode.
#

tstlocalrules(q{
  score TEST_SPAMD_CAP_CAPTURE  1.0
  score TEST_SPAMD_CAP_TEMPLATE 1.0
  score TEST_SPAMD_CAP_UNDEF    1.0

  # Sets tag TESTCAP_SPAMD; runs at priority -10000
  body TEST_SPAMD_CAP_CAPTURE /release of (?<TESTCAP_SPAMD>\w+)/

  # Uses %{TESTCAP_SPAMD}: must match after warm-up via spamd
  body TEST_SPAMD_CAP_TEMPLATE m,www\.%{TESTCAP_SPAMD}\.,i

  # Undefined tag in alternation: the (?!) branch never matches but
  # the plain-text alternative 'Evolution' still should
  body TEST_SPAMD_CAP_UNDEF /(?:%{TESTCAP_UNDEF_X}|Evolution)/
});

%patterns = (
  q{TEST_SPAMD_CAP_CAPTURE},  'capture_producing_rule',
  q{TEST_SPAMD_CAP_TEMPLATE}, 'capture_template_rule',
  q{TEST_SPAMD_CAP_UNDEF},    'capture_undef_alternation',
);

sdrun("-L", "< data/nice/001", \&patterns_run_cb);
ok_all_patterns();
