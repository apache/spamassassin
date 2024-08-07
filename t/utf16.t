#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("utf16");
use Test::More tests => 6;

# ---------------------------------------------------------------------------

$rules = '
  header SUBJ_TEST Subject =~ /Design and manufacturing/
  body   BODY_TEST /Shenzhen Powstar Technology/
';

%patterns = (
    q{ 1.0 SUBJ_TEST }, '',
    q{ 1.0 BODY_TEST }, '',
);

%anti_patterns = ();

# normalize_charset 1
tstprefs("
  $rules
  normalize_charset 1
");
ok (sarun ("-L -t < data/spam/utf16.eml", \&patterns_run_cb));
ok_all_patterns();

%patterns = (
    q{ 1.0 SUBJ_TEST }, '',
);

%anti_patterns = (
    q{ 1.0 BODY_TEST }, '',
);

# normalize_charset 0
tstprefs("
  $rules
  normalize_charset 0
");
ok (sarun ("-L -t < data/spam/utf16.eml", \&patterns_run_cb));
ok_all_patterns();
