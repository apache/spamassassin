#!/usr/bin/perl -T

###
### UTF-8 CONTENT, edit with UTF-8 locale/editor
###

use lib '.'; use lib 't';
use SATest; sa_t_init("utf8");
use Test::More tests => 14;

# ---------------------------------------------------------------------------

%patterns = (
  q{ X-Spam-Status: Yes, score=}, 'status',
  q{ X-Spam-Flag: YES}, 'flag',
  q{ X-Spam-Level: ****}, 'stars',
);
%anti_patterns = ();

ok (sarun ("-L -t < data/spam/009", \&patterns_run_cb));
ok_all_patterns();

# ---------------------------------------------------------------------------

my $rules = '
  body FOO1 /金融機/
  body FOO2 /金融(?:xyz|機)/
  body FOO3 /\xe9\x87\x91\xe8\x9e\x8d\xe6\xa9\x9f/
  body FOO4 /.\x87(?:\x91|\x00)[\xe8\x00]\x9e\x8d\xe6\xa9\x9f/
';

%patterns = (
  q{ 1.0 FOO1 }, '',
  q{ 1.0 FOO2 }, '',
  q{ 1.0 FOO3 }, '',
  q{ 1.0 FOO4 }, '',
);
%anti_patterns = ();

# normalize_charset 1
tstprefs("
  $rules
  normalize_charset 1
");
ok (sarun ("-L -t < data/spam/unicode1", \&patterns_run_cb));
ok_all_patterns();

# normalize_charset 0
tstprefs("
  $rules
  normalize_charset 0
");
ok (sarun ("-L -t < data/spam/unicode1", \&patterns_run_cb));
ok_all_patterns();

