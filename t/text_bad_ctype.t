#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("text_bad_ctype");
use Test::More tests => 2;

# ---------------------------------------------------------------------------

tstlocalrules ('
  body NATURAL	/\btotally <br> natural/i
');

%patterns = ( q{ 1.0 NATURAL } => 'NATURAL',);
%anti_patterns = ();
sarun ("-L -t < data/spam/badctype1", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();
%anti_patterns = ( q{ NATURAL } => 'NATURAL',);
sarun ("-L -t < data/spam/badctype2", \&patterns_run_cb);
ok_all_patterns();

