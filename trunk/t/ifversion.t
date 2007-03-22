#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("ifversion");
use Test; BEGIN { plan tests => 4 };

# ---------------------------------------------------------------------------

%patterns = (

q{ GTUBE }, 'gtube',
q{ SHOULD_BE_CALLED }, 'should_be_called'

);

%anti_patterns = (

q{ SHOULD_NOT_BE_CALLED }, 'should_not_be_called'

);

tstlocalrules ("
	if (version > 9.99999)
	  body SHOULD_NOT_BE_CALLED /./
	endif
	if (version <= 9.99999)
	  body SHOULD_BE_CALLED /./
	endif
");

ok (sarun ("-L -t < data/spam/gtube.eml", \&patterns_run_cb));
ok_all_patterns();

