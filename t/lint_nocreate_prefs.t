#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("lint_nocreate_prefs");
use Test; BEGIN { plan tests => 2 };

# ---------------------------------------------------------------------------

%patterns = ( q{  }, 'anything' );

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

sarun ("-L --lint --prefspath=log/prefs", \&patterns_run_cb);
ok_all_patterns();

ok (!-f "log/prefs");

