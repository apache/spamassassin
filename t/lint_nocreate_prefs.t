#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("lint_nocreate_prefs");
use Test::More tests => 2;

# ---------------------------------------------------------------------------

%patterns = ( qr/^/, 'anything' );

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

sarun ("-L --lint --prefspath=$workdir/prefs", \&patterns_run_cb);
ok_all_patterns();

ok (!-f "$workdir/prefs");

