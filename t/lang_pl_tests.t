#!/usr/bin/perl

use lib '.'; 
use lib 't';
use SATest; 
sa_t_init("lang_pl_tests");
use Test; 

use constant TEST_ENABLED => conf_bool('run_pl_tests');

BEGIN { plan tests => (TEST_ENABLED ? 1 : 0) };

exit unless TEST_ENABLED;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: }, 'didnt_hang_at_least',

);

$ENV{'PERL_BADLANG'} = 0; # Sweep problems under the rug
$ENV{'LANGUAGE'} = 'pl_PL';
$ENV{'LC_ALL'} = 'pl_PL';
sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
