#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("lang_pl_tests");
use Test; BEGIN { plan tests => 1 };

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: }, 'didnt_hang_at_least',

);

$ENV{'PERL_BADLANG'} = 0; # Sweep problems under the rug
$ENV{'LANGUAGE'} = 'pl_PL';
$ENV{'LC_ALL'} = 'pl';
sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
