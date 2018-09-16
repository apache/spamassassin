#!/usr/bin/perl

use lib '.';
use lib 't';
use SATest;
sa_t_init("lang_pl_tests");

use Test::More;
plan skip_all => "pl tests disabled" unless conf_bool('run_pl_tests');
plan tests => 1;

# ---------------------------------------------------------------------------

%patterns = (

q{ X-Spam-Status: }, 'didnt_hang_at_least',

);

$ENV{'PERL_BADLANG'} = 0; # Sweep problems under the rug
$ENV{'LANGUAGE'} = 'pl_PL';
$ENV{'LC_ALL'} = 'pl_PL';
sarun ("-L -t < data/nice/004", \&patterns_run_cb);
ok_all_patterns();
