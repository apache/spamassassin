#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("config_text");

# skip the test on Windows; the switches contain spaces, which does not
# work too well with win32 CMD.EXE

use Test::More;
plan skip_all => "These tests don't work on windows" if $^O =~ /^(mswin|dos|os2)/i;
plan tests => 2;

# ---------------------------------------------------------------------------

%patterns = (

q{ FOO } => 'FOO',
q{ BAR } => 'BAR',

);

sarun ("-L -t ".
    "--cf='body FOO /VFS/' ".
    "--cf='body BAR /source/' ".
    "< data/nice/001", \&patterns_run_cb);

ok_all_patterns();

