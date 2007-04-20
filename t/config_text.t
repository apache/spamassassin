#!/usr/bin/perl

use constant IS_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);

use lib '.'; use lib 't';
use SATest; sa_t_init("config_text");

# skip the test on Windows; the switches contain spaces, which does not
# work too well with win32 CMD.EXE
use Test; BEGIN { plan tests => IS_WINDOWS ? 0 : 2 };
exit if IS_WINDOWS;

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

