#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_l");
use Test; plan tests => ($NO_SPAMC_EXE ? 0 : 3),
               onfail => sub { warn "FAIL: Some other process running on port 8?  Test assumes nothing is listening on port 8." };


exit if $NO_SPAMC_EXE;

# ---------------------------------------------------------------------------

my $errmsg = ($RUNNING_ON_WINDOWS?"10061":"Connection refused");

%patterns = (

q{ hello world }, 'spamc_l',
q{ spamc: connect(AF_INET) to spamd at 127.0.0.1 failed, retrying (#1 of 3): } . $errmsg, 'connfailed',

);

# connect on port 8 (unassigned): should always fail
ok (scrunwithstderr ("-l -p 8 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

