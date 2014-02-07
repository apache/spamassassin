#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_y");
use Test; plan tests => ($NO_SPAMC_EXE ? 0 : 2),
               onfail => sub { warn "FAIL: Some other process running on port 8?  Test assumes nothing is listening on port 8." };


exit if $NO_SPAMC_EXE;

# ---------------------------------------------------------------------------

%patterns = (

);

%anti_patterns = (

  # the text should NOT be output, bug 4991
  q{ hello world }, 'spamc_y',

);

# connect on port 8 (unassigned): should always fail
ok (scrunwithstderr ("-y -p 8 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

