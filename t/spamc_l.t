#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("spamc_l");

use Test::More;
plan skip_all => "No SPAMC exe" if $NO_SPAMC_EXE;
plan tests => 4;

# ---------------------------------------------------------------------------

my $errmsg = ($RUNNING_ON_WINDOWS?"10061":"Connection refused");

%patterns = (
  q{ hello world }, 'spamc_l',
  q{ spamc: connect to spamd on }, 'connfailed_a',
  q{ failed, retrying (#1 of 3): } . $errmsg, 'connfailed_b',
);

# connect on port 8 (unassigned): should always fail
ok (scrunwithstderr ("-l -p 8 < data/etc/hello.txt", \&patterns_run_cb));
ok_all_patterns();

