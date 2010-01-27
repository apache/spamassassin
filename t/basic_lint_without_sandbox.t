#!/usr/bin/perl
#
# ensure the rules files work without rules/70_sandbox.cf

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint_without_sandbox");
use Test; BEGIN { plan tests => 3 };

# ---------------------------------------------------------------------------

%patterns = (

q{  }, 'anything',

);

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

my $sandboxfile = "log/test_rules_copy/70_sandbox.cf";
ok (-f $sandboxfile);
unlink $sandboxfile;
ok (!-f $sandboxfile);

sarun ("-L --lint", \&patterns_run_cb);
ok_all_patterns();
