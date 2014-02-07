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

my $scoresfile  = "log/test_rules_copy/50_scores.cf";
my $sandboxfile = "log/test_rules_copy/70_sandbox.cf";

# when running from the built tarball or make disttest, we will not have a full
# rules dir -- therefore no 70_sandbox.cf.  We will also have no 50_scores.cf,
# so we can use that to tell if this is the case
skip (!-f $scoresfile, -f $sandboxfile);
unlink $sandboxfile;
skip (!-f $scoresfile, !-f $sandboxfile);

sarun ("-L --lint", \&patterns_run_cb);
ok_all_patterns();
