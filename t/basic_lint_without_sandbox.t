#!/usr/bin/perl -T
#
# ensure the rules files work without rules/70_sandbox.cf

use lib '.'; use lib 't';
use SATest; sa_t_init("basic_lint_without_sandbox");
use Test::More tests => 3;

# ---------------------------------------------------------------------------

%patterns = (
  qr/^/, 'anything',
);

# override locale for this test!
$ENV{'LANGUAGE'} = $ENV{'LC_ALL'} = 'C';

my $scoresfile  = "$localrules/50_scores.cf";
my $sandboxfile = "$localrules/70_sandbox.cf";

# when running from the built tarball or make disttest, we will not have a full
# rules dir -- therefore no 70_sandbox.cf.  We will also have no 50_scores.cf,
# so we can use that to tell if this is the case
SKIP: {
    skip( "Not on a sandbox", 2 ) unless -f $scoresfile;
    ok -f $sandboxfile;
    unlink $sandboxfile;
    ok !-f $sandboxfile;
}

sarun ("-L --lint", \&patterns_run_cb);
ok_all_patterns();

