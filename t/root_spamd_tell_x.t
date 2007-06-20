#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_tell_x");
use Test;

use constant TEST_ENABLED => conf_bool('run_root_tests');
use constant IS_ROOT => eval { ($> == 0); };
use constant RUN_TESTS => (TEST_ENABLED && IS_ROOT);

BEGIN { plan tests => (RUN_TESTS ? 6 : 0) };
exit unless RUN_TESTS;

# ---------------------------------------------------------------------------

%patterns = (
q{ Message successfully } => 'learned',
);

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

# remove these first
unlink('log/user_state/bayes_seen.dir');
unlink('log/user_state/bayes_toks.dir');

# ensure it is writable by all
use File::Path; mkpath("log/user_state"); chmod 01777, "log/user_state";

# use SDBM so we do not need DB_File
tstlocalrules ("
        bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
");

ok(start_spamd("-L --allow-tell --create-prefs -x"));

ok(spamcrun("-lx -L ham < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok(stop_spamd());

# ensure these are not owned by root
ok check_owner('log/user_state/bayes_seen.dir');
ok check_owner('log/user_state/bayes_toks.dir');

sub check_owner {
  my $f = shift;
  my @stat = stat $f;

  print "stat($f) = ".join(', ', @stat)."\n";

  if (!defined $stat[1]) {
    warn "no stat for $f";
    return 0;
  }
  elsif ($stat[4] == 0) {
    warn "stat for $f: owner is root";
    return 0;
  }
  else {
    return 1;
  }
}
