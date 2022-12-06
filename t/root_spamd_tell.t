#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("root_spamd_tell");

use constant HAS_SUDO => $RUNNING_ON_WINDOWS || eval { $_ = untaint_cmd("which sudo 2>/dev/null"); chomp; -x };

use Test::More;
plan skip_all => "root tests disabled" unless conf_bool('run_root_tests');
plan skip_all => "not running tests as root" unless eval { ($> == 0); };
plan skip_all => "sudo executable not found in path" unless HAS_SUDO;
plan tests => 6;

# ---------------------------------------------------------------------------

%patterns = (
  q{Message successfully } => 'learned',
);

# run spamc as unpriv uid
$spamc = "sudo -u nobody $spamc";

# remove these first
unlink("$userstate/bayes_seen.dir");
unlink("$userstate/bayes_toks.dir");

# ensure it is readable/writeable by all
diag "Test will fail if run in directory not accessible by 'nobody' as is typical for a home directory";
chmod 01755, $workdir;
chmod 01777, $userstate;

# use SDBM so we do not need DB_File
tstprefs ("
  bayes_store_module Mail::SpamAssassin::BayesStore::SDBM
");

ok(start_spamd("-L --allow-tell"));

ok(spamcrun("-lx -L ham < data/spam/001", \&patterns_run_cb));
ok_all_patterns();

ok(stop_spamd());

# ensure these are not owned by root
ok check_owner("$userstate/bayes_seen.dir");
ok check_owner("$userstate/bayes_toks.dir");

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

