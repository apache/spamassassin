#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("db_awl_perms");
use Test; BEGIN { plan tests => 5 };
use IO::File;

# ---------------------------------------------------------------------------
# bug 6173

tstprefs ("
        $default_cf_lines
        use_auto_whitelist 1
        auto_whitelist_path ./log/user_state/awl
        auto_whitelist_file_mode 0755
        lock_method flock
");

unlink "log/user_state/awl";
unlink "log/user_state/awl.mutex";
umask 022;
sarun("--add-addr-to-whitelist whitelist_test\@example.org",
      \&patterns_run_cb);

system "ls -l log/user_state";          # for the logs

sub checkmode {
  my $fname = shift;
  if (!-f $fname) { return 1; }
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size) = stat $fname;
  return (($mode & 0777) == 0644);
}

ok checkmode "log/user_state/awl";              # DB_File
ok checkmode "log/user_state/awl.dir";          # SDBM
ok checkmode "log/user_state/awl.pag";          # SDBM
ok checkmode "log/user_state/awl.mutex";

unlink 'log/user_state/awl',
    'log/user_state/awl.dir',
    'log/user_state/awl.pag';
ok unlink 'log/user_state/awl.mutex';
