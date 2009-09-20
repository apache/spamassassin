#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("db_awl_perms");
use Test; BEGIN { plan tests => 4 };
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
sarun("--debug --add-addr-to-whitelist whitelist_test\@example.org",
      \&patterns_run_cb);

system "ls -l log/user_state";          # for the logs

my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size) = stat "log/user_state/awl";
ok (($mode & 0777) == 0644);

($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size) = stat "log/user_state/awl.mutex";
ok (($mode & 0777) == 0644);

ok unlink 'log/user_state/awl';
ok unlink 'log/user_state/awl.mutex';
