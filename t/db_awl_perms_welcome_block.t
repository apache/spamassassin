#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("db_awl_perms_welcome_block");
use IO::File;
use Test::More;
plan skip_all => "Tests don't work on windows" if $RUNNING_ON_WINDOWS;
plan tests => 5;

# ---------------------------------------------------------------------------
# bug 6173

tstprefs ("
  use_auto_welcomelist 1
  auto_welcomelist_path ./$userstate/awl
  auto_welcomelist_file_mode 0755
  lock_method flock
");

unlink "$userstate/awl";
unlink "$userstate/awl.mutex";
umask 022;
sarun("--add-addr-to-welcomelist whitelist_test\@example.org",
      \&patterns_run_cb);

# in case this test is ever made to work on Windows
untaint_system($RUNNING_ON_WINDOWS?("dir " . File::Spec->canonpath($userstate)):"ls -l $userstate");  # for the logs

sub checkmode {
  my $fname = shift;
  if (!-f $fname) { return 1; }
  my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size) = stat $fname;
  return (($mode & 0777) == 0644);
}

ok checkmode "$userstate/awl";              # DB_File
ok checkmode "$userstate/awl.dir";          # SDBM
ok checkmode "$userstate/awl.pag";          # SDBM
ok checkmode "$userstate/awl.mutex";

unlink "$userstate/awl",
    "$userstate/awl.dir",
    "$userstate/awl.pag";
ok unlink "$userstate/awl.mutex";
