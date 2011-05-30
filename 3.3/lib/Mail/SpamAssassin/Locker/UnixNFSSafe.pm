# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Locker::UnixNFSSafe;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;
use File::Spec;
use Time::Local;
use Fcntl qw(:DEFAULT :flock);

use vars qw{
  @ISA
};

@ISA = qw(Mail::SpamAssassin::Locker);

###########################################################################

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self;
}

###########################################################################
# NFS-safe locking (I hope!):
# Attempt to create a file lock, using NFS-safe locking techniques.
#
# Locking code adapted from code by Alexis Rosen <alexis@panix.com>
# by Kelsey Cummings <kgc@sonic.net>, with mods by jm and quinlan
#
# A good implementation of Alexis' code, for reference, is here:
# http://mail-index.netbsd.org/netbsd-bugs/1996/04/17/0002.html

use constant LOCK_MAX_AGE => 600;	# seconds 

sub safe_lock {
  my ($self, $path, $max_retries, $mode) = @_;
  my $is_locked = 0;
  my @stat;

  $max_retries ||= 30;
  $mode ||= "0700";
  $mode = (oct $mode) & 0666;
  dbg ("locker: mode is $mode");

  my $lock_file = "$path.lock";
  my $hname = Mail::SpamAssassin::Util::fq_hostname();
  my $lock_tmp = Mail::SpamAssassin::Util::untaint_file_path
                                      ($path.".lock.".$hname.".".$$);

  # keep this for unlocking
  $self->{lock_tmp} = $lock_tmp;

  my $umask = umask(~$mode);
  if (!open(LTMP, ">$lock_tmp")) {
      umask $umask; # just in case
      die "locker: safe_lock: cannot create tmp lockfile $lock_tmp for $lock_file: $!\n";
  }
  umask $umask;
  autoflush LTMP 1;
  dbg("locker: safe_lock: created $lock_tmp");

  for (my $retries = 0; $retries < $max_retries; $retries++) {
    if ($retries > 0) { $self->jittery_one_second_sleep(); }
    print LTMP "$hname.$$\n"  or warn "Error writing to $lock_tmp: $!";
    dbg("locker: safe_lock: trying to get lock on $path with $retries retries");
    if (link($lock_tmp, $lock_file)) {
      dbg("locker: safe_lock: link to $lock_file: link ok");
      $is_locked = 1;
      last;
    }
    # link _may_ return false even if the link _is_ created
    @stat = lstat($lock_tmp);
    @stat  or warn "locker: error accessing $lock_tmp: $!";
    if (defined $stat[3] && $stat[3] > 1) {
      dbg("locker: safe_lock: link to $lock_file: stat ok");
      $is_locked = 1;
      last;
    }
    # check age of lockfile ctime
    my $now = ($#stat < 11 ? undef : $stat[10]);
    @stat = lstat($lock_file);
    @stat  or warn "locker: error accessing $lock_file: $!";
    my $lock_age = ($#stat < 11 ? undef : $stat[10]);
    if (defined($lock_age) && defined($now) && ($now - $lock_age) > LOCK_MAX_AGE)
    {
      # we got a stale lock, break it
      dbg("locker: safe_lock: breaking stale $lock_file: age=" .
	  (defined $lock_age ? $lock_age : "undef") . " now=$now");
      unlink($lock_file)
        or warn "locker: safe_lock: unlink of lock file $lock_file failed: $!\n";
    }
  }

  close LTMP  or die "error closing $lock_tmp: $!";
  unlink($lock_tmp)
    or warn "locker: safe_lock: unlink of temp lock $lock_tmp failed: $!\n";

  # record this for safe unlocking
  if ($is_locked) {
    @stat = lstat($lock_file);
    @stat  or warn "locker: error accessing $lock_file: $!";
    my $lock_ctime = ($#stat < 11 ? undef : $stat[10]);

    $self->{lock_ctimes} ||= { };
    $self->{lock_ctimes}->{$path} = $lock_ctime;
  }

  return $is_locked;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  my $lock_file = "$path.lock";
  my $lock_tmp = $self->{lock_tmp};
  if (!$lock_tmp) {
    dbg("locker: safe_unlock: $path.lock never locked");
    return;
  }

  # 1. Build a temp file and stat that to get an idea of what the server
  # thinks the current time is (our_tmp.st_ctime).  note: do not use time()
  # directly because the server's clock may be out of sync with the client's.

  my @stat_ourtmp;
  if (!defined sysopen(LTMP, $lock_tmp, O_CREAT|O_WRONLY|O_EXCL, 0700)) {
    warn "locker: safe_unlock: failed to create lock tmpfile $lock_tmp: $!";
    return;
  } else {
    autoflush LTMP 1;
    print LTMP "\n"  or warn "Error writing to $lock_tmp: $!";

    if (!(@stat_ourtmp = stat(LTMP)) || (scalar(@stat_ourtmp) < 11)) {
      @stat_ourtmp  or warn "locker: error accessing $lock_tmp: $!";
      warn "locker: safe_unlock: failed to create lock tmpfile $lock_tmp";
      close LTMP  or die "error closing $lock_tmp: $!";
      unlink($lock_tmp)
        or warn "locker: safe_lock: unlink of lock file failed: $!\n";
      return;
    }
  }
 
  my $ourtmp_ctime = $stat_ourtmp[10]; # paranoia
  if (!defined $ourtmp_ctime) {
    die "locker: safe_unlock: stat failed on $lock_tmp";
  }

  close LTMP  or die "error closing $lock_tmp: $!";
  unlink($lock_tmp)
    or warn "locker: safe_lock: unlink of lock file failed: $!\n";

  # 2. If the ctime hasn't been modified, unlink the file and return. If the
  # lock has expired, sleep the usual random interval before returning. If we
  # didn't sleep, there could be a race if the caller immediately tries to
  # relock the file.

  my $lock_ctime = $self->{lock_ctimes}->{$path};
  if (!defined $lock_ctime) {
    warn "locker: safe_unlock: no ctime recorded for $lock_file";
    return;
  }

  my @stat_lock = lstat($lock_file);
  @stat_lock  or warn "locker: error accessing $lock_file: $!";

  my $now_ctime = $stat_lock[10];

  if (defined $now_ctime && $now_ctime == $lock_ctime) 
  {
    # things are good: the ctimes match so it was our lock
    unlink($lock_file)
      or warn "locker: safe_unlock: unlink failed: $lock_file\n";
    dbg("locker: safe_unlock: unlink $lock_file");

    if ($ourtmp_ctime >= $lock_ctime + LOCK_MAX_AGE) {
      # the lock has expired, so sleep a bit; use some randomness
      # to avoid race conditions.
      dbg("locker: safe_unlock: lock expired on $lock_file expired safely; sleeping");
      my $i; for ($i = 0; $i < 5; $i++) {
        $self->jittery_one_second_sleep();
      }
    }
    return;
  }

  # 4. Either ctime has been modified, or the entire lock file is missing.
  # If the lock should still be ours, based on the ctime of the temp
  # file, warn it was stolen. If not, then our lock is expired and
  # someone else has grabbed the file, so warn it was lost.
  if ($ourtmp_ctime < $lock_ctime + LOCK_MAX_AGE) {
    warn "locker: safe_unlock: lock on $lock_file was stolen";
  } else {
    warn "locker: safe_unlock: lock on $lock_file was lost due to expiry";
  }
}

###########################################################################

sub refresh_lock {
  my($self, $path) = @_;

  return unless $path;

  # this could arguably read the lock and make sure the same process
  # owns it, but this shouldn't, in theory, be an issue.
  # TODO: in NFS, it definitely may be one :(

  my $lock_file = "$path.lock";
  utime time, time, $lock_file;

  # update the lock_ctimes entry
  my @stat = lstat($lock_file);
  @stat  or warn "locker: error accessing $lock_file: $!";

  my $lock_ctime = ($#stat < 11 ? undef : $stat[10]);
  $self->{lock_ctimes}->{$path} = $lock_ctime;

  dbg("locker: refresh_lock: refresh $path.lock");
}

###########################################################################

1;
