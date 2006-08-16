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

package Mail::SpamAssassin::Locker::Flock;

use strict;
use warnings;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;
use File::Spec;
use IO::File;
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
# Attempt to create a file lock, using NFS-UNsafe locking techniques.

sub safe_lock {
  my ($self, $path, $max_retries, $mode) = @_;
  my $is_locked = 0;
  my @stat;

  $max_retries ||= 30;
  $mode ||= 0600;
  $mode = oct $mode if $mode =~ /^0/;   # accept number or string

  my $lock_file = "$path.mutex";
  my $umask = umask(~$mode);
  my $fh = new IO::File();

  if (!$fh->open ($lock_file, O_RDWR|O_CREAT)) {
      umask $umask; # just in case
      die "locker: safe_lock: cannot create lockfile $lock_file: $!\n";
  }
  umask $umask; # we've created the file, so reset umask

  dbg("locker: safe_lock: created $lock_file");

  my $unalarmed = 0;
  my $oldalarm = 0;

  # use a SIGALRM-based timer -- more efficient than second-by-second
  # sleeps
  eval {
    local $SIG{ALRM} = sub { die "alarm\n" };
    dbg("locker: safe_lock: trying to get lock on $path with $max_retries timeout");

    # max_retries is basically seconds! so use it for the timeout
    $oldalarm = alarm $max_retries;

    # HELLO!?! IO::File doesn't have a flock() method?!
    if (flock ($fh, LOCK_EX)) {
      alarm $oldalarm;
      $unalarmed = 1; # avoid calling alarm(0) twice

      dbg("locker: safe_lock: link to $lock_file: link ok");
      $is_locked = 1;

      # just to be nice: let people know when it was locked
      $fh->print ("$$\n");
      $fh->flush ();

      # keep the FD around - we need to keep the lockfile open or the lock
      # is unlocked!
      $self->{lock_fhs} ||= { };
      $self->{lock_fhs}->{$path} = $fh;
    }
  };

  my $err = $@;

  $unalarmed or alarm $oldalarm; # if we die'd above, need to reset here
  if ($err) {
    if ($err =~ /alarm/) {
      dbg("locker: safe_lock: timed out after $max_retries seconds");
    } else {
      die "locker: safe_lock: $err";
    }
  }

  return $is_locked;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  if (!exists $self->{lock_fhs} || !defined $self->{lock_fhs}->{$path}) {
    dbg("locker: safe_unlock: no lock handle for $path - already unlocked?");
    return;
  }

  my $fh = $self->{lock_fhs}->{$path};
  delete $self->{lock_fhs}->{$path};

  flock ($fh, LOCK_UN);
  $fh->close();

  dbg("locker: safe_unlock: unlocked $path.mutex");

  # do NOT unlink! this would open a race, whereby:
  #
  # procA: ....unlock                           (unlocked lockfile)
  # procB:            lock                      (gets lock on lockfile)
  # procA:                 unlink               (deletes lockfile)
  # (procB's lock is now deleted as well!)
  # procC:                        create, lock  (gets lock on new file)
  #
  # both procB and procC would then think they had locks, and both
  # would write to the database file.  this is bad.
  #
  # unlink ("$path.mutex"); 
  #
  # side-effect: we leave a .mutex file around. but hey!
}

###########################################################################

sub refresh_lock {
  my($self, $path) = @_;

  return unless $path;

  if (!exists $self->{lock_fhs} || !defined $self->{lock_fhs}->{$path}) {
    warn "locker: refresh_lock: no lock handle for $path\n";
    return;
  }

  my $fh = $self->{lock_fhs}->{$path};
  $fh->print ("$$\n");
  $fh->flush ();

  dbg("locker: refresh_lock: refresh $path.mutex");
}

###########################################################################

1;
