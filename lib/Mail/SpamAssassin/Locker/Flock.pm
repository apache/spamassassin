# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
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
# NFS-safe locking (I hope!):
# Attempt to create a file lock, using NFS-safe locking techniques.
#
# Locking code adapted from code by Alexis Rosen <alexis@panix.com>
# by Kelsey Cummings <kgc@sonic.net>, with mods by jm and quinlan

sub safe_lock {
  my ($self, $path, $max_retries) = @_;
  my $is_locked = 0;
  my @stat;

  $max_retries ||= 30;

  my $lock_file = "$path.lock";
  my $umask = umask 077;
  my $fh = new IO::File();

  if (!$fh->open ("$lock_file", O_RDWR|O_CREAT)) {
      umask $umask; # just in case
      die "lock: $$ cannot create lockfile $lock_file: $!\n";
  }

  dbg("lock: $$ created $lock_file");

  for (my $retries = 0; $retries < $max_retries; $retries++) {
    if ($retries > 0) { $self->jittery_one_second_sleep(); }
    dbg("lock: $$ trying to get lock on $path with $retries retries");

    # HELLO!?! IO::File doesn't have a flock() method?!
    if (flock ($fh, LOCK_EX|LOCK_NB)) {
      dbg("lock: $$ link to $lock_file: link ok");
      $is_locked = 1;
      last;
    }
  }

  # just to be nice: let people know when it was locked
  $fh->print ("$$\n");
  $fh->flush ();

  # keep the FD around - we need to keep the lockfile open or the lock
  # is unlocked!
  $self->{lock_fhs} ||= { };
  $self->{lock_fhs}->{$path} = $fh;
  return $is_locked;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  if (!exists $self->{lock_fhs} || !defined $self->{lock_fhs}->{$path}) {
    warn "unlock: $$ no lock handle for $path\n";
    return;
  }

  my $fh = $self->{lock_fhs}->{$path};
  delete $self->{lock_fhs}->{$path};

  flock ($fh, LOCK_UN);
  $fh->close();

  dbg("unlock: $$ unlocked $path.lock");

  # do NOT unlink! this would open a race, whereby:
  # procA: ....unlock                           (unlocked lockfile)
  # procB:            lock                      (gets lock on lockfile)
  # procA:                 unlink               (deletes lockfile)
  # (procB's lock is now deleted as well!)
  # procC:                        create, lock  (gets lock on new file)
  #
  # unlink ("$path.lock"); 
  #
  # side-effect: we leave a .lock file around. but hey!
}

###########################################################################

sub refresh_lock {
  my($self, $path) = @_;

  return unless $path;

  if (!exists $self->{lock_fhs} || !defined $self->{lock_fhs}->{$path}) {
    warn "refresh_lock: $$ no lock handle for $path\n";
    return;
  }

  my $fh = $self->{lock_fhs}->{$path};
  $fh->print ("$$\n");
  $fh->flush ();

  dbg("refresh: $$ refresh $path.lock");
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
