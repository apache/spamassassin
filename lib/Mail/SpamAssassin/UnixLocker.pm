package Mail::SpamAssassin::UnixLocker;

use strict;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
use Sys::Hostname;
use File::Spec;
use Time::Local;

use vars qw{
  @ISA $HOSTNAME
};

BEGIN { $HOSTNAME = hostname(); }

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

use constant LOCK_MAX_AGE => 600;	# seconds 

sub safe_lock {
  my ($self, $path, $max_retries) = @_;
  my $is_locked = 0;
  my @stat;

  $max_retries ||= 30;

  my $lock_file = "$path.lock";
  my $lock_tmp = Mail::SpamAssassin::Util::untaint_file_path
					("$path.lock.$HOSTNAME.$$");

  my $umask = 077;
  if (!open(LTMP, ">$lock_tmp")) {
      umask $umask;
      die "lock: $$ cannot create tmp lockfile $lock_tmp for $lock_file: $!\n";
  }
  umask $umask;
  autoflush LTMP 1;
  dbg("lock: $$ created $lock_tmp");

  for (my $retries = 0; $retries < $max_retries; $retries++) {
    if ($retries > 0) {
      select(undef, undef, undef, (rand(1.0) + 0.5));
    }
    print LTMP "$HOSTNAME.$$\n";
    dbg("lock: $$ trying to get lock on $path with $retries retries");
    if (link($lock_tmp, $lock_file)) {
      dbg("lock: $$ link to $lock_file: link ok");
      $is_locked = 1;
      last;
    }
    # link _may_ return false even if the link _is_ created
    @stat = stat($lock_tmp);
    if ($stat[3] > 1) {
      dbg("lock: $$ link to $lock_file: stat ok");
      $is_locked = 1;
      last;
    }
    # check age of lockfile ctime
    my $now = ($#stat < 11 ? undef : $stat[10]);
    @stat = stat($lock_file);
    my $lock_age = ($#stat < 11 ? undef : $stat[10]);
    if (!defined($lock_age) || ($now - $lock_age) > LOCK_MAX_AGE) {
      # we got a stale lock, break it
      dbg("lock: $$ breaking stale $lock_file: age=" .
	  (defined $lock_age ? $lock_age : "undef") . " now=$now");
      unlink ($lock_file) || warn "lock: $$ unlink of lock file $lock_file failed: $!\n";
    }
  }

  close(LTMP);
  unlink ($lock_tmp) || warn "lock: $$ unlink of temp lock $lock_tmp failed: $!\n";

  return $is_locked;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  unlink ("$path.lock") || warn "unlock: $$ unlink failed: $path.lock\n";
  dbg("unlock: $$ unlink $path.lock");
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
