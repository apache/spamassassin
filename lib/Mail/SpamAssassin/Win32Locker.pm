package Mail::SpamAssassin::Win32Locker;

use strict;
use bytes;
use Fcntl;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
use File::Spec;
use Time::Local;

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

use constant LOCK_MAX_AGE => 300;       # seconds 
use constant LOCK_MAX_RETRIES => 30;    # average 1 per second

sub safe_lock {
  my ($self, $path) = @_;
  my @stat;

  for (my $retries = 0; $retries < LOCK_MAX_RETRIES; $retries++) {
    if ($retries > 0) {
      sleep(1);
    }
    dbg("lock: $$ trying to get lock on $path with $retries retries");
    if (mkdir $lock_file) {
      dbg("lock: $$ mkdir to $lock_file: mkdir ok");
      return 1;
    }
    if (-M $lock_file > (LOCK_MAX_AGE / 86400)) {
      dbg("lock: $$ breaking stale lock: $lock_file");
      rmdir $lock_file || unlink $lock_file;
    }
    else {
      @stat = stat($lock_file);
      my $age = ($#stat < 11 ? undef : $stat[10]);
      if (!defined($age) || time() - $age > LOCK_MAX_AGE) {
	dbg("lock: $$ breaking stale lock: $lock_file");
	rmdir $lock_file || unlink $lock_file;
      }
    }
  }
  return 0;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  rmdir "$path.lock";
  dbg("unlock: $$ unlocked $path");
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
