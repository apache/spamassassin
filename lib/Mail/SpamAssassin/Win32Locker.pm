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

  my $lock_file = "$path.lock";

  if (-e $lock_file && -M $lock_file > (LOCK_MAX_AGE / 86400)) {
    dbg("lock: $$ breaking stale lock: $lock_file");
    unlink $lock_file;
  }
  for (my $retries = 0; $retries < LOCK_MAX_RETRIES; $retries++) {
    if ($retries > 0) {
      sleep(1);
    }
    dbg("lock: $$ trying to get lock on $path with $retries retries");
    if (sysopen(LOCKFILE, $lock_file, O_RDWR|O_CREAT|O_EXCL)) {
      dbg("lock: $$ link to $lock_file: sysopen ok");
      close(LOCKFILE);
      return 1;
    }
    my @stat = stat($lock_file);
    # check age of lockfile ctime
    my $age = ($#stat < 11 ? undef : $stat[10]);
    if ((!defined($age) && $retries > LOCK_MAX_RETRIES / 2) ||
	(time - $age > LOCK_MAX_AGE))
    {
      dbg("lock: $$ breaking stale lock: $lock_file");
      unlink $lock_file;
    }
  }
  return 0;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  unlink "$path.lock" || warn "unlock: $$ unlink failed: $path.lock\n";
  dbg("unlock: $$ unlink $path.lock");
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
