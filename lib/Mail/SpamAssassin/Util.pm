# A general class for utility functions.  Please use this for
# functions that stand alone, without requiring a $self object,
# Portability functions especially.

package Mail::SpamAssassin::Util;

use strict;
eval "use bytes";
use Fcntl ':DEFAULT',':flock';

use Mail::SpamAssassin;
use Sys::Hostname;
use File::Spec;

use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/oi);

use vars qw{
  $HOSTNAME $AM_TAINTED
};

###########################################################################

# NFS-safe locking (I hope!):
# Attempt to create a file lock, using NFS-safe locking techniques.
#
# Locking code adapted from code by Alexis Rosen <alexis@panix.com>
# by Kelsey Cummings <kgc@sonic.net>, with scattered mods by jm
#
sub safe_lock {
  my ($path) = @_;

  $HOSTNAME ||= hostname();
  my $lock_file = $path.'.lock';
  my $lock_tmp = $lock_file . '.' . $HOSTNAME . '.'. $$;
  my $max_lock_age = 300;	# seconds 
  my $lock_tries = 30;
  my $is_locked = 0;
  my @s;
  $lock_tmp = Mail::SpamAssassin::Util::untaint_file_path ($lock_tmp);

  open(LTMP, ">".$lock_tmp) or
	  die "Cannot create tmp lockfile $lock_tmp for $lock_file: $!\n";
  dbg ("lock: created $lock_tmp");

  my $old_fh = select(LTMP);
  $|=1;
  select($old_fh);

  for (my $i = 0; $i < $lock_tries; $i++) {
    dbg("lock: $$ trying to get lock on $path pass $i");
    print LTMP $HOSTNAME.".$$\n";

    if ( link ($lock_tmp,$lock_file) ) {
      dbg ("lock: link to $lock_file ok");
      $is_locked = 1;
      last;

    } else {
      #link _may_ return false even if the link _is_ created
      if ( (stat($lock_tmp))[3] > 1 ) {
        dbg ("lock: link to $lock_file: stat ok");
        $is_locked = 1;
        last;
      }

      #check to see how old the lockfile is
      @s = stat($lock_file); my $lock_age = ($#s < 11 ? undef : $s[10]);
      @s = stat($lock_tmp);  my $now = ($#s < 11 ? undef : $s[10]);

      if (!defined($lock_age) || $lock_age < $now - $max_lock_age) {
        #we got a stale lock, break it
        dbg("lock: breaking stale lockfile: age=$lock_age now=$now");
        unlink $lock_file;
      }

      sleep(1);
    }
  }

  close(LTMP);
  unlink($lock_tmp);
  dbg ("lock: unlinked $lock_tmp");

  if ($is_locked) {
    return $lock_file;
  } else {
    return undef;
  }
}

###########################################################################

# find an executable in the current $PATH (or whatever for that platform)
sub find_executable_in_env_path {
  my ($filename) = @_;

  Mail::SpamAssassin::Util::clean_path_in_taint_mode();
  foreach my $path (File::Spec->path()) {
    my $fname = File::Spec->catfile ($path, $filename);
    if (-x $fname) {
      dbg ("executable for $filename was found at $fname");
      return $fname;
    }
  }
  return undef;
}

###########################################################################

# taint mode: delete more unsafe vars for exec, as per perlsec
sub clean_path_in_taint_mode {
  return unless am_running_in_taint_mode();

  delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
  $ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';
}

# taint mode: are we running in taint mode? 1 for yes, undef for no.
sub am_running_in_taint_mode {
  if (defined $AM_TAINTED) { return $AM_TAINTED; }
  
  my $blank = substr ($ENV{PATH}, 0, 0);
  $AM_TAINTED = not eval { eval "1 || $blank" || 1 };
  dbg ("running in taint mode? $AM_TAINTED");
  return $AM_TAINTED;
}

###########################################################################

sub am_running_on_windows {
  return RUNNING_ON_WINDOWS;
}

###########################################################################

# untaint a path to a file, e.g. "/home/jm/.spamassassin/foo",
# "C:\Program Files\SpamAssassin\tmp\foo", "/home/õüt/etc".
#
# TODO: this does *not* handle locales well.  We cannot use "use locale"
# and \w, since that will not detaint the data.  So instead just allow the
# high-bit chars from ISO-8859-1, none of which have special metachar
# meanings (as far as I know).
#
sub untaint_file_path {
  my ($path) = @_;
  $path =~ /^([-_A-Za-z\xA0-\xFF 0-9\.\@\=\+\,\/\\\:]+)$/;
  return $1;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
