# A general class for utility functions.  Please use this for
# functions that stand alone, without requiring a $self object,
# Portability functions especially.

package Mail::SpamAssassin::Util;

use strict;
eval "use bytes";

use vars qw (@ISA @EXPORT $HOSTNAME $AM_TAINTED);
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(local_tz);

use Fcntl ':DEFAULT',':flock';
use Mail::SpamAssassin;
use Sys::Hostname;
use File::Spec;
use Time::Local;

use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/oi);

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
  $lock_tmp = untaint_file_path ($lock_tmp);

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
        dbg("lock: breaking stale lockfile: age=".(defined $lock_age?$lock_age:"undef")." now=$now");
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

  clean_path_in_taint_mode();
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
  return unless defined($path);
  $path =~ /^([-_A-Za-z\xA0-\xFF 0-9\.\@\=\+\,\/\\\:]+)$/;
  return $1;
}

###########################################################################

# timezone mappings: in case of conflicts, use RFC 2822, then most
# common and least conflicting mapping
my %TZ = (
	# standard
	'UT'   => '+0000',
	'UTC'  => '+0000',
	# US and Canada
	'AST'  => '-0400',
	'ADT'  => '-0300',
	'EST'  => '-0500',
	'EDT'  => '-0400',
	'CST'  => '-0600',
	'CDT'  => '-0500',
	'MST'  => '-0700',
	'MDT'  => '-0600',
	'PST'  => '-0800',
	'PDT'  => '-0700',
	'HST'  => '-1000',
	'AKST' => '-0900',
	'AKDT' => '-0800',
	# European
	'GMT'  => '+0000',
	'BST'  => '+0100',
	'IST'  => '+0100',
	'WET'  => '+0000',
	'WEST' => '+0100',
	'CET'  => '+0100',
	'CEST' => '+0200',
	'EET'  => '+0200',
	'EEST' => '+0300',
	'MSK'  => '+0300',
	'MSD'  => '+0400',
	# Australian
	'AEST' => '+1000',
	'AEDT' => '+1100',
	'ACST' => '+0930',
	'ACDT' => '+1030',
	'AWST' => '+0800',
	);

sub local_tz {
  # standard method for determining local timezone
  my $time = time;
  my @g = gmtime($time);
  my @t = localtime($time);
  my $z = $t[1]-$g[1]+($t[2]-$g[2])*60+($t[7]-$g[7])*1440+($t[5]-$g[5])*525600;
  return sprintf("%+.2d%.2d", $z/60, $z%60);
}

sub parse_rfc822_date {
  my ($date) = @_;
  local ($_);
  my ($yyyy, $mmm, $dd, $hh, $mm, $ss, $mon, $tzoff);

  # make it a bit easier to match
  $_ = " $date "; s/, */ /gs; s/\s+/ /gs;

  # now match it in parts.  Date part first:
  if (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) / /i) {
    $dd = $1; $mon = $2; $yyyy = $3;
  } elsif (s/ (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(\d+) \d+:\d+:\d+ (\d{4}) / /i) {
    $dd = $2; $mon = $1; $yyyy = $3;
  } elsif (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{2,3}) / /i) {
    $dd = $1; $mon = $2; $yyyy = $3;
  } else {
    dbg ("time cannot be parsed: $date");
    return undef;
  }

  # handle two and three digit dates as specified by RFC 2822
  if (defined $yyyy) {
    if (length($yyyy) == 2 && $yyyy < 50) {
      $yyyy += 2000;
    }
    elsif (length($yyyy) != 4) {
      # three digit years and two digit years with values between 50 and 99
      $yyyy += 1900;
    }
  }

  # hh:mm:ss
  if (s/ (\d?\d):(\d\d)(:(\d\d))? / /) {
    $hh = $1; $mm = $2; $ss = $4 || 0;
  }

  # numeric timezones
  if (s/ ([-+]\d{4}) / /) {
    $tzoff = $1;
  }
  # UT, GMT, and North American timezones
  elsif (s/\b([A-Z]{2,4})\b/ / && exists $TZ{$1}) {
    $tzoff = $TZ{$1};
  }
  # all other timezones are considered equivalent to "-0000"
  $tzoff ||= '-0000';

  if (!defined $mmm && defined $mon) {
    my @months = qw(jan feb mar apr may jun jul aug sep oct nov dec);
    $mon = lc($mon);
    my $i; for ($i = 0; $i < 12; $i++) {
      if ($mon eq $months[$i]) { $mmm = $i+1; last; }
    }
  }

  $hh ||= 0; $mm ||= 0; $ss ||= 0; $dd ||= 0; $mmm ||= 0; $yyyy ||= 0;

  my $time;
  eval {		# could croak
    $time = timegm ($ss, $mm, $hh, $dd, $mmm-1, $yyyy);
  };

  if ($@) {
    dbg ("time cannot be parsed: $date, $yyyy-$mmm-$dd $hh:$mm:$ss");
    return undef;
  }

  if ($tzoff =~ /([-+])(\d\d)(\d\d)$/)	# convert to seconds difference
  {
    $tzoff = (($2 * 60) + $3) * 60;
    if ($1 eq '-') {
      $time += $tzoff;
    } else {
      $time -= $tzoff;
    }
  }

  return $time;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
