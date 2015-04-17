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

=head1 NAME

Mail::SpamAssassin::Util - utility functions

=head1 DESCRIPTION

A general class for utility functions.  Please use this for functions that
stand alone, without requiring a $self object, Portability functions
especially.

NOTE: The functions in this module are to be considered private.  Their API may
change at any point, and it's expected that they'll only be used by other
Mail::SpamAssassin modules. (TODO: we should probably revisit this if
it's useful for plugin development.)

NOTE: Utility functions should not be changing global variables such
as $_, $1, $2, ... $/, etc. unless explicitly documented.  If these
variables are in use by these functions, they should be localized.

=over 4

=cut

package Mail::SpamAssassin::Util;

use strict;
use warnings;
use bytes;
use re 'taint';

require 5.008001;  # needs utf8::is_utf8()

use Mail::SpamAssassin::Logger;

BEGIN {
  use Exporter ();

  use vars qw (
    @ISA @EXPORT @EXPORT_OK
    $AM_TAINTED
  );

  @ISA = qw(Exporter);
  @EXPORT = ();
  @EXPORT_OK = qw(&local_tz &base64_decode &untaint_var &untaint_file_path
                  &exit_status_str &proc_status_ok &am_running_on_windows
                  &reverse_ip_address &decode_dns_question_entry
                  &secure_tmpfile &secure_tmpdir &uri_list_canonicalize);
}

use Mail::SpamAssassin;

use Config;
use IO::Handle;
use File::Spec;
use File::Basename;
use Time::Local;
use Sys::Hostname (); # don't import hostname() into this namespace!
use NetAddr::IP 4.000;
use Fcntl;
use Errno qw(ENOENT EACCES EEXIST);
use POSIX qw(:sys_wait_h WIFEXITED WIFSIGNALED WIFSTOPPED WEXITSTATUS
             WTERMSIG WSTOPSIG);

###########################################################################

use constant HAS_MIME_BASE64 => eval { require MIME::Base64; };
use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/oi);

# These are not implemented on windows (see bug 6798 and 6470)
BEGIN {
  if (RUNNING_ON_WINDOWS) {
    *WIFEXITED   = sub { not $_[0] & 127 };
    *WEXITSTATUS = sub { $_[0] >> 8 };
    *WIFSIGNALED = sub { ($_[0] & 127) && ($_[0] & 127 != 127) };
    *WTERMSIG    = sub { $_[0] & 127 };
  }
}

###########################################################################

# find an executable in the current $PATH (or whatever for that platform)
{
  # Show the PATH we're going to explore only once.
  my $displayed_path = 0;

  sub find_executable_in_env_path {
    my ($filename) = @_;

    clean_path_in_taint_mode();
    if ( !$displayed_path++ ) {
      dbg("util: current PATH is: ".join($Config{'path_sep'},File::Spec->path()));
    }
    foreach my $path (File::Spec->path()) {
      my $fname = File::Spec->catfile ($path, $filename);
      if ( -f $fname ) {
        if (-x $fname) {
          dbg("util: executable for $filename was found at $fname");
          return $fname;
        }
        else {
          dbg("util: $filename was found at $fname, but isn't executable");
        }
      }
    }
    return;
  }
}

###########################################################################

# taint mode: delete more unsafe vars for exec, as per perlsec
{
  # We only need to clean the environment once, it stays clean ...
  my $cleaned_taint_path = 0;

  sub clean_path_in_taint_mode {
    return if ($cleaned_taint_path++);
    return unless am_running_in_taint_mode();

    dbg("util: taint mode: deleting unsafe environment variables, resetting PATH");

    if (RUNNING_ON_WINDOWS) {
      dbg("util: running on Win32, skipping PATH cleaning");
      return;
    }

    delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

    # Go through and clean the PATH out
    my @path;
    my @stat;
    foreach my $dir (File::Spec->path()) {
      next unless $dir;

      # untaint if at least 1 char and no NL (is the restriction intentional?)
      local ($1);
      $dir = untaint_var($1)  if $dir =~ /^(.+)$/;
      # then clean ( 'foo/./bar' -> 'foo/bar', etc. )
      $dir = File::Spec->canonpath($dir);

      if (!File::Spec->file_name_is_absolute($dir)) {
	dbg("util: PATH included '$dir', which is not absolute, dropping");
	next;
      }
      elsif (!(@stat=stat($dir))) {
	dbg("util: PATH included '$dir', which is unusable, dropping: $!");
	next;
      }
      elsif (!-d _) {
	dbg("util: PATH included '$dir', which isn't a directory, dropping");
	next;
      }
      elsif (($stat[2]&2) != 0) {
        # World-Writable directories are considered insecure.
        # We could be more paranoid and check all of the parent directories as well,
        # but it's good for now.
	dbg("util: PATH included '$dir', which is world writable, dropping");
	next;
      }

      dbg("util: PATH included '$dir', keeping");
      push(@path, $dir);
    }

    $ENV{'PATH'} = join($Config{'path_sep'}, @path);
    dbg("util: final PATH set to: ".$ENV{'PATH'});
  }
}

# taint mode: are we running in taint mode? 1 for yes, 0 for no.
sub am_running_in_taint_mode {
  return $AM_TAINTED if defined $AM_TAINTED;

  if ($] >= 5.008) {
    # perl 5.8 and above, ${^TAINT} is a syntax violation in 5.005
    $AM_TAINTED = eval q(no warnings q(syntax); ${^TAINT});
  }
  else {
    # older versions
    my $blank;
    for my $d ((File::Spec->curdir, File::Spec->rootdir, File::Spec->tmpdir)) {
      opendir(TAINT, $d) || next;
      $blank = readdir(TAINT);
      closedir(TAINT)  or die "error closing directory $d: $!";
      last;
    }
    if (!(defined $blank && $blank)) {
      # these are sometimes untainted, so this is less preferable than readdir
      $blank = join('', values %ENV, $0, @ARGV);
    }
    $blank = substr($blank, 0, 0);
    # seriously mind-bending perl
    $AM_TAINTED = not eval { eval "1 || $blank" || 1 };
  }
  dbg("util: running in taint mode? %s", $AM_TAINTED ? "yes" : "no");
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
  return '' if ($path eq '');

  local ($1);
  # Barry Jaspan: allow ~ and spaces, good for Windows.  Also return ''
  # if input is '', as it is a safe path.
  my $chars = '-_A-Za-z0-9\xA0-\xFF\.\%\@\=\+\,\/\\\:';
  my $re = qr/^\s*([$chars][${chars}~ ]*)$/o;

  if ($path =~ $re) {
    $path = $1;
    return untaint_var($path);
  } else {
    warn "util: refusing to untaint suspicious path: \"$path\"\n";
    return $path;
  }
}

sub untaint_hostname {
  my ($host) = @_;

  return unless defined($host);
  return '' if ($host eq '');

  # from RFC 1035, but allowing domains starting with numbers:
  #   $label = q/[A-Za-z\d](?:[A-Za-z\d-]{0,61}[A-Za-z\d])?/;
  #   $domain = qq<$label(?:\.$label)*>;
  #   length($host) <= 255 && $host =~ /^($domain)$/
  # expanded (no variables in the re) because of a tainting bug in Perl 5.8.0
  if (length($host) <= 255 && $host =~ /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)*$/i) {
    return untaint_var($host);
  }
  else {
    warn "util: cannot untaint hostname: \"$host\"\n";
    return $host;
  }
}

# This sub takes a scalar or a reference to an array, hash, scalar or another
# reference and recursively untaints all its values (and keys if it's a
# reference to a hash). It should be used with caution as blindly untainting
# values subverts the purpose of working in taint mode. It will return the
# untainted value if requested but to avoid unnecessary copying, the return
# value should be ignored when working on lists.
# Bad:
#  %ENV = untaint_var(\%ENV);
# Better:
#  untaint_var(\%ENV);
#
sub untaint_var {
# my $arg = $_[0];  # avoid copying unnecessarily
  if (!ref $_[0]) { # optimized by-far-the-most-common case
    no re 'taint';  # override a  "use re 'taint'"  from outer scope
    return undef if !defined $_[0]; ## no critic (ProhibitExplicitReturnUndef)  - See Bug 7120
    local($1); # avoid Perl taint bug: tainted global $1 propagates taintedness
    $_[0] =~ /^(.*)\z/s;
    return $1;
  } else {
    my $r = ref $_[0];
    if ($r eq 'ARRAY') {
      my $arg = $_[0];
      $_ = untaint_var($_)  for @{$arg};
      return @{$arg} if wantarray;
    }
    elsif ($r eq 'HASH') {
      my $arg = $_[0];
      if ($arg == \%ENV) {  # purge undefs from %ENV, untaint the rest
        while (my($k, $v) = each %{$arg}) {
          # It is safe to delete the item most recently returned by each()
          if (!defined $v) { delete ${$arg}{$k}; next }
          ${$arg}{untaint_var($k)} = untaint_var($v);
        }
      } else {
        # hash keys are never tainted,
        # although old version of perl had some quirks there
        while (my($k, $v) = each %{$arg}) {
          ${$arg}{untaint_var($k)} = untaint_var($v);
        }
      }
      return %{$arg} if wantarray;
    }
    elsif ($r eq 'SCALAR' || $r eq 'REF') {
      my $arg = $_[0];
      ${$arg} = untaint_var(${$arg});
    }
    else {
      warn "util: can't untaint a $r !\n";
    }
  }
  return $_[0];
}

###########################################################################

sub taint_var {
  my ($v) = @_;
  return $v unless defined $v;      # can't taint "undef"

  # $^X is apparently "always tainted".
  # Concatenating an empty tainted string taints the result.
  return $v . substr($^X, 0, 0);
}

###########################################################################

# map process termination status number to an informative string, and
# append optional mesage (dual-valued errno or a string or a number),
# returning the resulting string
#
sub exit_status_str {
  my($stat,$errno) = @_;
  my $str;
  if (!defined($stat)) {
    $str = '(no status)';
  } elsif (WIFEXITED($stat)) {
    $str = sprintf("exit %d", WEXITSTATUS($stat));
  } elsif (WIFSTOPPED($stat)) {
    $str = sprintf("stopped, signal %d", WSTOPSIG($stat));
  } else {
    my $sig = WTERMSIG($stat);
    $str = sprintf("%s, signal %d (%04x)",
             $sig == 1 ? 'HANGUP' : $sig == 2 ? 'interrupted' :
             $sig == 6 ? 'ABORTED' : $sig == 9 ? 'KILLED' :
             $sig == 15 ? 'TERMINATED' : 'DIED',
             $sig, $stat);
  }
  if (defined $errno) {  # deal with dual-valued and plain variables
    $str .= ', '.$errno  if (0+$errno) != 0 || ($errno ne '' && $errno ne '0');
  }
  return $str;
}

###########################################################################

# check errno to be 0 and a process exit status to be in the list of success
# status codes, returning true if both are ok, and false otherwise
#
sub proc_status_ok {
  my($exit_status,$errno,@success) = @_;
  my $ok = 0;
  if ((!defined $errno || $errno == 0) && WIFEXITED($exit_status)) {
    my $j = WEXITSTATUS($exit_status);
    if (!@success) { $ok = $j==0 }  # empty list implies only status 0 is good
    elsif (grep {$_ == $j} @success) { $ok = 1 }
  }
  return $ok;
}

###########################################################################

# timezone mappings: in case of conflicts, use RFC 2822, then most
# common and least conflicting mapping
my %TZ = (
	# standard
	'UT'   => '+0000',
	'UTC'  => '+0000',
	# US and Canada
	'NDT'  => '-0230',
	'AST'  => '-0400',
	'ADT'  => '-0300',
	'NST'  => '-0330',
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
	'HADT' => '-0900',
	'HAST' => '-1000',
	# Europe
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
	'MET'  => '+0100',
	'MEZ'  => '+0100',
	'MEST' => '+0200',
	'MESZ' => '+0200',
	# South America
	'BRST' => '-0200',
	'BRT'  => '-0300',
	# Australia
	'AEST' => '+1000',
	'AEDT' => '+1100',
	'ACST' => '+0930',
	'ACDT' => '+1030',
	'AWST' => '+0800',
	# New Zealand
	'NZST' => '+1200',
	'NZDT' => '+1300',
	# Asia
	'JST'  => '+0900',
	'KST'  => '+0900',
	'HKT'  => '+0800',
	'SGT'  => '+0800',
	'PHT'  => '+0800',
	# Middle East
	'IDT'  => '+0300',
	);

# month mappings
my %MONTH = (jan => 1, feb => 2, mar => 3, apr => 4, may => 5, jun => 6,
	     jul => 7, aug => 8, sep => 9, oct => 10, nov => 11, dec => 12);

my $LOCALTZ;

sub local_tz {
  return $LOCALTZ if defined($LOCALTZ);

  # standard method for determining local timezone
  my $time = time;
  my @g = gmtime($time);
  my @t = localtime($time);
  my $z = $t[1]-$g[1]+($t[2]-$g[2])*60+($t[7]-$g[7])*1440+($t[5]-$g[5])*525600;
  $LOCALTZ = sprintf("%+.2d%.2d", $z/60, $z%60);
  return $LOCALTZ;
}

sub parse_rfc822_date {
  my ($date) = @_;
  local ($_); local ($1,$2,$3,$4);
  my ($yyyy, $mmm, $dd, $hh, $mm, $ss, $mon, $tzoff);

  # make it a bit easier to match
  $_ = " $date "; s/, */ /gs; s/\s+/ /gs;

  # now match it in parts.  Date part first:
  if (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) / /i) {
    $dd = $1; $mon = lc($2); $yyyy = $3;
  } elsif (s/ (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +(\d+) \d+:\d+:\d+ (\d{4}) / /i) {
    $dd = $2; $mon = lc($1); $yyyy = $3;
  } elsif (s/ (\d+) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{2,3}) / /i) {
    $dd = $1; $mon = lc($2); $yyyy = $3;
  } else {
    dbg("util: time cannot be parsed: $date");
    return;
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
  # common timezones
  elsif (s/\b([A-Z]{2,4}(?:-DST)?)\b/ / && exists $TZ{$1}) {
    $tzoff = $TZ{$1};
  }
  # all other timezones are considered equivalent to "-0000"
  $tzoff ||= '-0000';

  # months
  if (exists $MONTH{$mon}) {
    $mmm = $MONTH{$mon};
  }

  $hh ||= 0; $mm ||= 0; $ss ||= 0; $dd ||= 0; $mmm ||= 0; $yyyy ||= 0;

  # Fudge invalid times so that we get a usable date.
  if ($ss > 59) {  # rfc2822 does recognize leap seconds, not handled here
    dbg("util: second after supported range, forcing second to 59: $date");  
    $ss = 59;
  } 

  if ($mm > 59) { 
    dbg("util: minute after supported range, forcing minute to 59: $date");
    $mm = 59;
  }

  if ($hh > 23) { 
    dbg("util: hour after supported range, forcing hour to 23: $date"); 
    $hh = 23;
  }

  my $max_dd = 31;
  if ($mmm == 4 || $mmm == 6 || $mmm == 9 || $mmm == 11) {
    $max_dd = 30;
  }
  elsif ($mmm == 2) {
    $max_dd = (!($yyyy % 4) && (($yyyy % 100) || !($yyyy % 400))) ? 29 : 28;
  }
  if ($dd > $max_dd) {
    dbg("util: day is too high, incrementing date to next valid date: $date");
    $dd = 1;
    $mmm++;
    if ($mmm > 12) {
      $mmm = 1;
      $yyyy++;
    }
  }

  # Time::Local (v1.10 at least, also 1.17) throws warnings when dates cause
  # a signed 32-bit integer overflow.  So force a min/max for year.
  if ($yyyy > 2037) {
    dbg("util: year after supported range, forcing year to 2037: $date");
    $yyyy = 2037;
  }
  elsif ($yyyy < 1970) {
    dbg("util: year before supported range, forcing year to 1970: $date");
    $yyyy = 1970;
  }

  my $time;
  eval {		# could croak
    $time = timegm($ss, $mm, $hh, $dd, $mmm-1, $yyyy);
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("util: time cannot be parsed: $date, $yyyy-$mmm-$dd $hh:$mm:$ss, $eval_stat");
    return;
  };

  if ($tzoff =~ /([-+])(\d\d)(\d\d)$/)	# convert to seconds difference
  {
    $tzoff = (($2 * 60) + $3) * 60;
    if ($1 eq '-') {
      $time += $tzoff;
    } elsif ($time < $tzoff) {  # careful with year 1970 and '+' time zones
      $time = 0;
    } else {
      $time -= $tzoff;
    }
  }

  return $time;
}

sub time_to_rfc822_date {
  my($time) = @_;

  my @days = qw/Sun Mon Tue Wed Thu Fri Sat/;
  my @months = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
  my @localtime = localtime($time || time);
  $localtime[5]+=1900;

  sprintf("%s, %02d %s %4d %02d:%02d:%02d %s", $days[$localtime[6]], $localtime[3],
    $months[$localtime[4]], @localtime[5,2,1,0], local_tz());
}

###########################################################################

# This used to be a wrapper for Text::Wrap.  Now we do basically the same
# function as Text::Wrap::wrap().  See bug 5056 and 2165 for more information
# about why things aren't using that function anymore.
#
# It accepts values for almost all options which can be set
# in Text::Wrap.   All parameters are optional (leaving away the first one 
# probably doesn't make too much sense though), either a missing or a false
# value will fall back to the default.
# 
# The parameters are:
#  1st:  The string to wrap.  Only one string is allowed.
#                                             (default: "")
#  2nd:  The prefix to be put in front of all lines except the first one. 
#                                             (default: "")
#  3rd:  The prefix for the first line.       (default:  "")
#  4th:  The number of columns available (no line will be longer than this
#        unless overflow is set below).       (default:  77)
#  5th:  Enable or disable overflow mode.     (default: 0)
#  6th:  The sequence/expression to wrap at.  (default: '\s');
#  7th:  The string to join the lines again.  (default: "\n")

sub wrap {
  my $string   = shift || '';
  my $prefix   = shift || '';
  my $first    = shift || '';
  my $length   = shift || 77;
  my $overflow = shift || 0;
  my $break    = shift || qr/\s/;
  my $sep      = "\n";

  # go ahead and break apart the string, keeping the break chars
  my @arr = split(/($break)/, $string);

  # tack the first prefix line at the start
  splice @arr, 0, 0, $first if $first;

  # go ahead and make up the lines in the array
  my $pos = 0;
  my $pos_mod = 0;
  while ($#arr > $pos) {
    my $len = length $arr[$pos];

    # if we don't want to have lines > $length (overflow==0), we
    # need to verify what will happen with the next line.  if we don't
    # care if a single line goes longer, don't care about the next
    # line.
    # we also want this to be true for the first entry on the line
    if ($pos_mod != 0 && $overflow == 0) {
      $len += length $arr[$pos+1];
    }

    if ($len <= $length) {
      # if the length determined above is within bounds, go ahead and
      # merge the next line with the current one
      $arr[$pos] .= splice @arr, $pos+1, 1;
      $pos_mod = 1;
    }
    else {
      # ok, the current line is the right length, but there's more text!
      # prep the current line and then go onto the next one

      # strip any trailing whitespace from the next line that's ready
      $arr[$pos] =~ s/\s+$//;

      # go to the next line and reset pos_mod
      $pos++;
      $pos_mod = 0;

      # put the appropriate prefix at the front of the line
      splice @arr, $pos, 0, $prefix;
    }
  }

  # go ahead and return the wrapped text, with the separator in between
  return join($sep, @arr);
}

###########################################################################

# Some base64 decoders will remove intermediate "=" characters, others
# will stop decoding on the first "=" character, this one translates "="
# characters to null.
sub base64_decode {
  local $_ = shift;
  my $decoded_length = shift;

  s/\s+//g;
  if (HAS_MIME_BASE64 && (length($_) % 4 == 0) &&
      m|^(?:[A-Za-z0-9+/=]{2,}={0,2})$|s)
  {
    # only use MIME::Base64 when the XS and Perl are both correct and quiet
    s/(=+)(?!=*$)/'A' x length($1)/ge;

    # If only a certain number of bytes are requested, truncate the encoded
    # version down to the appropriate size and return the requested bytes
    if (defined $decoded_length) {
      $_ = substr $_, 0, 4 * (int($decoded_length/3) + 1);
      my $decoded = MIME::Base64::decode_base64($_);
      return substr $decoded, 0, $decoded_length;
    }

    # otherwise, just decode the whole thing and return it
    return MIME::Base64::decode_base64($_);
  }
  tr{A-Za-z0-9+/=}{}cd;			# remove non-base64 characters
  s/=+$//;				# remove terminating padding
  tr{A-Za-z0-9+/=}{ -_`};		# translate to uuencode
  s/.$// if (length($_) % 4 == 1);	# unpack cannot cope with extra byte

  my $length;
  my $out = '';
  while ($_) {
    $length = (length >= 84) ? 84 : length;
    $out .= unpack("u", chr(32 + $length * 3/4) . substr($_, 0, $length, ''));
    last if (defined $decoded_length && length $out >= $decoded_length);
  }

  # If only a certain number of bytes are requested, truncate the encoded
  # version down to the appropriate size and return the requested bytes
  if (defined $decoded_length) {
    return substr $out, 0, $decoded_length;
  }

  return $out;
}

sub qp_decode {
  local $_ = shift;

  # RFC 2045: when decoding a Quoted-Printable body, any trailing
  # white space on a line must be deleted
  s/[ \t]+(?=\r?\n)//gs;

  s/=\r?\n//gs;  # soft line breaks

  # RFC 2045 explicitly prohibits lowercase characters a-f in QP encoding
  # do we really want to allow them???
  s/=([0-9a-fA-F]{2})/chr(hex($1))/ge;

  return $_;
}

sub base64_encode {
  local $_ = shift;

  if (HAS_MIME_BASE64) {
    return MIME::Base64::encode_base64($_);
  }

  $_ = pack("u57", $_);
  s/^.//mg;
  tr| -_`|A-Za-z0-9+/A|; # -> #`# <- kluge against vim syntax issues
  s/(A+)$/'=' x length $1/e;
  return $_;
}

###########################################################################

sub portable_getpwuid {
  if (defined &Mail::SpamAssassin::Util::_getpwuid_wrapper) {
    return Mail::SpamAssassin::Util::_getpwuid_wrapper(@_);
  }

  my $sts;
  if (!RUNNING_ON_WINDOWS) {
    $sts = eval ' sub _getpwuid_wrapper { getpwuid($_[0]); }; 1 ';
  } else {
    dbg("util: defining getpwuid() wrapper using 'unknown' as username");
    $sts = eval ' sub _getpwuid_wrapper { _fake_getpwuid($_[0]); }; 1 ';
  }
  if (!$sts) {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "util: failed to define getpwuid() wrapper: $eval_stat\n";
  } else {
    return Mail::SpamAssassin::Util::_getpwuid_wrapper(@_);
  }
}

sub _fake_getpwuid {
  return (
    'unknown',		# name,
    'x',		# passwd,
    $_[0],		# uid,
    0,			# gid,
    '',			# quota,
    '',			# comment,
    '',			# gcos,
    '/',		# dir,
    '',			# shell,
    '',			# expire
  );
}

###########################################################################

# Given a string, extract an IPv4 address from it.  Required, since
# we currently have no way to portably unmarshal an IPv4 address from
# an IPv6 one without kludging elsewhere.
#
sub extract_ipv4_addr_from_string {
  my ($str) = @_;

  return unless defined($str);

  if ($str =~ /\b(
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)\.
			(?:1\d\d|2[0-4]\d|25[0-5]|\d\d|\d)
		      )\b/ix)
  {
    if (defined $1) { return $1; }
  }

  # ignore native IPv6 addresses;
  # TODO, eventually, once IPv6 spam starts to appear ;)
  return;
}

###########################################################################

{
  my($hostname, $fq_hostname);

# get the current host's unqalified domain name (better: return whatever
# Sys::Hostname thinks our hostname is, might also be a full qualified one)
  sub hostname {
    return $hostname if defined($hostname);

    # Sys::Hostname isn't taint safe and might fall back to `hostname`. So we've
    # got to clean PATH before we may call it.
    clean_path_in_taint_mode();
    $hostname = Sys::Hostname::hostname();
    $hostname =~ s/[()]//gs;            # bug 5929
    return $hostname;
  }

# get the current host's fully-qualified domain name, if possible.  If
# not possible, return the unqualified hostname.
  sub fq_hostname {
    return $fq_hostname if defined($fq_hostname);

    $fq_hostname = hostname();
    if ($fq_hostname !~ /\./) { # hostname doesn't contain a dot, so it can't be a FQDN
      my @names = grep(/^\Q${fq_hostname}.\E/o,                         # grep only FQDNs
                    map { split } (gethostbyname($fq_hostname))[0 .. 1] # from all aliases
                  );
      $fq_hostname = $names[0] if (@names); # take the first FQDN, if any 
      $fq_hostname =~ s/[()]//gs;       # bug 5929
    }

    return $fq_hostname;
  }
}

###########################################################################

sub ips_match_in_16_mask {
  my ($ipset1, $ipset2) = @_;
  my ($b1, $b2);

  foreach my $ip1 (@{$ipset1}) {
    foreach my $ip2 (@{$ipset2}) {
      next unless defined $ip1;
      next unless defined $ip2;
      next unless ($ip1 =~ /^(\d+\.\d+\.)/); $b1 = $1;
      next unless ($ip2 =~ /^(\d+\.\d+\.)/); $b2 = $1;
      if ($b1 eq $b2) { return 1; }
    }
  }

  return 0;
}

sub ips_match_in_24_mask {
  my ($ipset1, $ipset2) = @_;
  my ($b1, $b2);

  foreach my $ip1 (@{$ipset1}) {
    foreach my $ip2 (@{$ipset2}) {
      next unless defined $ip1;
      next unless defined $ip2;
      next unless ($ip1 =~ /^(\d+\.\d+\.\d+\.)/); $b1 = $1;
      next unless ($ip2 =~ /^(\d+\.\d+\.\d+\.)/); $b2 = $1;
      if ($b1 eq $b2) { return 1; }
    }
  }

  return 0;
}

###########################################################################

# Given a quad-dotted IPv4 address or an IPv6 address, reverses the order
# of its bytes (IPv4) or nibbles (IPv6), joins them with dots, producing
# a string suitable for reverse DNS lookups. Returns undef in case of a
# syntactically invalid IP address.
#
sub reverse_ip_address {
  my ($ip) = @_;

  my $revip;
  local($1,$2,$3,$4);
  if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\z/) {
    $revip = "$4.$3.$2.$1";
  } elsif ($ip !~ /:/ || $ip !~ /^[0-9a-fA-F:.]{2,}\z/) {  # triage
    # obviously unrecognized syntax
  } elsif (!NetAddr::IP->can('full6')) {  # since NetAddr::IP 4.010
    info("util: version of NetAddr::IP is too old, IPv6 not supported");
  } else {
    # looks like an IPv6 address, let NetAddr::IP check the details
    my $ip_obj = NetAddr::IP->new6($ip);
    if (defined $ip_obj) {  # valid IPv6 address
      # RFC 5782 section 2.4.
      $revip = lc $ip_obj->network->full6;  # string in a canonical form
      $revip =~ s/://g;
      $revip = join('.', reverse split(//,$revip));
    }
  }
  return $revip;
}

###########################################################################

sub my_inet_aton { unpack("N", pack("C4", split(/\./, $_[0]))) }

###########################################################################

sub decode_dns_question_entry {
  # decodes a Net::DNS::Packet->question entry,
  # returning a triple: class, type, label
  #
  my $q = $_[0];
  my $qname = $q->qname;

  # Bug 6959, Net::DNS flags a domain name in a query section as utf8, while
  # still keeping it "RFC 1035 zone file format"-encoded, silly and harmful
  utf8::encode($qname) if utf8::is_utf8($qname);  # since Perl 5.8.1

  local $1;
  # Net::DNS provides a query in encoded RFC 1035 zone file format, decode it!
  $qname =~ s{ \\ ( [0-9]{3} | [^0-9] ) }
             { length($1)==1 ? $1 : $1 <= 255 ? chr($1) : "\\$1" }xgse;
  return ($q->qclass, $q->qtype, $qname);
}

###########################################################################

sub parse_content_type {
  # This routine is typically called by passing a
  # get_header("content-type") which passes all content-type headers
  # (array context).  If there are multiple Content-type headers (invalid,
  # but it happens), MUAs seem to take the last one and so that's what we
  # should do here.
  #
  my $ct = $_[-1] || 'text/plain; charset=us-ascii';

  # This could be made a bit more rigid ...
  # the actual ABNF, BTW (RFC 1521, section 7.2.1):
  # boundary := 0*69<bchars> bcharsnospace
  # bchars := bcharsnospace / " "
  # bcharsnospace :=    DIGIT / ALPHA / "'" / "(" / ")" / "+" /"_"
  #               / "," / "-" / "." / "/" / ":" / "=" / "?"
  #
  # The boundary may be surrounded by double quotes.
  # "the boundary parameter, which consists of 1 to 70 characters from
  # a set of characters known to be very robust through email gateways,
  # and NOT ending with white space.  (If a boundary appears to end with
  # white space, the white space must be presumed to have been added by
  # a gateway, and must be deleted.)"
  #
  # In practice:
  # - MUAs accept whitespace before and after the "=" character
  # - only an opening double quote seems to be needed
  # - non-quoted boundaries should be followed by space, ";", or end of line
  # - blank boundaries seem to not work
  #
  my($boundary) = $ct =~ m!\bboundary\s*=\s*("[^"]+|[^\s";]+(?=[\s;]|$))!i;

  # remove double-quotes in boundary (should only be at start and end)
  #
  $boundary =~ tr/"//d if defined $boundary;

  # Parse out the charset and name, if they exist.
  #
  my($charset) = $ct =~ /\bcharset\s*=\s*["']?(.*?)["']?(?:;|$)/i;
  my($name) = $ct =~ /\b(?:file)?name\s*=\s*["']?(.*?)["']?(?:;|$)/i;

  # Get the actual MIME type out ...
  # Note: the header content may not be whitespace unfolded, so make sure the
  # REs do /s when appropriate.
  # correct:
  # Content-type: text/plain; charset=us-ascii
  # missing a semi-colon, CT shouldn't have whitespace anyway:
  # Content-type: text/plain charset=us-ascii
  #
  $ct =~ s/^\s+//;				# strip leading whitespace
  $ct =~ s/;.*$//s;				# strip everything after first ';'
  $ct =~ s@^([^/]+(?:/[^/\s]*)?).*$@$1@s;	# only something/something ...
  $ct = lc $ct;

  # bug 4298: If at this point we don't have a content-type, assume text/plain;
  # also, bug 5399: if the content-type *starts* with "text", and isn't in a 
  # list of known bad/non-plain formats, do likewise.
  if (!$ct ||
        ($ct =~ /^text\b/ && $ct !~ /^text\/(?:x-vcard|calendar|html)$/))
  {
    $ct = "text/plain";
  }

  # strip inappropriate chars (bug 5399: after the text/plain fixup)
  $ct =~ tr/\000-\040\177-\377\042\050\051\054\072-\077\100\133-\135//d;

  # Now that the header has been parsed, return the requested information.
  # In scalar context, just the MIME type, in array context the
  # four important data parts (type, boundary, charset, and filename).
  #
  return wantarray ? ($ct,$boundary,$charset,$name) : $ct;
}

###########################################################################

sub url_encode {
  my ($url) = @_;
  my (@characters) = split(/(\%[0-9a-fA-F]{2})/, $url);
  my (@unencoded);
  my (@encoded);

  foreach (@characters) {
    # escaped character set ...
    if (/\%[0-9a-fA-F]{2}/) {
      # IF it is in the range of 0x00-0x20 or 0x7f-0xff
      #    or it is one of  "<", ">", """, "#", "%",
      #                     ";", "/", "?", ":", "@", "=" or "&"
      # THEN preserve its encoding
      unless (/(20|7f|[0189a-fA-F][0-9a-fA-F])/i) {
	s/\%([2-7][0-9a-fA-F])/sprintf "%c", hex($1)/e;
	push(@unencoded, $_);
      }
    }
    # other stuff
    else {
      # no re "strict";  # since perl 5.21.8
      # 0x00-0x20, 0x7f-0xff, ", %, <, >
      s/([\000-\040\177-\377\042\045\074\076])
	  /push(@encoded, $1) && sprintf "%%%02x", unpack("C",$1)/egx;
    }
  }
  if (wantarray) {
    return(join("", @characters), join("", @unencoded), join("", @encoded));
  }
  else {
    return join("", @characters);
  }
}

###########################################################################

=item $module = first_available_module (@module_list)

Return the name of the first module that can be successfully loaded with
C<require> from the list.  Returns C<undef> if none are available.

This is used instead of C<AnyDBM_File> as follows:

  my $module = Mail::SpamAssassin::Util::first_available_module
                        (qw(DB_File GDBM_File NDBM_File SDBM_File));
  tie %hash, $module, $path, [... args];

Note that C<SDBM_File> is guaranteed to be present, since it comes
with Perl.

=cut

sub first_available_module {
  my (@packages) = @_;
  foreach my $mod (@packages) {
    if (eval 'require '.$mod.'; 1; ') {
      return $mod;
    }
  }
  undef;
}

###########################################################################

=item my ($filepath, $filehandle) = secure_tmpfile();

Generates a filename for a temporary file, opens it exclusively and
securely, and returns a filehandle to the open file (opened O_RDWR).

If it cannot open a file after 20 tries, it returns C<undef>.

=cut

# thanks to http://www2.picante.com:81/~gtaylor/autobuse/ for this code
sub secure_tmpfile {
  my $tmpdir = untaint_file_path($ENV{'TMPDIR'} || File::Spec->tmpdir());

  defined $tmpdir && $tmpdir ne ''
    or die "util: cannot find a temporary directory, set TMP or TMPDIR in environment";

  opendir(my $dh, $tmpdir) or die "Could not open directory $tmpdir: $!";
  closedir $dh or die "Error closing directory $tmpdir: $!";

  my ($reportfile, $tmpfh);
  for (my $retries = 20; $retries > 0; $retries--) {
    # we do not rely on the obscurity of this name for security,
    # we use a average-quality PRG since this is all we need
    my $suffix = join('', (0..9,'A'..'Z','a'..'z')[rand 62, rand 62, rand 62,
						   rand 62, rand 62, rand 62]);
    $reportfile = File::Spec->catfile($tmpdir,".spamassassin${$}${suffix}tmp");

    # instead, we require O_EXCL|O_CREAT to guarantee us proper
    # ownership of our file, read the open(2) man page
    if (sysopen($tmpfh, $reportfile, O_RDWR|O_CREAT|O_EXCL, 0600)) {
      binmode $tmpfh  or die "cannot set $reportfile to binmode: $!";
      last;
    }
    my $errno = $!;

    # ensure the file handle is not semi-open in some way
    if ($tmpfh) {
      if (! close $tmpfh) {
       info("error closing $reportfile: $!");
       undef $tmpfh;
      }
    }

    # it is acceptable if $tmpfh already exists, try another
    next if $errno == EEXIST;

    # error, maybe "out of quota", "too many open files", "Permission denied"
    # (bug 4017); makes no sense retrying
    die "util: failed to create a temporary file '$reportfile': $errno";
  }

  if (!$tmpfh) {
    warn "util: secure_tmpfile failed to create a temporary file, giving up";
    return;
  }

  dbg("util: secure_tmpfile created a temporary file %s", $reportfile);
  return ($reportfile, $tmpfh);
}

=item my ($dirpath) = secure_tmpdir();

Generates a directory for temporary files.  Creates it securely and
returns the path to the directory.

If it cannot create a directory after 20 tries, it returns C<undef>.

=cut

# stolen from secure_tmpfile()
sub secure_tmpdir {
  my $tmpdir = untaint_file_path(File::Spec->tmpdir());

  if (!$tmpdir) {
    # Note: we would prefer to keep this fatal, as not being able to
    # find a writable tmpdir is a big deal for the calling code too.
    # That would be quite a psychotic case, also.
    warn "util: cannot find a temporary directory, set TMP or TMPDIR in environment";
    return;
  }

  my ($reportpath, $tmppath);
  my $umask = umask 077;

  for (my $retries = 20; $retries > 0; $retries--) {
    # we do not rely on the obscurity of this name for security,
    # we use a average-quality PRG since this is all we need
    my $suffix = join('', (0..9,'A'..'Z','a'..'z')[rand 62, rand 62, rand 62,
						   rand 62, rand 62, rand 62]);
    $reportpath = File::Spec->catfile($tmpdir,".spamassassin${$}${suffix}tmp");

    # instead, we require O_EXCL|O_CREAT to guarantee us proper
    # ownership of our file, read the open(2) man page
    if (mkdir $reportpath, 0700) {
      $tmppath = $reportpath;
      last;
    }

    if ($!{EEXIST}) {
      # it is acceptable if $reportpath already exists, try another
      next;
    }
    
    # error, maybe "out of quota" or "too many open files" (bug 4017)
    warn "util: secure_tmpdir failed to create file '$reportpath': $!\n";
  }

  umask $umask;

  warn "util: secure_tmpdir failed to create a directory, giving up" if (!$tmppath);

  return $tmppath;
}


###########################################################################

##
## DEPRECATED FUNCTION, only left for third party plugins as fallback.
## Replaced with Mail::SpamAssassin::RegistryBoundaries::uri_to_domain.
##
sub uri_to_domain {
  my ($uri) = @_;

  # Javascript is not going to help us, so return.
  return if ($uri =~ /^javascript:/i);

  $uri =~ s{\#.*$}{}gs;			# drop fragment
  $uri =~ s{^[a-z]+:/{0,2}}{}gsi;	# drop the protocol
  $uri =~ s{^[^/]*\@}{}gs;		# username/passwd

  # strip path and CGI params.  note: bug 4213 shows that "&" should
  # *not* be likewise stripped here -- it's permitted in hostnames by
  # some common MUAs!
  $uri =~ s{[/?].*$}{}gs;              

  $uri =~ s{:\d*$}{}gs;		# port, bug 4191: sometimes the # is missing

  # skip undecoded URIs if the encoded bits shouldn't be.
  # we'll see the decoded version as well.  see url_encode()
  return if $uri =~ /\%(?:2[1-9a-fA-F]|[3-6][0-9a-fA-F]|7[0-9a-eA-E])/;

  my $host = $uri;  # unstripped/full domain name

  # keep IPs intact
  if ($uri !~ /^\d+\.\d+\.\d+\.\d+$/) { 
    # get rid of hostname part of domain, understanding delegation
    $uri = Mail::SpamAssassin::Util::RegistrarBoundaries::trim_domain($uri);

    # ignore invalid domains
    return unless
        (Mail::SpamAssassin::Util::RegistrarBoundaries::is_domain_valid($uri));
  }
  
  # $uri is now the domain only, optionally return unstripped host name
  return !wantarray ? lc $uri : (lc $uri, lc $host);
}

*uri_list_canonify = \&uri_list_canonicalize;  # compatibility alias
sub uri_list_canonicalize {
  my($redirector_patterns, @uris) = @_;

  # make sure we catch bad encoding tricks
  my @nuris;
  for my $uri (@uris) {
    # we're interested in http:// and so on, skip mailto: and
    # email addresses with no protocol
    next if $uri =~ /^mailto:/i || $uri =~ /^[^:]*\@/;

    # sometimes we catch URLs on multiple lines
    $uri =~ s/\n//g;

    # URLs won't have leading/trailing whitespace
    $uri =~ s/^\s+//;
    $uri =~ s/\s+$//;

    # CRs just confuse things down below, so trash them now
    $uri =~ s/\r//g;

    # Make a copy so we don't trash the original in the array
    my $nuri = $uri;

    # bug 4390: certain MUAs treat back slashes as front slashes.
    # since backslashes are supposed to be encoded in a URI, swap non-encoded
    # ones with front slashes.
    $nuri =~ tr{\\}{/};

    # http:www.foo.biz -> http://www.foo.biz
    $nuri =~ s{^(https?:)/{0,2}}{$1//}i;

    # *always* make a dup with all %-encoding decoded, since
    # important parts of the URL may be encoded (such as the
    # scheme). (bug 4213)
    if ($nuri =~ /%[0-9a-fA-F]{2}/) {
      $nuri = Mail::SpamAssassin::Util::url_encode($nuri);
    }

    # www.foo.biz -> http://www.foo.biz
    # unschemed URIs: assume default of "http://" as most MUAs do
    if ($nuri !~ /^[-_a-z0-9]+:/i) {
      if ($nuri =~ /^ftp\./) {
	$nuri =~ s{^}{ftp://}g;
      }
      else {
	$nuri =~ s{^}{http://}g;
      }
    }

    # http://www.foo.biz?id=3 -> http://www.foo.biz/?id=3
    $nuri =~ s{^(https?://[^/?]+)\?}{$1/?}i;

    # deal with encoding of chars, this is just the set of printable
    # chars minus ' ' (that is, dec 33-126, hex 21-7e)
    $nuri =~ s/\&\#0*(3[3-9]|[4-9]\d|1[01]\d|12[0-6]);/sprintf "%c",$1/ge;
    $nuri =~ s/\&\#x0*(2[1-9]|[3-6][a-fA-F0-9]|7[0-9a-eA-E]);/sprintf "%c",hex($1)/ge;

    # put the new URI on the new list if it's different
    if ($nuri ne $uri) {
      push(@nuris, $nuri);
    }

    # deal with wierd hostname parts, remove user/pass, etc.
    if ($nuri =~ m{^(https?://)([^/]+?)((?::\d*)?\/.*)?$}i) {
      my($proto, $host, $rest) = ($1,$2,$3);

      # not required
      $rest ||= '';

      # Bug 6751:
      # RFC 3490 (IDNA): Whenever dots are used as label separators, the
      #   following characters MUST be recognized as dots: U+002E (full stop),
      #   U+3002 (ideographic full stop), U+FF0E (fullwidth full stop),
      #   U+FF61 (halfwidth ideographic full stop).
      # RFC 5895: [...] the IDEOGRAPHIC FULL STOP character (U+3002)
      #   can be mapped to the FULL STOP before label separation occurs.
      #   [...] Only the IDEOGRAPHIC FULL STOP character (U+3002) is added in
      #   this mapping because the authors have not fully investigated [...]
      # Adding also 'SMALL FULL STOP' (U+FE52) as seen in the wild.
      # Parhaps also the 'ONE DOT LEADER' (U+2024).
      if ($host =~ s{(?: \xE3\x80\x82 | \xEF\xBC\x8E | \xEF\xBD\xA1 |
                         \xEF\xB9\x92 | \xE2\x80\xA4 )}{.}xgs) {
        push(@nuris, join ('', $proto, $host, $rest));
      }

      # bug 4146: deal with non-US ASCII 7-bit chars in the host portion
      # of the URI according to RFC 1738 that's invalid, and the tested
      # browsers (Firefox, IE) remove them before usage...
      if ($host =~ tr/\000-\040\200-\377//d) {
        push(@nuris, join ('', $proto, $host, $rest));
      }

      # deal with http redirectors.  strip off one level of redirector
      # and add back to the array.  the foreach loop will go over those
      # and deal appropriately.
      # bug 3308: redirectors like yahoo only need one '/' ... <grrr>
      if ($rest =~ m{(https?:/{0,2}.+)$}i) {
        push(@uris, $1);
      }

      # resort to redirector pattern matching if the generic https? check
      # doesn't result in a match -- bug 4176
      else {
	foreach (@{$redirector_patterns}) {
	  if ("$proto$host$rest" =~ $_) {
	    next unless defined $1;
	    dbg("uri: parsed uri pattern: $_");
	    dbg("uri: parsed uri found: $1 in redirector: $proto$host$rest");
	    push (@uris, $1);
	    last;
	  }
	}
      }

      ########################
      ## TVD: known issue, if host has multiple combinations of the following,
      ## all permutations will be put onto @nuris.  shouldn't be an issue.

      # Get rid of cruft that could cause confusion for rules...

      # remove "www.fakehostname.com@" username part
      if ($host =~ s/^[^\@]+\@//gs) {
        push(@nuris, join ('', $proto, $host, $rest));
      }

      # bug 3186: If in a sentence, we might pick up odd characters ...
      # ie: "visit http://example.biz." or "visit http://example.biz!!!"
      # the host portion should end in some form of alpha-numeric, strip off
      # the rest.
      if ($host =~ s/[^0-9A-Za-z]+$//) {
        push(@nuris, join ('', $proto, $host, $rest));
      }

      ########################

      # deal with hosts which are IPs
      # also handle things like:
      # http://89.0x00000000000000000000068.0000000000000000000000160.0x00000000000011
      #    both hex (0x) and oct (0+) encoded octets, etc.

      if ($host =~ /^
                    ((?:0x[0-9a-f]+|\d+)\.)
                    ((?:0x[0-9a-f]+|\d+)\.)
                    ((?:0x[0-9a-f]+|\d+)\.)
                    (0x[0-9a-f]+|\d+)
                    $/ix)
      {
        my @chunk = ($1,$2,$3,$4);
        foreach my $octet (@chunk) {
          $octet =~ s/^0x([0-9a-f]+)/sprintf "%d",hex($1)/gei;
          $octet =~ s/^0+([1-3][0-7]{0,2}|[4-7][0-7]?)\b/sprintf "%d",oct($1)/ge;
	  $octet =~ s/^0+//;
        }
        push(@nuris, join ('', $proto, @chunk, $rest));
      }

      # "http://0x7f000001/"
      elsif ($host =~ /^0x[0-9a-f]+$/i) {
        # only take last 4 octets
        $host =~ s/^0x[0-9a-f]*?([0-9a-f]{1,8})$/sprintf "%d",hex($1)/gei;
        push(@nuris, join ('', $proto, decode_ulong_to_ip($host), $rest));
      }

      # "http://1113343453/"
      elsif ($host =~ /^[0-9]+$/) {
        push(@nuris, join ('', $proto, decode_ulong_to_ip($host), $rest));
      }

    }
  }

  # remove duplicates, merge nuris and uris
  my %uris = map { $_ => 1 } @uris, @nuris;

  return keys %uris;
}

sub decode_ulong_to_ip {
  return join(".", unpack("CCCC",pack("H*", sprintf "%08lx", $_[0])));
}

###########################################################################

sub first_date {
  my (@strings) = @_;

  foreach my $string (@strings) {
    my $time = parse_rfc822_date($string);
    return $time if defined($time) && $time;
  }
  return;
}

sub receive_date {
  my ($header) = @_;

  $header ||= '';
  $header =~ s/\n[ \t]+/ /gs;	# fix continuation lines

  my @rcvd = ($header =~ /^Received:(.*)/img);
  my @local;
  my $time;

  if (@rcvd) {
    if ($rcvd[0] =~ /qmail \d+ invoked by uid \d+/ ||
	$rcvd[0] =~ /\bfrom (?:localhost\s|(?:\S+ ){1,2}\S*\b127\.0\.0\.1\b)/)
    {
      push @local, (shift @rcvd);
    }
    if (@rcvd && ($rcvd[0] =~ m/\bby localhost with \w+ \(fetchmail-[\d.]+/)) {
      push @local, (shift @rcvd);
    }
    elsif (@local) {
      unshift @rcvd, (shift @local);
    }
  }

  if (@rcvd) {
    $time = first_date(shift @rcvd);
    return $time if defined($time);
  }
  if (@local) {
    $time = first_date(@local);
    return $time if defined($time);
  }
  if ($header =~ /^(?:From|X-From-Line:)\s+(.+)$/im) {
    my $string = $1;
    $string .= " ".local_tz() unless $string =~ /(?:[-+]\d{4}|\b[A-Z]{2,4}\b)/;
    $time = first_date($string);
    return $time if defined($time);
  }
  if (@rcvd) {
    $time = first_date(@rcvd);
    return $time if defined($time);
  }
  if ($header =~ /^Resent-Date:\s*(.+)$/im) {
    $time = first_date($1);
    return $time if defined($time);
  }
  if ($header =~ /^Date:\s*(.+)$/im) {
    $time = first_date($1);
    return $time if defined($time);
  }

  return time;
}

###########################################################################

sub setuid_to_euid {
  return if (RUNNING_ON_WINDOWS);

  # remember the target uid, the first number is the important one
  my $touid = $>;

  if ($< != $touid) {
    dbg("util: changing real uid from $< to match effective uid $touid");
    # bug 3586: kludges needed to work around platform dependent behavior assigning to $<
    #  The POSIX functions deal with that so just use it here
    POSIX::setuid($touid);
    $< = $touid; $> = $touid;       # bug 5574

    # Check that we have now accomplished the setuid: catch bug 3586 if it comes back
    if ($< != $touid) {
      # keep this fatal: it's a serious security problem if it fails
      die "util: setuid $< to $touid failed!";
    }
  }
}

# helper app command-line open
sub helper_app_pipe_open {
  if (RUNNING_ON_WINDOWS) {
    return helper_app_pipe_open_windows (@_);
  } else {
    return helper_app_pipe_open_unix (@_);
  }
}

sub helper_app_pipe_open_windows {
  my ($fh, $stdinfile, $duperr2out, @cmdline) = @_;

  # use a traditional open(FOO, "cmd |")
  my $cmd = join(' ', @cmdline);
  if ($stdinfile) { $cmd .= qq/ < "$stdinfile"/; }
  if ($duperr2out) { $cmd .= " 2>&1"; }
  return open ($fh, $cmd.'|');
}

sub force_die {
  my ($msg) = @_;

  # note use of eval { } scope in logging -- paranoia to ensure that a broken
  # $SIG{__WARN__} implementation will not interfere with the flow of control
  # here, where we *have* to die.
  eval { warn $msg };  # hmm, STDERR may no longer be open
  eval { dbg("util: force_die: $msg") };

  POSIX::_exit(6);  # avoid END and destructor processing 
  kill('KILL',$$);  # still kicking? die! 
}

sub helper_app_pipe_open_unix {
  my ($fh, $stdinfile, $duperr2out, @cmdline) = @_;

  my $pid;
  # do a fork-open, so we can setuid() back
  eval {
    $pid = open ($fh, '-|');  1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    die "util: cannot fork: $eval_stat";
  };
  if (!defined $pid) {
    # acceptable to die() here, calling code catches it
    die "util: cannot open a pipe to a forked process: $!";
  }

  if ($pid != 0) {
    return $pid;          # parent process; return the child pid
  }

  # else, child process.  

  # from now on, we cannot die(), it could create a cloned process
  # use force_die() instead  (bug 4370, cmt 2)
  eval {
    # go setuid...
    setuid_to_euid();
    dbg("util: setuid: ruid=$< euid=$>");

    # now set up the fds.  due to some wierdness, we may have to ensure that
    # we *really* close the correct fd number, since some other code may have
    # redirected the meaning of STDOUT/STDIN/STDERR it seems... (bug 3649).
    # use POSIX::close() for that. it's safe to call close() and POSIX::close()
    # on the same fd; the latter is a no-op in that case.

    if (!$stdinfile) {              # < $tmpfile
      # ensure we have *some* kind of fd 0.
      $stdinfile = "/dev/null";
    }

    my $f = fileno(STDIN);
    close STDIN  or die "error closing STDIN: $!";

    # sanity: was that the *real* STDIN? if not, close that one too ;)
    if ($f != 0) {
      POSIX::close(0);
    }

    open (STDIN, "<$stdinfile") or die "cannot open $stdinfile: $!";

    # this should be impossible; if we just closed fd 0, UNIX
    # fd behaviour dictates that the next fd opened (the new STDIN)
    # will be the lowest unused fd number, which should be 0.
    # so die with a useful error if this somehow isn't the case.
    if (fileno(STDIN) != 0) {
      die "oops: fileno(STDIN) [".fileno(STDIN)."] != 0";
    }

    # Ensure STDOUT is open. As we just created a pipe to ensure this, it has
    # to be open to that pipe, and if it isn't, something's seriously screwy.
    # Update: actually, this fails! see bug 3649 comment 37.  For some reason,
    # fileno(STDOUT) can be 0; possibly because open("-|") didn't change the fh
    # named STDOUT, instead changing fileno(1) directly.  So this is now
    # commented.
    # if (fileno(STDOUT) != 1) {
    # die "setuid: oops: fileno(STDOUT) [".fileno(STDOUT)."] != 1";
    # }

    STDOUT->autoflush(1);

    if ($duperr2out) {             # 2>&1
      my $f = fileno(STDERR);
      close STDERR  or die "error closing STDERR: $!";

      # sanity: was that the *real* STDERR? if not, close that one too ;)
      if ($f != 2) {
        POSIX::close(2);
      }

      open (STDERR, ">&STDOUT") or die "dup STDOUT failed: $!";
      STDERR->autoflush(1);  # make sure not to lose diagnostics if exec fails

      # STDERR must be fd 2 to be useful to subprocesses! (bug 3649)
      if (fileno(STDERR) != 2) {
        die "oops: fileno(STDERR) [".fileno(STDERR)."] != 2";
      }
    }

    exec @cmdline;
    die "exec failed: $!";
  };
  my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;

  # bug 4370: we really have to exit here; break any eval traps
  force_die(sprintf('util: failed to spawn a process "%s": %s',
                    join(", ",@cmdline), $eval_stat));
  die;  # must be a die() otherwise -w will complain
}

###########################################################################

# As "perldoc perlvar" notes, in perl 5.8.0, the concept of "safe" signal
# handling was added, which means that signals cannot interrupt a running OP.
# unfortunately, a regexp match is a single OP, so a psychotic m// can
# effectively "hang" the interpreter as a result, and a $SIG{ALRM} handler
# will never get called.
#
# However, by using "unsafe" signals, we can still interrupt that -- and
# POSIX::sigaction can create an unsafe handler on 5.8.x.   So this function
# provides a portable way to do that.

sub trap_sigalrm_fully {
  my ($handler) = @_;
  if ($] < 5.008 || am_running_on_windows()) {
    # signals are always unsafe on perl older than 5.008, just use %SIG
    # Bug 6359, no POSIX::SIGALRM on Windows, just use %SIG
    $SIG{ALRM} = $handler;
  } else {
    # may be using "safe" signals with %SIG; use POSIX to avoid it
    POSIX::sigaction POSIX::SIGALRM(), new POSIX::SigAction $handler;
  }
}

###########################################################################

# Removes any normal perl-style regexp delimiters at
# the start and end, and modifiers at the end (if present).
# If modifiers are found, they are inserted into the pattern using
# the /(?i)/ idiom.

sub regexp_remove_delimiters {
  my ($re) = @_;

  my $delim;
  if (!defined $re || $re eq '') {
    warn "cannot remove delimiters from null regexp";
    return;  # invalid
  }
  elsif ($re =~ s/^m\{//) {             # m{foo/bar}
    $delim = '}';
  }
  elsif ($re =~ s/^m\(//) {             # m(foo/bar)
    $delim = ')';
  }
  elsif ($re =~ s/^m<//) {              # m<foo/bar>
    $delim = '>';
  }
  elsif ($re =~ s/^m(\W)//) {           # m#foo/bar#
    $delim = $1;
  } else {                              # /foo\/bar/ or !foo/bar!
    $re =~ s/^(\W)//; $delim = $1;
  }

  $re =~ s/\Q${delim}\E([imsx]*)$// or warn "unbalanced re: $re";

  my $mods = $1;
  if ($mods) {
    $re = "(?".$mods.")".$re;
  }

  return $re;
}

# turn "/foobar/i" into qr/(?i)foobar/

sub make_qr {
  my ($re) = @_;
  $re = regexp_remove_delimiters($re);
  return qr/$re/;
}

###########################################################################

sub get_my_locales {
  my ($ok_locales) = @_;

  my @locales = split(' ', $ok_locales);
  my $lang = $ENV{'LC_ALL'};
  $lang ||= $ENV{'LANGUAGE'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  push (@locales, $lang) if defined($lang);
  return @locales;
}

###########################################################################

# bug 5612: work around for bugs in Berkeley db 4.2
#
# on 4.2 having the __db.[DBNAME] file will cause an loop that will never finish
# on 4.3+ the loop will timeout after 301 open attempts, but we will still
# be unable to open the database.  This workaround solves both problems. 
#
sub avoid_db_file_locking_bug {
  my ($path) = @_;

  my $db_tmpfile = untaint_file_path(File::Spec->catfile(dirname($path),
                        '__db.'.basename($path)));

  # delete "__db.[DBNAME]" and "__db.[DBNAME].*"
  foreach my $tfile ($db_tmpfile, glob("$db_tmpfile.*")) {
    my $file = untaint_file_path($tfile);
    my $stat_errn = stat($file) ? 0 : 0+$!;
    next if $stat_errn == ENOENT;

    dbg("util: Berkeley DB bug work-around: cleaning tmp file $file");
    unlink($file) or warn "cannot remove Berkeley DB tmp file $file: $!\n";
  }
}

###########################################################################

sub fisher_yates_shuffle {
  my ($deck) = @_;
  for (my $i = $#{$deck}; $i > 0; $i--) {
    my $j = int rand($i+1);
    @$deck[$i,$j] = @$deck[$j,$i];
  }
}

###########################################################################


###########################################################################

# bugs 6419 and 2607 relate to returning a score 1/10th lower than the
# required score if the rounded to the 10th version of the score is equal
# to the required score
#
# moved from PerMessageStatus.pm to here and modified to allow for a 
# non-class version of the routine to be called from PerMessageStatus
# and from spamd

sub get_tag_value_for_score {
  my ($score, $rscore, $is_spam) = @_;

  #BASED ON _get_tag_value_for_score from PerMsgStatus.pm

  $score  = sprintf("%2.1f", $score);
  $rscore = sprintf("%2.1f", $rscore);

  # if the email is spam, return the accurate score
  # if the email is NOT spam and the score is less than the required score, 
  #   then return the accurate score

  return $score if $is_spam or $score < $rscore;

  # if the email is NOT spam and $score = $rscore, return the $rscore - 0.1 
  #   effectively flooring the value to the closest tenth

  return $rscore - 0.1;
}

###########################################################################


1;

=back

=cut
