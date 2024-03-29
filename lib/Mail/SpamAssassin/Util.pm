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
# use bytes;
use re 'taint';

use Mail::SpamAssassin::Logger;

use version 0.77;
use Exporter ();

our @ISA = qw(Exporter);
our @EXPORT = ();
our @EXPORT_OK = qw(&local_tz &base64_decode &base64_encode &base32_encode
                  &untaint_var &untaint_file_path &exit_status_str
                  &proc_status_ok &am_running_on_windows &reverse_ip_address
                  &decode_dns_question_entry &touch_file &secure_tmpfile
                  &secure_tmpdir &uri_list_canonicalize &get_my_locales
                  &parse_rfc822_date &idn_to_ascii &is_valid_utf_8
                  &get_user_groups &compile_regexp &qr_to_string
                  &is_fqdn_valid &parse_header_addresses &force_die
                  &domain_to_search_list &get_part_details);

our $AM_TAINTED;

use Config;
use Encode;
use IO::Handle;
use File::Spec;
use File::Basename;
use Time::Local;
use Scalar::Util qw(tainted);
use Fcntl;
use Errno qw(ENOENT EACCES EEXIST);
use POSIX qw(:sys_wait_h WIFEXITED WIFSIGNALED WIFSTOPPED WEXITSTATUS
             WTERMSIG WSTOPSIG);

###########################################################################

use constant HAS_NETADDR_IP => eval { require NetAddr::IP; };
use constant HAS_MIME_BASE64 => eval { require MIME::Base64; };
use constant RUNNING_ON_WINDOWS => ($^O =~ /^(?:mswin|dos|os2)/i);

# These are only defined as stubs on Windows (see bugs 6798 and 6470).
BEGIN {
  if (RUNNING_ON_WINDOWS) {
    require Win32;
    no warnings 'redefine';

    # See the section on $? at
    # http://perldoc.perl.org/perlvar.html#Error-Variables for some
    # hints on the magic numbers that are used here.
    *WIFEXITED   = sub { not $_[0] & 127 };
    *WEXITSTATUS = sub { $_[0] >> 8 };
    *WIFSIGNALED = sub { ($_[0] & 127) && (($_[0] & 127) != 127) };
    *WTERMSIG    = sub { $_[0] & 127 };
  }
}

###########################################################################

our $ALT_FULLSTOP_UTF8_RE;
BEGIN {
  # Bug 6751:
  # RFC 3490 (IDNA): Whenever dots are used as label separators, the
  #   following characters MUST be recognized as dots: U+002E (full stop),
  #   U+3002 (ideographic full stop), U+FF0E (fullwidth full stop),
  #   U+FF61 (halfwidth ideographic full stop).
  # RFC 5895: [...] the IDEOGRAPHIC FULL STOP character (U+3002)
  #   can be mapped to the FULL STOP before label separation occurs.
  #   [...] Only the IDEOGRAPHIC FULL STOP character (U+3002) is added in
  #   this mapping because the authors have not fully investigated [...]
  # Adding also 'SMALL FULL STOP' (U+FE52) as seen in the wild,
  # and a 'ONE DOT LEADER' (U+2024).
  #
  no bytes;  # make sure there is no 'use bytes' in effect
  my $dot_chars = "\x{2024}\x{3002}\x{FF0E}\x{FF61}\x{FE52}";  # \x{002E}
  my $dot_bytes = join('|', split(//,$dot_chars));  utf8::encode($dot_bytes);
  $ALT_FULLSTOP_UTF8_RE = qr/$dot_bytes/s;
}

###########################################################################

our ($have_libidn, $have_libidn2);
BEGIN {
  my $sa_libidn = ($ENV{'SA_LIBIDN'}||'') =~ /(\d+)/ ? $1 : 0;
  if (!$sa_libidn || $sa_libidn eq '2') {
    eval { require Net::LibIDN2; } and do { $have_libidn2 = 1; };
  }
  if (!$have_libidn2 && (!$sa_libidn || $sa_libidn eq '1')) {
    eval { require Net::LibIDN; } and do { $have_libidn = 1; };
  }
}

$have_libidn||$have_libidn2
  or info("util: module Net::LibIDN or Net::LibIDN2 not available, ".
          "internationalized domain names with U-labels will not be recognized!");

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

    my @pathext = ('');
    if (RUNNING_ON_WINDOWS) {
      if ( $ENV{PATHEXT} ) {
        push @pathext, split($Config{'path_sep'}, $ENV{PATHEXT});
      } else {
        push @pathext, qw{.exe .com .bat};
      }
    }

    foreach my $path (File::Spec->path()) {
      my $base = File::Spec->catfile ($path, $filename);
      for my $ext ( @pathext ) {
        my $fname = $base.$ext;
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
      if ( $ENV{'PATHEXT'} ) { # clean and untaint
        $ENV{'PATHEXT'} = join($Config{'path_sep'}, grep ($_, map( {$_ =~ m/^(\.[a-zA-Z]{1,10})$/; $1; } split($Config{'path_sep'}, $ENV{'PATHEXT'}))));
      }
    } else {
      delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
    }

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
      elsif (!RUNNING_ON_WINDOWS && (($stat[2]&2) != 0)) {
        # World-Writable directories are considered insecure, but unavoidable on Windows
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
# "C:\Program Files\SpamAssassin\tmp\foo", "/home/��t/etc".
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
  # Barry Jaspan: allow ~ and spaces, good for Windows.
  # Also return '' if input is '', as it is a safe path.
  # Bug 7264: allow also parenthesis, e.g. "C:\Program Files (x86)"
  my $chars = '-_A-Za-z0-9.#%=+,/:()\\@\\xA0-\\xFF\\\\';
  my $re = qr{^\s*([$chars][${chars}~ ]*)\z};

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
    # Bug 7591 not using this faster untaint. https://bz.apache.org/SpamAssassin/show_bug.cgi?id=7591 
      #return defined $_[0] ? scalar each %{ { $_[0] => undef } } : undef; ## no critic (ProhibitExplicitReturnUndef)  - See Bug 7120 - fast untaint (hash keys cannot be tainted)
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
        if($] < 5.020) {
          # hash keys are never tainted,
          # although old version of perl had some quirks there
          # skip the check only for Perl > 5.020 to be on the safe side
          while (my($k, $v) = each %{$arg}) {
            ${$arg}{untaint_var($k)} = untaint_var($v);
          }
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
  # Bug 7806: use $fh trick to enforce for older Perl
  my $t = eval { local $/; open my $fh, '<', \""; <$fh>; };
  $t = '' unless defined $t;
  return $v . $t . substr($^X, 0, 0);
}

###########################################################################

# Check for full hostname / FQDN / DNS name validity.  IP addresses must be
# validated with other functions like Constants::IP_ADDRESS.  Does not check
# for valid TLD, use $self->{main}->{registryboundaries}->is_domain_valid()
# additionally for that.  If $is_ascii given and true, skip idn_to_ascii()
# conversion.
sub is_fqdn_valid {
  my ($host, $is_ascii) = @_;
  return if !defined $host;

  if ($is_ascii) {
    utf8::encode($host)  if utf8::is_utf8($host); # force octets
    $host = lc $host;
  } else {
    # convert to ascii, handles Unicode dot normalization also
    $host = idn_to_ascii($host);
  }

  # remove trailing dots
  $host =~ s/\.+\z//;

  # max total length 253
  return if length($host) > 253;

  # validate dot separated components/labels
  my @labels = split(/\./, $host);
  my $cnt = scalar @labels;
  return unless $cnt > 1; # at least two labels required
  foreach my $label (@labels) {
    # length of 1-63
    return if length($label) < 1;
    return if length($label) > 63;
    # alphanumeric, - allowed only in middle part
    # underscores are allowed in DNS queries, so we allow here
    # (idn_to_ascii made sure we are lowercase and pure ascii)
    return if $label !~ /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/;
    # 1st-2nd level part can not contain _, only third+ can
    if ($cnt == 2 || $cnt == 1) {
      return if index($label, '_') != -1;
    }
    $cnt--;
  }

  # is good
  return 1;
}

###########################################################################

# returns true if the provided string of octets represents a syntactically
# valid UTF-8 string, otherwise a false is returned
#
sub is_valid_utf_8 {
# my $octets = $_[0];
  return undef if !defined $_[0]; ## no critic (ProhibitExplicitReturnUndef)
  #
  # RFC 6532: UTF8-non-ascii = UTF8-2 / UTF8-3 / UTF8-4
  # RFC 3629 section 4: Syntax of UTF-8 Byte Sequences
  #   UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
  #   UTF8-1      = %x00-7F
  #   UTF8-2      = %xC2-DF UTF8-tail
  #   UTF8-3      = %xE0 %xA0-BF UTF8-tail /
  #                 %xE1-EC 2( UTF8-tail ) /
  #                 %xED %x80-9F UTF8-tail /
  #                   # U+D800..U+DFFF are utf16 surrogates, not legal utf8
  #                 %xEE-EF 2( UTF8-tail )
  #   UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) /
  #                 %xF1-F3 3( UTF8-tail ) /
  #                 %xF4 %x80-8F 2( UTF8-tail )
  #   UTF8-tail   = %x80-BF
  #
  # loose variant:
  #   [\x00-\x7F] | [\xC0-\xDF][\x80-\xBF] |
  #   [\xE0-\xEF][\x80-\xBF]{2} | [\xF0-\xF4][\x80-\xBF]{3}
  #
  $_[0] =~ /^ (?: [\x00-\x7F] |
                  [\xC2-\xDF] [\x80-\xBF] |
                  \xE0 [\xA0-\xBF] [\x80-\xBF] |
                  [\xE1-\xEC] [\x80-\xBF]{2} |
                  \xED [\x80-\x9F] [\x80-\xBF] |
                  [\xEE-\xEF] [\x80-\xBF]{2} |
                  \xF0 [\x90-\xBF] [\x80-\xBF]{2} |
                  [\xF1-\xF3] [\x80-\xBF]{3} |
                  \xF4 [\x80-\x8F] [\x80-\xBF]{2} )* \z/xs ? 1 : 0;
}

# Given an international domain name with U-labels (UTF-8 or Unicode chars)
# converts it to ASCII-compatible encoding (ACE).  If the argument is in
# ASCII (or is an invalid IDN), returns it lowercased but otherwise unchanged.
# The result is always in octets (utf8 flag off) even if the argument was in
# Unicode characters.
#
#my $idn_cache = {};
sub idn_to_ascii {
  no bytes;  # make sure there is no 'use bytes' in effect
  return undef  if !defined $_[0]; ## no critic (ProhibitExplicitReturnUndef)
  my $s = "$_[0]";  # stringify

  # encode chars to UTF-8, leave octets unchanged (not necessarily valid UTF-8)
  utf8::encode($s)  if utf8::is_utf8($s); # i.e. remove utf-8 flag if set

  # Rapid return for most common case, all-ASCII (including IP address literal),
  # no conversion needed. Also if we don't have LibIDN, nothing more we can do.
  if ($s !~ tr/a-zA-Z0-9_.:[]-//c || !($have_libidn||$have_libidn2)) {
    return lc $s; # retains taintedness
  }

  #if (exists $idn_cache->{$s}) {
  #  dbg("util: idn_to_ascii: converted to ACE: '$s' -> '$idn_cache->{$s}' (cached)");
  #  return $idn_cache->{$s};
  #}
  #$idn_cache = {} if %$idn_cache > 1000;
  #my $orig_s = $s; # save original for idn_cache

  # propagate taintedness of the argument
  my $t = tainted($s);
  if ($t) {  # untaint $s, avoids taint-related bugs in LibIDN or in old perl
    $s = untaint_var($s);
  }

  my $charset;

  # Check for valid UTF-8
  if (is_valid_utf_8($s)) {
    # RFC 3490 (IDNA): Whenever dots are used as label separators, the
    # following characters MUST be recognized as dots: U+002E (full stop),
    # U+3002 (ideographic full stop), U+FF0E (fullwidth full stop),
    # U+FF61 (halfwidth ideographic full stop).
    if ($s =~ s/$ALT_FULLSTOP_UTF8_RE/./gs) {
      dbg("util: idn_to_ascii: alternative dots normalized: '%s' -> '%s'",
           $_[0], $s);
    }
    $charset = 'UTF-8';
  }
  # Check for valid extended ISO-8859-1 including diacritics
  elsif ($s !~ tr/a-zA-Z0-9\xc0-\xd6\xd8-\xde\xe0-\xf6\xf8-\xfe_.-//c) {
    $charset = 'ISO-8859-1';
  }

  if ($charset) {
    # to ASCII-compatible encoding (ACE), lowercased
    if ($have_libidn) {
      my $sa = Net::LibIDN::idn_to_ascii($s, $charset);
      if (!defined $sa) {
        info("util: idn_to_ascii: conversion to ACE failed: '%s' (charset %s)",
             $s, $charset);
      } else {
        dbg("util: idn_to_ascii: converted to ACE: '%s' -> '%s' (charset %s)",
            $s, $sa, $charset)  if $s ne $sa;
        $s = $sa;
      }
    } elsif ($have_libidn2) {
      my $si = $s;
      if ($charset eq 'ISO-8859-1') {
        Encode::from_to($si, 'ISO-8859-1', 'UTF-8');
      }
      utf8::decode($si) unless utf8::is_utf8($si);
      my $rc = 0;
      my $sa = Net::LibIDN2::idn2_to_ascii_8($si,
                 &Net::LibIDN2::IDN2_NFC_INPUT + &Net::LibIDN2::IDN2_NONTRANSITIONAL,
                 $rc);
      if (!defined $sa) {
        info("util: idn_to_ascii: conversion to ACE failed, %s: '%s' (charset %s) (LibIDN2)",
             Net::LibIDN2::idn2_strerror($rc), $s, $charset);
      } else {
        dbg("util: idn_to_ascii: converted to ACE: '%s' -> '%s' (charset %s) (LibIDN2)",
            $s, $sa, $charset)  if $s ne $sa;
        $s = $sa;
      }
    }
  } else {
    my($package, $filename, $line) = caller;
    info("util: idn_to_ascii: valid charset not detected: '%s', called from %s line %d",
         $s, $package, $line);
    $s = lc $s;  # garbage-in / garbage-out
  }

  return $t ? taint_var($s) : $s;  # propagate taintedness of the argument
  #return $idn_cache->{$orig_s} = $t ? taint_var($s) : $s;  # propagate taintedness of the argument
}

###########################################################################

# map process termination status number to an informative string, and
# append optional message (dual-valued errno or a string or a number),
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
    my $len = length($arr[$pos]);
    $len += ($arr[$pos] =~ tr/\t//) * 7; # add tab lengths

    # if we don't want to have lines > $length (overflow==0), we
    # need to verify what will happen with the next line.  if we don't
    # care if a single line goes longer, don't care about the next
    # line.
    # we also want this to be true for the first entry on the line
    if ($pos_mod != 0 && $overflow == 0) {
      $len += length($arr[$pos+1]);
      $len += ($arr[$pos+1] =~ tr/\t//) * 7; # add tab lengths
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
    local $1;
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
  tr{A-Za-z0-9+/=}{ -_};		# translate to uuencode
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
  my $str = $_[0];

  # RFC 2045: when decoding a Quoted-Printable body, any trailing
  # white space on a line must be deleted
  $str =~ s/[ \t]+(?=\r?\n)//gs;

  $str =~ s/=\r?\n//gs;  # soft line breaks

  # RFC 2045 explicitly prohibits lowercase characters a-f in QP encoding
  # do we really want to allow them???

  local $1;
  $str =~ s/=([0-9a-fA-F]{2})/chr(hex($1))/ge;

  return $str;
}

sub base64_encode {
  local $_ = shift;

  if (HAS_MIME_BASE64) {
    return MIME::Base64::encode_base64($_,'');
  }

  $_ = pack("u57", $_);
  s/^.//mg;
  tr| -_`|A-Za-z0-9+/A|; # -> #`# <- kluge against vim syntax issues
  s/(A+)$/'=' x length $1/e;
  return $_;
}

# Very basic Base32 encoder
our %base32_bitchr = (
  '00000'=>'A', '00001'=>'B', '00010'=>'C', '00011'=>'D', '00100'=>'E',
  '00101'=>'F', '00110'=>'G', '00111'=>'H', '01000'=>'I', '01001'=>'J',
  '01010'=>'K', '01011'=>'L', '01100'=>'M', '01101'=>'N', '01110'=>'O',
  '01111'=>'P', '10000'=>'Q', '10001'=>'R', '10010'=>'S', '10011'=>'T',
  '10100'=>'U', '10101'=>'V', '10110'=>'W', '10111'=>'X', '11000'=>'Y',
  '11001'=>'Z', '11010'=>'2', '11011'=>'3', '11100'=>'4', '11101'=>'5',
  '11110'=>'6', '11111'=>'7'
);
sub base32_encode {
  my ($str) = @_;
  return if !defined $str;
  utf8::encode($str)  if utf8::is_utf8($str); # force octets
  my $bits = unpack("B*", $str)."0000";
  my $output;
  local($1);
  $output .= $base32_bitchr{$1} while ($bits =~ /(.{5})/g);
  return $output;
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
# Get a platform specific directory for application data
# Just used for Windows for now
sub common_application_data_directory {
  return Win32::GetFolderPath(Win32::CSIDL_COMMON_APPDATA()) if (RUNNING_ON_WINDOWS);
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
                       (?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.
                       (?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.
                       (?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.
                       (?:1\d\d|2[0-4]\d|25[0-5]|[1-9]\d|\d)
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
    # Load only when required
    require Sys::Hostname;
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
    if (index($fq_hostname, '.') == -1) { # hostname doesn't contain a dot, so it can't be a FQDN
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
  } elsif (index($ip, ':') == -1 || $ip !~ /^[0-9a-fA-F:.]{2,}\z/) {  # triage
    # obviously unrecognized syntax
  } elsif (!HAS_NETADDR_IP || !NetAddr::IP->can('full6')) {  # since NetAddr::IP 4.010
    info("util: sufficiently new NetAddr::IP not found, IPv6 not supported");
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
  $qname =~ s{ \\ ( [0-9]{3} | (?![0-9]{3}) . ) }
             { length($1)==3 && $1 <= 255 ? chr($1) : $1 }xgse;
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
  my $missing; # flag missing content-type, even though we force it text/plain
  my $ct = $_[-1] || do { $missing = 1; 'text/plain; charset=us-ascii' };

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

  # RFC 2231 section 3: Parameter Value Continuations
  # support continuations for name values
  #
  if (!$name && $ct =~ /\b(?:file)?name\*0\s*=/i) {

    my @name;
    $name[$1] = $2
      while ($ct =~ /\b(?:file)?name\*(\d+)\s*=\s*["']?(.*?)["']?(?:;|$)/ig);

    $name = join "", grep defined, @name;
  }

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
  $missing = 1 if !$ct; # flag missing content-type
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
  # Added fifth array member $missing, if caller wants to know ct was
  # missing/invalid, even though we forced it as text/plain.
  #
  return wantarray ? ($ct,$boundary,$charset,$name,$missing) : $ct;
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
    next if $mod !~ /^[\w:]+$/; # be paranoid
    if (eval 'require '.$mod.'; 1;') {
      return $mod;
    }
  }
  undef;
}

###########################################################################

=item touch_file(file, { args });

Touch or create a file.

Possible args:

create_exclusive =E<gt> 1
  Create a new empty file safely, only if not existing before

=cut

sub touch_file {
  my ($file, $args) = @_;

  $file = untaint_file_path($file);
  $args ||= {};

  return unless defined $file && $file ne '';

  if ($args->{create_exclusive}) {
    if (sysopen(my $fh, $file, O_CREAT|O_EXCL)) {
      close $fh;
      return 1;
    }
    return 1 if $! == EEXIST; # fine if it exists already
    dbg("util: exclusive touch_file failed: $file: $!");
    return 0;
  }

  if (!utime(undef,undef,$file)) {
    dbg("util: touch_file failed: $file: $!");
    return 0;
  }

  return 1;
}

###########################################################################

sub pseudo_random_string {
  my $len = shift || 6;
  my $str = '';
  $str .= (0..9,'A'..'Z','a'..'z')[rand 62] for (1 .. $len);
  return $str;
}

###########################################################################

=item my ($filepath, $filehandle) = secure_tmpfile();

Generates a filename for a temporary file, opens it exclusively and
securely, and returns a filehandle to the open file (opened O_RDWR).

If it cannot open a file after 20 tries, it returns C<undef>.

=cut

# thanks to http://www2.picante.com:81/~gtaylor/autobuse/ for this code
sub secure_tmpfile {
  my $tmpenv = am_running_on_windows() ? 'TMP' : 'TMPDIR';
  my $tmpdir = untaint_file_path($ENV{$tmpenv} || File::Spec->tmpdir());

  defined $tmpdir && $tmpdir ne ''
    or die "util: cannot find a temporary directory, set TMP or TMPDIR in environment";

  opendir(my $dh, $tmpdir) or die "Could not open directory $tmpdir: $!";
  closedir $dh or die "Error closing directory $tmpdir: $!";

  my ($reportfile, $tmpfh);
  for (my $retries = 20; $retries > 0; $retries--) {
    # we do not rely on the obscurity of this name for security,
    # we use a average-quality PRG since this is all we need
    my $suffix = pseudo_random_string(6);
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
## DEPRECATED FUNCTION, sub uri_to_domain removed.
## Replaced with Mail::SpamAssassin::RegistryBoundaries::uri_to_domain.
##

###########################################################################

*uri_list_canonify = \&uri_list_canonicalize;  # compatibility alias
sub uri_list_canonicalize {
  my $redirector_patterns = shift;

  my @uris;
  my $rb;
  if (ref($_[0]) eq 'ARRAY') {
    # New call style:
    # - reference to array of redirector_patterns
    # - reference to array of URIs
    # - reference to $self->{main}->{registryboundaries}
    @uris = @{$_[0]};
    $rb = $_[1];
  } else {
    # Old call style:
    # - reference to array of redirector_patterns
    # - rest of the arguments is list of uris
    @uris = @_;
  }

  # make sure we catch bad encoding tricks
  my @nuris;
  for my $uri (@uris) {
    # sometimes we catch URLs on multiple lines
    $uri =~ s/\n//g;

    # URLs won't have leading/trailing whitespace
    $uri =~ s/^\s+//;
    $uri =~ s/\s+$//;

    # CRs just confuse things down below, so trash them now
    $uri =~ s/\r//g;

    # Skip some common non-http stuff like #abcdef, ?foobar,
    # /image.gif (but not //foo.com which actually does http)
    next if length($uri) <= 1 || $uri =~ m{^(?:[#?&]|/(?!/))};

    # Make a copy so we don't trash the original in the array
    my $nuri = $uri;

    # Handle emails differently
    if ($nuri =~ /^mailto:/i || $nuri =~ /^[^:]*\@/) {
      # Strip ?subject= parameters and obfuscations
      # Outlook linkifies foo@bar%2Ecom&x.com to foo@bar.com !!
      if ($nuri =~ /^([^\@]+\@[^?]+)\?/) {
        push @nuris, $1;
      }
      if ($nuri =~ /^([^\@]+\@[^?&]+)\&/) {
        push @nuris, $1
      }
      # Address must be trimmed of %20
      if (index($nuri, '%20') >= 0 &&
          $nuri =~ /^(?:mailto:)?(?:\%20)*([^\@]+\@[^?&%]+)/) {
        push @nuris, "mailto:$1";
      }
      # mailto:"Foo%20Bar"%20<foo.bar@example.com>
      if ($nuri =~ /^[^?&]*<([^\@>]+\@[^>]+)>/) {
        push @nuris, "mailto:$1";
      }
      # End email processing
      next;
    }

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
    # http://www.foo.biz#id=3 -> http://www.foo.biz/#id=3
    $nuri =~ s{^(https?://[^/?#]+)([?#])}{$1/$2}i;

    # deal with encoding of chars, this is just the set of printable
    # chars minus ' ' (that is, dec 33-126, hex 21-7e)
    $nuri =~ s/\&\#0*(3[3-9]|[4-9]\d|1[01]\d|12[0-6]);/sprintf "%c",$1/ge;
    $nuri =~ s/\&\#x0*(2[1-9]|[3-6][a-fA-F0-9]|7[0-9a-eA-E]);/sprintf "%c",hex($1)/ge;
    # handle other unicode dots (U+002E U+3002 U+FF0E U+FF61) -> .
    $nuri =~ s/\&\#(?:x2e|12290|x3002|65294|xff0e|65377|xff61);/./gi;

    # put the new URI on the new list if it's different
    if ($nuri ne $uri) {
      push(@nuris, $nuri);
    }

    # deal with weird hostname parts, remove user/pass, etc.
    if ($nuri =~ m{^(https?://)([^\@/?#]*\@)?([^/?#:]+)((?::(\d*))?.*)$}i) {
      my($proto, $host, $rest) = ($1,$3,$4);
      my $auth = defined $2 ? $2 : '';
      my $port = defined $5 ? $5 : '';

      my $rest_noport;
      if ($port eq '') {
        $port = $proto eq 'http://' ? 80 : 443;
      } else {
        $rest_noport = $rest;
        # Strip default ports from url and add to list
        if ($proto eq 'http://') {
          if ($rest_noport =~ s/^:80\b//) {
            push(@nuris, join('', $proto, $host, $rest_noport));
          }
        } elsif ($rest_noport =~ s/^:443\b//) {
          push(@nuris, join('', $proto, $host, $rest_noport));
        }
      }

      my $nhost = idn_to_ascii($host);
      if ($nhost ne lc($host)) {
        push(@nuris, join('', $proto, $nhost, $rest));
        # Also add noport variant
        push(@nuris, join('', $proto, $nhost, $rest_noport)) if $rest_noport;
        $host = $nhost;
      }

      # bug 4146: deal with non-US ASCII 7-bit chars in the host portion
      # of the URI according to RFC 1738 that's invalid, and the tested
      # browsers (Firefox, IE) remove them before usage...
      #if ($host =~ tr/\000-\040\200-\377//d) {
      # Fixed 7/2019 to not strip extended chars, since they can be used in
      # IDN domains. Stripping control chars should be enough?
      if ($host =~ tr/\x00-\x20//d) {
        push(@nuris, join ('', $proto, $host, $rest));
      }

      # deal with http redirectors.  strip off one level of redirector
      # and add back to the array.  the foreach loop will go over those
      # and deal appropriately.

      # Bug 7278: try redirector pattern matching first
      # (but see also Bug 4176)
      my $found_redirector_match;
      foreach my $re (@{$redirector_patterns}) {
        if ("$proto$host$rest" =~ $re) {
          next unless defined $1 && index($1, '.') != -1;
          dbg("uri: parsed uri pattern: $re");
          dbg("uri: parsed uri found: $1 in redirector: $proto$host$rest");
          push (@uris, $1);
          $found_redirector_match = 1;
          last;
        }
      }
      if (!$found_redirector_match) {
        # try generic https? check if redirector pattern matching failed
        # bug 3308: redirectors like yahoo only need one '/' ... <grrr>
        if ($rest =~ m{(https?:/{0,2}[^&#]+)}i && index($1, '.') != -1) {
          push(@uris, $1);
          dbg("uri: parsed uri found: $1 in hard-coded redirector");
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
      # the host portion should end in some form of alphanumeric, strip off
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

      # http://foobar -> http://www.foobar.com as Firefox does (Bug 6596)
      # (do this here so we don't trip on those 0x123 IPs etc..)
      # https://hg.mozilla.org/mozilla-central/file/tip/docshell/base/nsDefaultURIFixup.cpp
      elsif ($proto eq 'http://' && $auth eq '' &&
             $nhost ne 'localhost' && $port eq '80' &&
             $nhost =~ /^(?:www\.)?([^.]+)$/) {
        # Do not add .com to already valid schemelessly parsed domains (Bug 7891)
        unless (defined $rb && $rb->is_domain_valid($nhost)) {
          push(@nuris, join('', $proto, 'www.', $1, '.com', $rest));
        }
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
sub get_user_groups {
  my $suid = shift;
  dbg("util: get_user_groups: uid is $suid\n");
  my ($user, $gid) = (getpwuid($suid))[0,3];
  my $rgids = "$gid ";
  while (my($name,$gid,$members) = (getgrent())[0,2,3]) {
    if (grep { $_ eq $user } split(/ /, $members)) {
      $rgids .= "$gid ";
      dbg("util: get_user_groups: added $gid ($name) to group list which is now: $rgids\n");
    }
  }
  endgrent;
  chop $rgids;
  return ($rgids);
}



sub setuid_to_euid {
  return if (RUNNING_ON_WINDOWS);

  # remember the target uid, the first number is the important one
  my $touid = $>;
  my $gids = get_user_groups($touid);
  my ( $pgid, $supgs ) = split (' ',$gids,2);
  defined $supgs or $supgs=$pgid;
  my $prgid = 0 + $(; # bug 8043 - Only set rgid if it isn't already one of the euid's groups
  if ( ($prgid == 0) or not (grep { $_ == $prgid } split(/ /, ${(}))) {
    # setgid only works if euid is root, have to set that temporarily
    $> = 0;
    if ($> != 0) { warn("util: seteuid to 0 failed: $!"); }
    dbg("util: changing real primary gid from $( to $pgid and supplemental groups to $supgs to match effective uid $touid");
    $! = 0; POSIX::setgid($pgid);
    if ($!) { warn("util: POSIX::setgid $pgid failed: $!\n"); }
    $! = 0; $( = $pgid;
    if ($!) { warn("util: failed to set gid $pgid: $!\n"); }
    $! = 0; $) = "$pgid $supgs";
    if ($!) {
      # could be perl 5.30 bug #134169, let's be safe
      if (grep { $_ eq '0' } split(/ /, ${)})) {
        die("util: failed to set effective gid $pgid $supgs: $!\n");
      } else {
        warn("util: failed to set effective gid $pgid $supgs: $!\n");
      }
    }
  }
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

  my @cmdline;
  my $startquote = 0;
  my $ntok;
  foreach my $tok ( @_ ) {
   if(defined $tok && ($tok =~ /^\"/) && ($tok !~ /\"$/)) {
     $startquote = 1;
   }
   if($startquote) {
     $ntok .= " " if($tok !~ /^\"/);
     $ntok =~ s/\"// if defined $ntok;
     $ntok .= $tok;
   }
   if($startquote && defined $tok && ($tok =~ /\"$/)) {
     $startquote = 0;
     $ntok =~ s/\"// if defined $ntok;
     push(@cmdline, $ntok);
     undef $ntok;
   } elsif(not $startquote) {
     push(@cmdline, $tok);
   }
  }
  if (RUNNING_ON_WINDOWS) {
    return helper_app_pipe_open_windows (@cmdline);
  } else {
    return helper_app_pipe_open_unix (@cmdline);
  }
}

sub helper_app_pipe_open_windows {
  my ($fh, $stdinfile, $duperr2out, @cmdline) = @_;

  # use a traditional open(FOO, "cmd |")
  $cmdline[0] = '"'.$cmdline[0].'"' if ($cmdline[0] !~ /^\".*\"$/);
  my $cmd = join(' ', @cmdline);
  if ($stdinfile) { $cmd .= qq/ < "$stdinfile"/; }
  if ($duperr2out) {
    # Support custom file target for STDERR, if ">file" specified
    # Caller must make sure the destination is safe and untainted
    if ($duperr2out =~ /^>/) {
      $cmd .= " 2$duperr2out";
    } else {
      $cmd .= " 2>&1";
    }
  }
  return open ($fh, $cmd.'|');
}

sub force_die {
  my ($statrc, $msg) = @_;

  # note use of eval { } scope in logging -- paranoia to ensure that a broken
  # $SIG{__WARN__} implementation will not interfere with the flow of control
  # here, where we *have* to die.
  if ($msg) {
    eval { warn $msg };  # hmm, STDERR may no longer be open
    eval { dbg("util: force_die: $msg") };
  }

  if (am_running_on_windows()) {
    exit($statrc); # on Windows _exit would terminate parent too BUG 8007
  } else {
    POSIX::_exit($statrc);  # avoid END and destructor processing 
    kill('KILL',$$) if ($statrc);  # somehow this breaks those places that are calling it to exit(0)
  }
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
    dbg("util: setuid: ruid=$< euid=$> rgid=$( egid=$)");

    # now set up the fds.  due to some weirdness, we may have to ensure that
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

      # Support custom file target for STDERR, if ">file" specified
      # Caller must make sure the destination is safe and untainted
      my $errout;
      if ($duperr2out =~ /^>/) {
        $errout = $duperr2out;
      } else {
        $errout = ">&STDOUT";
      }
      open (STDERR, $errout) or die "dup $errout failed: $!";
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
  force_die(6, sprintf('util: failed to spawn a process "%s": %s',
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
    POSIX::sigaction POSIX::SIGALRM(), POSIX::SigAction->new($handler);
  }
}

###########################################################################

# Bug 6802 helper function, use /aa for perl 5.16+
my $qr_sa;
if ($] >= 5.016) {
  eval '$qr_sa = sub { return qr/$_[0]/aa; }';
} else {
  eval '$qr_sa = sub { return qr/$_[0]/; }';
}

# returns ($compiled_re, $error)
# if any errors, $compiled_re = undef, $error has string
# args:
# - regexp
# - strip_delimiters (default: 1) (value 2 means, try strip, but don't error)
# - ignore_always_matching (default: 0)
sub compile_regexp {
  my ($re, $strip_delimiters, $ignore_always_matching) = @_;
  local($1);

  # Do not allow already compiled regexes or other funky refs
  if (ref($re) ne '') {
    return (undef, 'ref passed: '.ref($re));
  }

  # try stripping by default
  $strip_delimiters = 1 if !defined $strip_delimiters;

  # OK, try to remove any normal perl-style regexp delimiters at
  # the start and end, and modifiers at the end if present,
  # so we can validate those too.
  my $origre = $re;
  my $delim_end = '';

  if ($strip_delimiters >= 1) {
    # most common delimiter
    if ($re =~ s{^/}{}) {
      $delim_end = '/';
    }
    # symmetric delimiters
    elsif ($re =~ s/^(?:m|qr)([\{\(\<\[])//) {
      ($delim_end = $1) =~ tr/\{\(\<\[/\}\)\>\]/;
    }
    # any non-wordchar delimiter, but let's ignore backslash..
    elsif ($re =~ s/^(?:m|qr)(\W)//) {
      $delim_end = $1;
      if ($delim_end eq '\\') {
        return (undef, 'backslash delimiter not allowed');
      }
    }
    elsif ($strip_delimiters != 2) {
      return (undef, 'missing regexp delimiters');
    }
  }

  # cut end delimiter, mods
  my $mods;
  if ($delim_end) {
    # Ignore e because paranoid
    if ($re =~ s/\Q${delim_end}\E([a-df-z]*)\z//) {
      $mods = $1;
    } else {
      return (undef, 'invalid end delimiter/mods');
    }
  }

  # paranoid check for eval exec (?{foo}), in case someone
  # actually put "use re 'eval'" somewhere..
  if (index($re, '?{') >= 0 && $re =~ /\(\?\??\{/) {
    return (undef, 'eval (?{}) found');
  }

  # check unescaped delimiter, but only if it's not symmetric,
  # those will fp on .{0,10} [xyz] etc, no need for so strict checks
  # since these regexes don't end up in eval strings anyway
  if ($delim_end && $delim_end !~ tr/\}\)\]//) {
    # first we remove all escaped backslashes "\\"
    my $dbs_stripped = $re;
    $dbs_stripped =~ s/\\\\//g if index($dbs_stripped, '\\\\') >= 0;
    # now we can properly check if something is unescaped
    if ($dbs_stripped =~ /(?<!\\)\Q${delim_end}\E/) {
      return (undef, "unquoted delimiter '$delim_end' found");
    }
  }

  if ($ignore_always_matching) {
    if (my $err = is_always_matching_regexp($re)) {
      return (undef, "always matching regexp: $err");
    }
  }

  # now prepend the modifiers, in order to check if they're valid
  if ($mods) {
    $re = '(?'.$mods.')'.$re;
  }

  # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
  my $compiled_re;
  $re = untaint_var($re);
  my $ok = eval {
    # don't dump deprecated warnings to user STDERR
    # but die on any other warning for safety?
    local $SIG{__WARN__} = sub {
      if ($_[0] !~ /deprecated/i) {
        die "$_[0]\n";
      }
    };
    $compiled_re = $qr_sa->($re);
    1;
  };
  if ($ok && ref($compiled_re) eq 'Regexp') {
    #$origre = untaint_var($origre);
    #dbg("config: accepted regex '%s' => '%s'", $origre, $compiled_re);
    return ($compiled_re, '');
  } else {
    my $err = $@ ne '' ? $@ : "errno=$!"; chomp $err;
    $err =~ s/ at .*? line \d.*$//;
    return (undef, $err);
  }
}

sub is_always_matching_regexp {
  my ($re) = @_;

  if ($re eq '') {
    return "empty";
  }
  elsif ($re =~ /(?<!\\)\|\|/) {
    return "contains '||'";
  }
  elsif ($re =~ /^\||\|(?<!\\\|)$/) {
    return "starts or ends with '|'";
  }

  return "";
}

# convert compiled regexp (?^i:foo) presentation to string (?i)foo
# NOTE: This function is mainly used for Rule2XSBody purposes, since it
# expects "(?i)foo" formatted strings.  Generally there should NOT be need
# to use this function.  If you need a string, try "".$re / "".qr(foo.*bar).
sub qr_to_string {
  my ($re) = @_;

  return undef unless ref($re) eq 'Regexp'; ## no critic (ProhibitExplicitReturnUndef)
  $re = "".$re; # stringify

  local($1);
  my $mods;
  # perl >=5.14 (?^i:foo)
  if ($re =~ s/^\(\?\^([a-z]*)://) {
    $mods = $1;
    $re =~ s/\)\s*\z//;
  }
  # perl <5.14 (?i-xsm:foo)
  elsif ($re =~ s/^\(\?([a-z]*)-[a-z]*://) {
    $mods = $1;
    $re =~ s/\)\s*\z//;
  }

  return ($mods ? "(?$mods)$re" : $re);
}

###########################################################################

###
### regexp_remove_delimiters and make_qr DEPRECATED, to be removed
### compile_regexp() should be used everywhere
###

# Removes any normal perl-style regexp delimiters at
# the start and end, and modifiers at the end (if present).
# If modifiers are found, they are inserted into the pattern using
# the /(?i)/ idiom.

sub regexp_remove_delimiters {
  my ($re) = @_;

  warn("deprecated Util regexp_remove_delimiters() called\n");

  my $delim;
  if (!defined $re || $re eq '') {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
  elsif ($re =~ s/^m?\{//) {             # m{foo/bar}
    $delim = '}';
  }
  elsif ($re =~ s/^m?\[//) {             # m[foo/bar]
    $delim = ']';
  }
  elsif ($re =~ s/^m?\(//) {             # m(foo/bar)
    $delim = ')';
  }
  elsif ($re =~ s/^m?<//) {              # m<foo/bar>
    $delim = '>';
  }
  elsif ($re =~ s/^m?(\W)//) {           # m#foo/bar#
    $delim = $1;
  } else {                              # /foo\/bar/ or !foo/bar!
    # invalid
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }

  if ($re !~ s/\Q${delim}\E([imsx]*)$//) {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }

  my $mods = $1;
  if ($mods) {
    $re = "(?".$mods.")".$re;
  }

  return $re;
}

# turn "/foobar/i" into qr/(?i)foobar/

sub make_qr {
  my ($re) = @_;

  warn("deprecated Util make_qr() called\n");

  $re = regexp_remove_delimiters($re);
  return undef if !defined $re || $re eq ''; ## no critic (ProhibitExplicitReturnUndef)
  my $compiled_re;
  if (eval { $compiled_re = qr/$re/; 1; } && ref($compiled_re) eq 'Regexp') {
    return $compiled_re;
  } else {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }
}

###########################################################################

###########################################################################

sub get_my_locales {
  my ($ok_locales) = @_;

  my @locales = split(/\s+/, $ok_locales);
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

# Given a domain name, produces a listref of successively stripped down
# parent domains, e.g. a domain '2.10.Example.COM' would produce a list:
# '2.10.example.com', '10.example.com', 'example.com', 'com'
#
sub domain_to_search_list {
  my ($domain) = @_;

  $domain =~ s/^\.+//; $domain =~ s/\.+\z//;  # strip leading and trailing dots
  return [] unless $domain;                   # no domain left
  return [$domain] if index($domain, '[') == 0; # don't split address literals

  # initialize
  $domain = lc $domain;
  my @search_keys = ($domain);
  my $pos = 0;

  # split domain into search keys
  while (($pos = index($domain, '.', $pos+1)) != -1) {
    push @search_keys, substr($domain, $pos+1);
  }

  # enforce some sanity limit
  if (@search_keys > 20) {
    @search_keys = @search_keys[$#search_keys-19 .. $#search_keys];
  }

  return \@search_keys;
}

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

# RFC 5322 (+IDN?) parsing of addresses and names from To/From/Cc.. headers
#
# Return array of hashes, containing at minimum name,address,user,host
#
# Override parser with SA_HEADER_ADDRESS_PARSER environment variable

our $header_address_parser;
our $email_address_xs;
our $email_address_xs_fix_address;
BEGIN {
  # SA_HEADER_ADDRESS_PARSER=1 only use internal parser
  # SA_HEADER_ADDRESS_PARSER=2 only use Email::Address::XS
  # By default internal is preferred, will defer for some cases
  $header_address_parser = untaint_var($ENV{'SA_HEADER_ADDRESS_PARSER'});
  if ((!defined $header_address_parser || $header_address_parser eq '2') &&
       eval 'use Email::Address::XS; 1;') {
    $email_address_xs = 1;
    if (version->parse(Email::Address::XS->VERSION) < version->parse(1.02)) {
      $email_address_xs_fix_address = 1;
    }
  }
}

# Helper for internal parser
our $header_address_mailre = qr/
  # user
  (?:
    # quoted localpart
    " (?:|(?:[^"\\]++|\\.)*+) " |
    # or un-quoted localpart
    [^\@\s\<\>\(\)\[\]\,\:\;]+
  )
  # domain
  \@ (?: [^\"\s\<\>\(\)\[\]\,\:\;]+ | \[ [\d:.]+ \] )
/ix;

# Very relaxed internal parser
# Only handles non-nested comments in some places
our $header_address_re = qr/^
  \s*
  (?:
    # optional phrase, quoted or non-quoted
    (?:
      ( (?: " (?:|(?:[^"\\]++|\\.)*+) " | [^",;<]++ )+ )
      \s*
    )?
    # and enclosed email (or empty)
    # ... allow whitespace in localpart
    < \s* ( [^>\@]* \S+ | \s* ) \s* >
    # some output duplicate enclosures..
    (?: \s* < \s* (?: (?: " (?:|(?:[^"\\]++|\\.)*+) " )? \S+ | \s* ) \s* > )*
  |
    # or standalone email or phrase
    (?:
      ( $header_address_mailre ) |
      ( (?: " (?:|(?:[^"\\]++|\\.)*+) " | [^",;<]++ )+ )
    )
  )
  # possible comment after (no nested support here)
  (?: \s* \( ( (?:|(?:[^()\\]++|\\.)*+) ) \) )?
  # Followed by comma (semi-colon sometimes) or finish
  \s* (?: [,;] | \z )
/ix;

#
# Main public function
# expected input is header contents without Header: itself
#
sub parse_header_addresses {
  my ($str) = @_;

  return if !defined $str || $str !~ /\S/;

  my @results;

  # Internal parser
  if (!$header_address_parser || $header_address_parser eq '1') {
    @results = _parse_header_addresses($str);
  }

  # Email::Address::XS
  if ($email_address_xs) {
    if (!$header_address_parser || $header_address_parser eq '2') {
      # Only consulted if no internal results, or there doesn't
      # seem to have enough results, or possible nested comments ( (
      my $maybe_nested = scalar($str =~ /\(/) >= 2;
      if (!@results || $maybe_nested || @results < scalar($str =~ tr/,//)+1) {
        my @results_xs = _parse_header_addresses_xs($str);
        # If we have more results than internal, use it, or nested
        if (@results_xs > @results || $maybe_nested) {
          return @results_xs;
        }
      }
    }
  }

  return @results;
}

sub get_part_details {
    my ($pms, $part, $prefer_contentdisposition) = @_;
    #https://en.wikipedia.org/wiki/MIME#Content-Disposition
    #https://github.com/mikel/mail/pull/464

    my $ctt = $part->get_header('content-type');
    return undef unless defined $ctt; ## no critic (ProhibitExplicitReturnUndef)

    my $cte = lc($part->get_header('content-transfer-encoding') || '');
    return undef unless ($cte =~ /^(?:base64|quoted\-printable)$/); ## no critic (ProhibitExplicitReturnUndef)

    $ctt = _decode_part_header($part, $ctt || '');

    my $name = '';
    my $cttname = '';
    my $ctdname = '';

    if ($ctt =~ m/name\s*=\s*["']?([^"';]*)/is) {
      $cttname = $1;
      $cttname =~ s/\s+$//;
    }

    my $ctd = $part->get_header('content-disposition');
    $ctd = _decode_part_header($part, $ctd || '');

    if ($ctd =~ m/filename\s*=\s*["']?([^"';]*)/is) {
      $ctdname = $1;
      $ctdname =~ s/\s+$//;
    }

    if (lc $ctdname eq lc $cttname) {
      $name = $ctdname;
    } elsif ($ctdname eq '') {
      $name = $cttname;
    } elsif ($cttname eq '') {
      $name = $ctdname;
    } else {
      if ((defined $ctdname) and $prefer_contentdisposition) {
        $name = $ctdname;
      } else {
        $name = $cttname;
      }
    }

    return $ctt, $ctd, $cte, $name;
}

sub _decode_part_header {
  my($part, $header_field_body) = @_;

  return '' unless defined $header_field_body && $header_field_body ne '';

  # deal with folding and cream the newlines and such
  $header_field_body =~ s/\n[ \t]+/\n /g;
  $header_field_body =~ s/\015?\012//gs;

  local($1,$2,$3);

  # Multiple encoded sections must ignore the interim whitespace.
  # To avoid possible FPs with (\s+(?==\?))?, look for the whole RE
  # separated by whitespace.
  1 while $header_field_body =~
            s{ ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) \s+
               ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) }
             {$1$2}xsg;

  # transcode properly encoded RFC 2047 substrings into UTF-8 octets,
  # leave everything else unchanged as it is supposed to be UTF-8 (RFC 6532)
  # or plain US-ASCII
  $header_field_body =~
    s{ (?: = \? ([A-Za-z0-9_-]+) \? ([bqBQ]) \? ([^?]*) \? = ) }
     { $part->__decode_header($1, uc($2), $3) }xsge;

  return $header_field_body;
}

# Check some basic parsing mistakes
sub _valid_parsed_address {
  return 0 if !defined $_[0];
  return 0 if index($_[0], '""@') == 0;
  return 0 if scalar($_[0] =~ tr/"//) == 1;
  return 1;
}

#
# v0.1, improved internal parser, no support for comments in strange
# places or nested comments, but handled a large corpus atleast 99% the
# same as Email::Address::XS and in some cases even better (retains some
# more name/addr info, even when not fully valid).
#
sub _parse_header_addresses {
  local $_ = shift;
  local ($1, $2, $3, $4, $5);

  # Clear trailing whitespace
  s/\s+\z//s;

  # Strip away all escaped blackslashes, simplifies processing a lot
  s/\\\\//g;

  # Reduce group address
  s/^[^"()<>]+:\s*(.*?)\s*(?:;.*)?/$1/gs;

  # Skip empty
  return unless /\S/;

  my @results;
  while (s/$header_address_re//igs) {
    my $phrase = defined $1 ? $1 :
                 defined $4 ? $4 : undef;
    my $address = defined $2 ? $2 :
                defined $3 ? $3 : undef;
    my $comment = defined $5 ? $5 : undef;

    my ($user, $host, $invalid);

    # Check relaxed <> capture
    if (defined $2) {
      # Remove comments (no nested support here)
      $address =~ s/\((?:|(?:[^()\\]++|\\.)*+)\)//gs;
      # Validate as somewhat email looking
      if ($address !~ /^$header_address_mailre$/) {
        $address = undef;
      }
    }

    # Validate some other address oddities
    if (!_valid_parsed_address($address)) {
      $address = undef;
    }

    if (defined $phrase) {
      my $newphrase;
      # Parse phrase as quoted and unquoted parts
      while ($phrase =~ /(?:"(|(?:[^"\\]++|\\.)*+)"|([^"]++))/igs) {
        my $qs = $1;
        my $nqs = $2;
        if (defined $qs) {
          # Unescape things inside quoted string
          $qs =~ s/\\(?!\\)//g;
          $qs =~ s/\\\\/\\/g;
          #$qs =~ s/\\//g;
          $newphrase .= $qs;
        } else {
          # Remove comments (no nested support here)
          $nqs =~ s/\((?:|(?:[^()\\]++|\\.)*+)\)//gs;
          $newphrase .= $nqs;
        }
      }
      $phrase = $newphrase;

      # If we only have phrase which looks email, swap when valid
      # Check all in one if, either swap or don't
      if (!defined $address &&
          $phrase =~ /^$header_address_mailre$/i &&
          _valid_parsed_address($phrase) &&
          $phrase =~ /^[^\@]*\@([^\@]*)/ &&
          is_fqdn_valid(idn_to_ascii($1), 1)) {
        $address = $phrase;
        $phrase = undef;
      } else {
        # Remove redundant phrase==email?
        if (defined $address && $phrase eq $address) {
          $phrase = undef;
        } elsif ($phrase eq '') {
          $phrase = undef;
        }
      }
    }

    # Copy comment to phrase if not defined
    if (!defined $phrase && defined $comment) {
      $phrase = $comment;
    }

    if (defined $address) {
      # Unescape quoted localpart
      #if ($address =~ /^"(.*?)"\@(.*)/) {
      #  $user = $1;
      #  $host = $2;
      #  $user =~ s/\\//g;
      #  $user =~ s/\s+//gs;
      #  $address = "$user\@$host";
      #}
      # Strip sometimes seen quotes
      #$address =~ s/^'(.*?)'$/$1/;
      $address =~ s/^(([^\@]*)\@([^\@]*)).*/$1/;
      ($user, $host) = ($2, $3);
    }

    $invalid = !defined $host || !is_fqdn_valid(idn_to_ascii($host), 1);
    push @results, {
      'phrase' => $phrase,
      'user' => $user,
      'host' => $host,
      'address' => $address,
      'comment' => $comment,
      'invalid' => $invalid
    };
  }

  # Was something left unparsed?
  if (index($_, '@') != -1) {
    # Last ditch effort, examples:
    # =?UTF-8?Q?"Foobar"_<noreply@foobar.com>?=
    # =?utf-8?Q?"Foobar"?=<info=foobar.com@mlsend.com>
    while (/<($header_address_mailre)>/igs) {
      my $address = $1;
      next if !_valid_parsed_address($address);
      $address =~ s/^(([^\@]*)\@([^\@]*)).*/$1/;
      my ($user, $host) = ($2, $3);
      my $invalid = !is_fqdn_valid(idn_to_ascii($host), 1);
      push @results, {
        'phrase' => undef,
        'user' => $user,
        'host' => $host,
        'address' => $address,
        'comment' => undef,
        'invalid' => $invalid
      };
    }
  }

  return if !@results;
  return @results;
}

sub _parse_header_addresses_xs {
  my ($str) = @_;

  # Strip away all escaped blackslashes, simplifies processing a lot
  $str =~ s/\\\\//g;

  my @results;
  my @addrs = Email::Address::XS->parse($str);

  local ($1, $2);
  foreach my $addr (@addrs) {
    my $name = $addr->name;
    my $address = $addr->address;
    my $user = $addr->user;
    my $host = $addr->host;
    my $phrase = $addr->phrase;
    my $comment = $addr->comment;
    my $invalid;

    # Workaround Bug 5201 for Email::Address::XS
    # From: "joe+foobar@example.com"
    # If everything else is missing but phrase looks like
    # an email, let's assume it is (hostname verifies)
    if (!defined $address && !defined $user &&
        !defined $comment && defined $phrase &&
        _valid_parsed_address($phrase) &&
        $phrase =~ /^([^\s\@]+)\@([^\s\@]+)$/ &&
        is_fqdn_valid(idn_to_ascii($2), 1))
    {
      $user = $1;
      $host = $2;
      $address = $phrase;
      $name = $user;
      $invalid = 0;
      $phrase = undef;
    }
    else {
      $invalid = !$addr->is_valid;
    }

    # Version <1.02 borks address if both user+host are UTF-8
    if ($email_address_xs_fix_address) {
      if (defined $user && defined $host) {
        # <"Another User"@foo> loses quotes in user, add back
        if (index($user, ' ') != -1 &&
            index($user, '"') == -1) {
          $user = '"'.$user.'"';
        }
        $address = $user.'@'.$host;
      }
    }

    # Copy comment to phrase if not defined
    if (!defined $phrase && defined $comment) {
      $phrase = $comment;
    }

    # Use input as name if nothing found
    if (!defined $phrase && !defined $address) {
      $phrase = $str;
    }

    push @results, {
      'phrase' => $phrase,
      'user' => $user,
      'host' => $host,
      'address' => $address,
      'comment' => $comment,
      'invalid' => $invalid
    };
  }

  return @results;
}

1;

=back

=cut
