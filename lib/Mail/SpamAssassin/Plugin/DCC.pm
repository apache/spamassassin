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

# Changes since SpamAssassin 3.3.2:
#   support for DCC learning.  See dcc_learn_score.
#   deal with orphan dccifd sockets
#   use `cdcc -q` to not stall waiting to find a DCC server when deciding
#     whether DCC checks are enabled
#   use dccproc -Q or dccifd query if a pre-existing X-DCC header shows
#     the message has already been reported
#   dccproc now uses -w /var/dcc/whiteclnt so it acts more like dccifd
#   warn about the use of ancient versions of dccproc and dccifd
#   turn off dccifd greylisting
#   query instead of reporting mail messages that contain X-DCC headers
#     and so has probably already been reported
#   try harder to find dccproc and cdcc when not explicitly configured
#	Rhyolite Software DCC 2.3.140-1.4 $Revision$

=head1 NAME

Mail::SpamAssassin::Plugin::DCC - perform DCC check of messages

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::DCC

  full DCC_CHECK	eval:check_dcc()
  full DCC_CHECK_50_79	eval:check_dcc_reputation_range('50','79')

=head1 DESCRIPTION

The DCC or Distributed Checksum Clearinghouse is a system of servers
collecting and counting checksums of millions of mail messages.
The counts can be used by SpamAssassin to detect and filter spam.

See https://www.dcc-servers.net/dcc/ for more information about DCC.

Note that DCC is disabled by default in C<v310.pre> because its use requires
software that is not distributed with SpamAssassin and that has license
restrictions for certain commercial uses.
See the DCC license at https://www.dcc-servers.net/dcc/LICENSE for details.

Enable it by uncommenting the "loadplugin Mail::SpamAssassin::Plugin::DCC"
confdir/v310.pre or by adding this line to your local.pre.  It might also
be necessary to install a DCC package, port, rpm, or equivalent from your
operating system distributor or a tarball from the primary DCC source
at https://www.dcc-servers.net/dcc/#download
See also https://www.dcc-servers.net/dcc/INSTALL.html

=head1 TAGS

The following tags are added to the set, available for use in reports,
header fields, other plugins, etc.:

  _DCCB_    DCC server ID in X-DCC-*-Metrics header field name
  _DCCR_    X-DCC-*-Metrics header field body
  _DCCREP_  DCC Reputation or percent bulk mail (0..100) from
	      commercial DCC software

=cut

package Mail::SpamAssassin::Plugin::DCC;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str);
use Errno qw(ENOENT EACCES);
use IO::Socket;
use IO::Select;

our @ISA = qw(Mail::SpamAssassin::Plugin);

our $io_socket_module_name;
BEGIN {
  if (eval { require IO::Socket::IP }) {
    $io_socket_module_name = 'IO::Socket::IP';
  } elsif (eval { require IO::Socket::INET6 }) {
    $io_socket_module_name = 'IO::Socket::INET6';
  } elsif (eval { require IO::Socket::INET }) {
    $io_socket_module_name = 'IO::Socket::INET';
  }
}

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # are network tests enabled?
  if ($mailsaobject->{local_tests_only}) {
    $self->{dcc_disabled} = 1;
    dbg("dcc: local tests only, disabling DCC");
  }

  $self->register_eval_rule("check_dcc", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_dcc_reputation_range", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item use_dcc (0|1)		(default: 1)

Whether to use DCC, if it is available.

=cut

  push(@cmds, {
    setting => 'use_dcc',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=item use_dcc_rep (0|1)		(default: 1)

Whether to use the commercial DCC Reputation feature, if it is available. 
Note that reputation data is free for all starting from DCC 2.x version,
where it's automatically used.

=cut

  push(@cmds, {
    setting => 'use_dcc_rep',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=item dcc_body_max NUMBER

=item dcc_fuz1_max NUMBER

=item dcc_fuz2_max NUMBER

Sets how often a message's body/fuz1/fuz2 checksum must have been reported
to the DCC server before SpamAssassin will consider the DCC check hit.
C<999999> is DCC's MANY count.

The default is C<999999> for all these options.

=item dcc_rep_percent NUMBER

Only the commercial DCC software provides DCC Reputations (but starting from
DCC 2.x version it is available for all).  A DCC Reputation is the
percentage of bulk mail received from the last untrusted relay in the path
taken by a mail message as measured by all commercial DCC installations. 
See http://www.rhyolite.com/dcc/reputations.html You C<must> whitelist your
trusted relays or MX servers with MX or MXDCC lines in /var/dcc/whiteclnt as
described in the main DCC man page to avoid seeing your own MX servers as
sources of bulk mail.  See
https://www.dcc-servers.net/dcc/dcc-tree/dcc.html#White-and-Blacklists The
default is C<90>.

=cut

  push (@cmds, {
    setting => 'dcc_body_max',
    default => 999999,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  },
  {
    setting => 'dcc_fuz1_max',
    default => 999999,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  },
  {
    setting => 'dcc_fuz2_max',
    default => 999999,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  },
  {
    setting => 'dcc_rep_percent',
    default => 90,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=back

=head1 ADMINISTRATOR SETTINGS

=over 4

=item dcc_timeout n		(default: 5)

How many seconds you wait for DCC to complete, before scanning continues
without the DCC results. A numeric value is optionally suffixed by a
time unit (s, m, h, d, w, indicating seconds (default), minutes, hours,
days, weeks).

=cut

  push (@cmds, {
    setting => 'dcc_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION,
  });

=item dcc_home STRING

This option tells SpamAssassin where to find the dcc homedir.
If not specified, try to use the locally configured directory
from the C<cdcc homedir> command.
Try /var/dcc if that command fails.

=cut

  push (@cmds, {
    setting => 'dcc_home',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = untaint_file_path($value);
      my $stat_errn = stat($value) ? 0 : 0+$!;
      if ($stat_errn != 0 || !-d _) {
	my $msg = $stat_errn == ENOENT ? "does not exist"
		  : !-d _ ? "is not a directory" : "not accessible: $!";
	info("config: dcc_home \"$value\" $msg");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{dcc_home} = $value;
    }
  });

=item dcc_dccifd_path STRING

This option tells SpamAssassin where to find the dccifd socket instead
of a local Unix socket named C<dccifd> in the C<dcc_home> directory.
If a socket is specified or found, use it instead of C<dccproc>.

If specified, C<dcc_dccifd_path> is the absolute path of local Unix socket
or an INET socket specified as C<[Host]:Port> or C<Host:Port>.
Host can be an IPv4 or IPv6 address or a host name
Port is a TCP port number. The brackets are required for an IPv6 address.

The default is C<undef>.

=cut

  push (@cmds, {
    setting => 'dcc_dccifd_path',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if (!defined $value || $value eq '') {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }

      local($1,$2,$3);
      if ($value =~ m{^ (?: \[ ([^\]]*) \] | ([^:]*) ) : ([^:]*) \z}sx) {
	my $host = untaint_var(defined $1 ? $1 : $2);
	my $port = untaint_var($3);
	if (!$host) {
	  info("config: missing or bad host name in dcc_dccifd_path '$value'");
	  return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}
	if (!$port || $port !~ /^\d+\z/ || $port < 1 || $port > 65535) {
	  info("config: bad TCP port number in dcc_dccifd_path '$value'");
	  return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}

	$self->{dcc_dccifd_host} = $host;
	$self->{dcc_dccifd_port} = $port;
	dbg("config: dcc_dccifd_path set to [%s]:%s", $host, $port);

      } else {
	# assume a unix socket
	if ($value !~ m{^/}) {
	  info("config: dcc_dccifd_path '$value' is not an absolute path");
	  # return $Mail::SpamAssassin::Conf::INVALID_VALUE;  # abort or accept?
	}
	$value = untaint_file_path($value);

	$self->{dcc_dccifd_socket} = $value;
	dbg("config: dcc_dccifd_path set to local socket %s", $value);
	dbg("dcc: dcc_dccifd_path set to local socket %s", $value);
      }

      $self->{dcc_dccifd_path_raw} = $value;
    }
  });

=item dcc_path STRING

Where to find the C<dccproc> client program instead of relying on SpamAssassin
to find it in the current PATH or C<dcc_home/bin>. This must often be set,
because the current PATH is cleared by I<taint mode> in the Perl interpreter,

If a C<dccifd> socket is found in C<dcc_home> or specified explicitly
with C<dcc_dccifd_path>, use the C<dccifd(8)> interface instead of C<dccproc>.

The default is C<undef>.


=cut

  push (@cmds, {
    setting => 'dcc_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = untaint_file_path($value);
      if (!-x $value) {
	info("config: dcc_path '$value' is not executable");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{dcc_path} = $value;
    }
  });

=item dcc_options options

Specify additional options to the dccproc(8) command.  Only
characters in the range [0-9A-Za-z ,._/-] are allowed for security reasons.

The default is C<undef>.

=cut

  push (@cmds, {
    setting => 'dcc_options',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ m{^([0-9A-Za-z ,._/-]+)$}) {
	info("config: dcc_options '$value' contains impermissible characters");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{dcc_options} = $1;
    }
  });

=item dccifd_options options

Specify additional options to send to the dccifd daemon with
the ASCII protocol described on the dccifd(8) man page.
Only characters in the range [0-9A-Za-z ,._/-] are allowed for security reasons.

The default is C<undef>.

=cut

  push (@cmds, {
    setting => 'dccifd_options',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ m{^([0-9A-Za-z ,._/-]+)$}) {
	info("config: dccifd_options '$value' contains impermissible characters");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{dccifd_options} = $1;
    }
  });

=item dcc_learn_score n		(default: undef)

Report messages with total scores this much larger than the
SpamAssassin spam threshold to DCC as spam.

=back

=cut

  push (@cmds, {
    setting => 'dcc_learn_score',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub ck_dir {
  my ($self, $dir, $tgt, $src) = @_;

  $dir = untaint_file_path($dir);
  if (!stat($dir)) {
    my $dir_errno = 0+$!;
    if ($dir_errno == ENOENT) {
      dbg("dcc: $tgt $dir from $src does not exist");
    } else {
      dbg("dcc: $tgt $dir from $src is not accessible: $!");
    }
    return;
  }
  if (!-d _) {
    dbg("dcc: $tgt $dir from $src is not a directory");
    return;
  }

  $self->{main}->{conf}->{$tgt} = $dir;
  dbg("dcc: use '$tgt $dir' from $src");
}

sub find_dcc_home {
  my ($self) = @_;

  # just once
  return if defined $self->{dcc_version};
  $self->{dcc_version} = '?';

  my $conf = $self->{main}->{conf};

  # Get the DCC software version for talking to dccifd and formatting the
  # dccifd options and the built-in DCC homedir.  Use -q to prevent delays.
  my $cdcc_home;
  my $cdcc = $self->dcc_pgm_path('cdcc');
  my $cmd = '-qV homedir libexecdir';
  if ($cdcc && open(CDCC, "$cdcc $cmd 2>&1 |")) {
    my $cdcc_output = do { local $/ = undef; <CDCC> };
    close CDCC;

    $cdcc_output =~ s/\s+/ /gs;		# everything in 1 line for debugging
    $cdcc_output =~ s/\s+$//;
    dbg("dcc: `%s %s` reports '%s'", $cdcc, $cmd, $cdcc_output);
    $self->{dcc_version} = ($cdcc_output =~ /^(\d+\.\d+\.\d+)/) ? $1 : '';
    $cdcc_home = ($cdcc_output =~ /\s+homedir=(\S+)/) ? $1 : '';
    if ($cdcc_output =~ /\s+libexecdir=(\S+)/) {
      $self->ck_dir($1, 'dcc_libexec', 'cdcc');
    }
  }

  # without a home, try the homedir from cdcc
  if (!$conf->{dcc_home} && $cdcc_home) {
    $self->ck_dir($cdcc_home, 'dcc_home', 'cdcc');
  }
  # finally fall back to /var/dcc
  if (!$conf->{dcc_home}) {
    $self->ck_dir($conf->{dcc_home} = '/var/dcc', 'dcc_home', 'default')
  }

  # fall back to $conf->{dcc_home}/libexec or /var/dcc/libexec for dccsight
  if (!$conf->{dcc_libexec}) {
    $self->ck_dir($conf->{dcc_home} . '/libexec', 'dcc_libexec', 'dcc_home');
  }
  if (!$conf->{dcc_libexec}) {
    $self->ck_dir('/var/dcc/libexec', 'dcc_libexec', 'dcc_home');
  }

  # format options for dccifd
  my $opts = ($conf->{dccifd_options} || '') . "\n";
  if ($self->{dcc_version} =~ /\d+\.(\d+)\.(\d+)$/ &&
      ($1 < 3 || ($1 == 3 && $2 < 123))) {
    if ($1 < 3 || ($1 == 3 && $2 < 50)) {
      info("dcc: DCC version $self->{dcc_version} is years old, ".
           "obsolete, and likely to cause problems.  ".
           "See https://www.dcc-servers.net/dcc/old-versions.html");
    }
    $self->{dccifd_lookup_options} = "header " . $opts;
    $self->{dccifd_report_options} = "header spam " . $opts;
  } else {
    # dccifd after version 1.2.123 understands "cksums" and "no-grey"
    $self->{dccifd_lookup_options} = "cksums grey-off " . $opts;
    $self->{dccifd_report_options} = "header spam grey-off " . $opts;
  }
}

sub dcc_pgm_path {
  my ($self, $pgm) = @_;
  my $pgmpath;
  my $conf = $self->{main}->{conf};

  $pgmpath = $conf->{dcc_path};
  if (defined $pgmpath && $pgmpath ne '') {
    # accept explicit setting for dccproc
    return $pgmpath if $pgm eq 'dccproc';
    # try adapting it for cdcc and everything else
    if ($pgmpath =~ s{[^/]+\z}{$pgm}s) {
      $pgmpath = untaint_file_path($pgmpath);
      if (-x $pgmpath) {
        dbg("dcc: dcc_pgm_path, found %s in dcc_path: %s", $pgm,$pgmpath);
        return $pgmpath;
      }
    }
  }

  $pgmpath = Mail::SpamAssassin::Util::find_executable_in_env_path($pgm);
  if (defined $pgmpath) {
    dbg("dcc: dcc_pgm_path, found %s in env.path: %s", $pgm,$pgmpath);
    return $pgmpath;
  }

  # try dcc_home/bin, dcc_libexec, and some desperate last attempts
  foreach my $dir (!defined $conf->{dcc_home} ? () : $conf->{dcc_home}.'/bin',
                   $conf->{dcc_libexec},
                   '/usr/local/bin', '/usr/local/dcc', '/var/dcc') {
    next unless defined $dir;
    $pgmpath = $dir . '/' . $pgm;
    if (-x $pgmpath) {
      dbg("dcc: dcc_pgm_path, found %s in %s: %s", $pgm,$dir,$pgmpath);
      return $pgmpath;
    }
  }

  return;
}

sub is_dccifd_available {
  my ($self) = @_;

  # dccifd remains available until it breaks
  return $self->{dccifd_available} if $self->{dccifd_available};

  $self->find_dcc_home();
  my $conf = $self->{main}->{conf};

  # deal with configured INET or INET6 socket
  if (defined $conf->{dcc_dccifd_host}) {
    dbg("dcc: dccifd is available via socket [%s]:%s",
	$conf->{dcc_dccifd_host}, $conf->{dcc_dccifd_port});
    return ($self->{dccifd_available} = 1);
  }

  # the first time here, compute a default local socket based on DCC home
  # from self->find_dcc_home() called elsewhere
  my $sockpath = $conf->{dcc_dccifd_socket};
  if (!$sockpath) {
      if ($conf->{dcc_dccifd_path_raw}) {
	$sockpath = $conf->{dcc_dccifd_path_raw};
      } else {
	$sockpath = "$conf->{dcc_home}/dccifd";
      }
      $conf->{dcc_dccifd_socket} = $sockpath;
  }

  # check the socket every time because it can appear and disappear
  return ($self->{dccifd_available} = 1) if (-S $sockpath && -w _ && -r _);

  dbg("dcc: dccifd is not available; no r/w socket at %s", $sockpath);
  return ($self->{dccifd_available} = 0);
}

sub is_dccproc_available {
  my ($self) = @_;
  my $conf = $self->{main}->{conf};

  # dccproc remains (un)available so check only once
  return $self->{dccproc_available} if defined $self->{dccproc_available};

  $self->find_dcc_home();
  my $dccproc = $conf->{dcc_path};
  if (!defined $dccproc || $dccproc eq '') {
    $dccproc = $self->dcc_pgm_path('dccproc');
    $conf->{dcc_path} = $dccproc;
    if (!$dccproc || ! -x $dccproc) {
      dbg("dcc: dccproc is not available: no dccproc executable found");
      return ($self->{dccproc_available} = 0);
    }
  }

  dbg("dcc: %s is available", $conf->{dcc_path});
  return ($self->{dccproc_available} = 1);
}

sub dccifd_connect {
  my($self, $tag) = @_;
  my $conf = $self->{main}->{conf};
  my $sockpath = $conf->{dcc_dccifd_socket};
  my $sock;

  if (defined $sockpath) {
    dbg("$tag connecting to local socket $sockpath");
    $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sockpath);
    info("$tag failed to connect to local socket $sockpath") if !$sock;

  } else {  # must be TCP/IP
    my $host = $conf->{dcc_dccifd_host};
    my $port = $conf->{dcc_dccifd_port};
    dbg("$tag connecting to [%s]:%s using %s",
        $host, $port, $io_socket_module_name);
    $sock = $io_socket_module_name->new(
              Proto => 'tcp', PeerAddr => $host, PeerPort => $port);
    info("$tag failed to connect to [%s]:%s using %s: %s",
         $host, $port, $io_socket_module_name, $!) if !$sock;
  }

  $self->{dccifd_available} = 0  if !$sock;
  return $sock;
}

# check for dccifd every time in case enough uses of dccproc starts dccifd
sub get_dcc_interface {
  my ($self) = @_;

  if (!$self->is_dccifd_available() && !$self->is_dccproc_available()) {
    dbg("dcc: dccifd or dccproc is not available");
    return 0;
  }

  return 1;
}

sub check_tick {
  my ($self, $opts) = @_;

  $self->_check_async($opts, 0);

  my $pms = $opts->{permsgstatus};

  # Finish callbacks
  if ($pms->{dcc_range_callbacks}) {
    while (@{$pms->{dcc_range_callbacks}}) {
      my $cb_args = shift @{$pms->{dcc_range_callbacks}};
      $self->check_dcc_reputation_range($pms, @$cb_args);
    }
  }
}

sub check_cleanup {
  my ($self, $opts) = @_;

  $self->_check_async($opts, 1);

  my $pms = $opts->{permsgstatus};

  # Finish callbacks
  if ($pms->{dcc_range_callbacks}) {
    while (@{$pms->{dcc_range_callbacks}}) {
      my $cb_args = shift @{$pms->{dcc_range_callbacks}};
      $self->check_dcc_reputation_range($pms, @$cb_args);
    }
  }
}

sub _check_async {
  my ($self, $opts, $timeout) = @_;
  my $pms = $opts->{permsgstatus};

  return if !$pms->{dcc_sock};

  my $timer = $self->{main}->time_method("check_dcc");

  $pms->{dcc_abort} =
    $pms->{dcc_abort} || $pms->{deadline_exceeded} || $pms->{shortcircuited};

  if ($pms->{dcc_abort}) {
    $timeout = 0;
  } elsif ($timeout) {
    # Calculate how much time left from original timeout
    $timeout = $self->{main}->{conf}->{dcc_timeout} -
      (time - $pms->{dcc_async_start});
    $timeout = 1 if $timeout < 1;
    $timeout = 20 if $timeout > 20; # hard sanity check
    dbg("dcc: final wait for dccifd, timeout in $timeout sec");
  }

  if (IO::Select->new($pms->{dcc_sock})->can_read($timeout)) {
    dbg("dcc: reading dccifd response");
    my @resp;
    # if DCC is ready, should never block? timeout 1s just in case
    my $timer = Mail::SpamAssassin::Timeout->new({ secs => 1 });
    my $err = $timer->run_and_catch(sub {
      local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };
      @resp = $pms->{dcc_sock}->getlines();
    });
    delete $pms->{dcc_sock};
    if ($timer->timed_out()) {
      info("dcc: dccifd read failed");
    } elsif ($err) {
      chomp $err;
      info("dcc: dccifd read failed: $err");
    } else {
      shift @resp; shift @resp; # ignore status/multistatus line
      if (@resp) {
        dbg("dcc: dccifd raw response: ".join("", @resp));
        ($pms->{dcc_x_result}, $pms->{dcc_cksums}) =
          $self->parse_dcc_response(\@resp, 'dccifd');
        if ($pms->{dcc_x_result}) {
          dbg("dcc: dccifd parsed response: $pms->{dcc_x_result}");
          ($pms->{dcc_result}, $pms->{dcc_rep}) =
            $self->check_dcc_result($pms, $pms->{dcc_x_result});
          if ($pms->{dcc_result}) {
            foreach (@{$pms->{conf}->{eval_to_rule}->{check_dcc}}) {
              $pms->got_hit($_, "", ruletype => 'eval');
            }
          } else {
            foreach (@{$pms->{conf}->{eval_to_rule}->{check_dcc}}) {
              $pms->rule_ready($_);
            }
          }
        }
      } else {
        info("dcc: empty response from dccifd?");
      }
    }
  } elsif ($pms->{dcc_abort}) {
    dbg("dcc: bailing out due to deadline/shortcircuit");
    delete $pms->{dcc_sock};
    delete $pms->{dcc_range_callbacks};
  } elsif ($timeout) {
    dbg("dcc: no response from dccifd, timed out");
    delete $pms->{dcc_sock};
    delete $pms->{dcc_range_callbacks};
  } else {
    dbg("dcc: still waiting for dccifd response");
  }
}

sub check_dnsbl {
  my($self, $opts) = @_;

  return 0 if $self->{dcc_disabled};
  return 0 if !$self->{main}->{conf}->{use_dcc};

  my $pms = $opts->{permsgstatus};

  # Check that rules are active
  return 0 if !grep {$pms->{conf}->{scores}->{$_}}
    ( @{$pms->{conf}->{eval_to_rule}->{check_dcc}},
      @{$pms->{conf}->{eval_to_rule}->{check_dcc_reputation_range}} );

  # Launch async only if dccifd found
  if ($self->is_dccifd_available()) {
    $self->_launch_dcc($pms);
  }
}

sub _launch_dcc {
  my ($self, $pms) = @_;

  return if $pms->{dcc_running};
  $pms->{dcc_running} = 1;

  my $timer = $self->{main}->time_method("check_dcc");

  # initialize valid tags
  $pms->{tag_data}->{DCCB} = '';
  $pms->{tag_data}->{DCCR} = '';
  $pms->{tag_data}->{DCCREP} = '';

  my $fulltext = $pms->{msg}->get_pristine();
  if ($fulltext eq '') {
    dbg("dcc: empty message; skipping dcc check");
    $pms->{dcc_result} = 0;
    $pms->{dcc_abort} = 1;
    return;
  }

  if (!$self->get_dcc_interface()) {
    $pms->{dcc_result} = 0;
    $pms->{dcc_abort} = 1;
    return;
  }

  #if ($pms->get('ALL-TRUSTED') =~ /^(X-DCC-[^:]*?-Metrics: .*)$/m) {
    # short-circuit if there is already a X-DCC header with value of
    # "bulk" from an upstream DCC check
    # require "bulk" because then at least one body checksum will be "many"
    # and so we know the X-DCC header is not forged by spammers
    #if ($1 =~ / bulk /) {
    #  return $self->check_dcc_result($pms, $1);
    #}
  #}

  my $envelope = $pms->{relays_external}->[0];

  ($pms->{dcc_x_result}, $pms->{dcc_cksums}) =
    $self->ask_dcc('dcc:', $pms, \$fulltext, $envelope);

  return;
}

sub check_dcc {
  my ($self, $pms) = @_;

  return 0 if $self->{dcc_disabled};
  return 0 if !$pms->{conf}->{use_dcc};
  return 0 if $pms->{dcc_abort};

  # async already handling?
  if ($pms->{dcc_async_start}) {
    return; # return undef for async status
  }

  return $pms->{dcc_result} if defined $pms->{dcc_result};

  $self->_launch_dcc($pms);
  return if $pms->{dcc_async_start}; # return undef for async status

  if (!defined $pms->{dcc_x_result}) {
    $pms->{dcc_abort} = 1;
    return 0;
  }

  ($pms->{dcc_result}, $pms->{dcc_rep}) =
    $self->check_dcc_result($pms, $pms->{dcc_x_result});

  return $pms->{dcc_result};
}

sub check_dcc_reputation_range {
  my ($self, $pms, undef, $min, $max, $cb_rulename) = @_;

  return 0 if $self->{dcc_disabled};
  return 0 if !$pms->{conf}->{use_dcc};
  return 0 if !$pms->{conf}->{use_dcc_rep};
  return 0 if $pms->{dcc_abort};

  my $timer = $self->{main}->time_method("check_dcc");

  if (exists $pms->{dcc_rep}) {
    my $result;

    # Process result
    if ($pms->{dcc_rep} < 0) {
      # Not used or missing reputation
      $result = 0;
    } else {
      # cover the entire range of reputations if not told otherwise
      $min = 0   if !defined $min;
      $max = 100 if !defined $max;
      $result = $pms->{dcc_rep} >= $min && $pms->{dcc_rep} <= $max ? 1 : 0;
      dbg("dcc: dcc_rep %s, min %s, max %s => result=%s",
        $pms->{dcc_rep}, $min, $max, $result ? 'YES' : 'no');
    }

    if (defined $cb_rulename) {
      # If callback, use got_hit()
      if ($result) {
        $pms->got_hit($cb_rulename, "", ruletype => 'eval');
      } else {
        $pms->rule_ready($cb_rulename);
      }
      return 0;
    } else {
      return $result;
    }
  } else {
    # Install callback if waiting for async result
    if (!defined $cb_rulename) {
      my $rulename = $pms->get_current_eval_rule_name();
      # array matches check_dcc_reputation_range() argument order
      push @{$pms->{dcc_range_callbacks}}, [undef, $min, $max, $rulename];
      return; # return undef for async status
    }
  }

  return 0;
}

sub check_dcc_result {
  my ($self, $pms, $x_dcc) = @_;

  my $dcc_result = 0;
  my $dcc_rep = -1;

  if (!defined $x_dcc || $x_dcc eq '') {
    return ($dcc_result, $dcc_rep);
  }

  my $conf = $pms->{conf};

  if ($x_dcc =~ /^X-DCC-([^:]*?)-Metrics: (.*)$/) {
    $pms->set_tag('DCCB', $1);
    $pms->set_tag('DCCR', $2);
  }
  $x_dcc =~ s/many/999999/ig;
  $x_dcc =~ s/ok\d?/0/ig;

  my %count = (body => 0, fuz1 => 0, fuz2 => 0, rep => 0);
  if ($x_dcc =~ /\bBody=(\d+)/) {
    $count{body} = $1+0;
  }
  if ($x_dcc =~ /\bFuz1=(\d+)/) {
    $count{fuz1} = $1+0;
  }
  if ($x_dcc =~ /\bFuz2=(\d+)/) {
    $count{fuz2} = $1+0;
  }
  if ($pms->{conf}->{use_dcc_rep} && $x_dcc =~ /\brep=(\d+)/) {
    $count{rep}  = $1+0;
    $dcc_rep = $count{rep};
    $pms->set_tag('DCCREP', $dcc_rep);
  }
  if ($count{body} >= $conf->{dcc_body_max} ||
      $count{fuz1} >= $conf->{dcc_fuz1_max} ||
      $count{fuz2} >= $conf->{dcc_fuz2_max} ||
      $count{rep}  >= $conf->{dcc_rep_percent})
  {
    dbg(sprintf("dcc: listed: BODY=%s/%s FUZ1=%s/%s FUZ2=%s/%s REP=%s/%s",
		map { defined $_ ? $_ : 'undef' } (
		  $count{body}, $conf->{dcc_body_max},
		  $count{fuz1}, $conf->{dcc_fuz1_max},
		  $count{fuz2}, $conf->{dcc_fuz2_max},
		  $count{rep},  $conf->{dcc_rep_percent})
		));
    $dcc_result = 1;
  }

  return ($dcc_result, $dcc_rep);
}

# get the X-DCC header line and save the checksums from dccifd or dccproc
sub parse_dcc_response {
  my ($self, $resp, $pgm) = @_;
  my ($raw_x_dcc, $cksums);

  # The first line is the header we want.  It uses SMTP folded whitespace
  # if it is long.  The folded whitespace is always a single \t.
  chomp($raw_x_dcc = shift @$resp);
  my $v;
  while (($v = shift @$resp) && $v =~ s/^\t(.+)\s*\n/ $1/) {
    $raw_x_dcc .= $v;
  }

  # skip the "reported:" line between the X-DCC header and any checksums
  # remove ':' to avoid a bug in versions 1.3.115 - 1.3.122 in dccsight
  # with the length of "Message-ID:"
  $cksums = '';
  while (($v = shift @$resp) && $v =~ s/^([^:]*):/$1/) {
    $cksums .= $v;
  }

  if (!defined $raw_x_dcc || $raw_x_dcc !~ /^X-DCC/) {
    info("dcc: instead of X-DCC header, $pgm returned '%s'", $raw_x_dcc||'');
  }

  return ($raw_x_dcc, $cksums);
}

sub ask_dcc {
  my ($self, $tag, $pms, $fulltext, $envelope) = @_;

  my $conf = $pms->{conf};
  my $timeout = $conf->{dcc_timeout};

  if ($self->is_dccifd_available()) {
    my @resp;
    my $timer = Mail::SpamAssassin::Timeout->new(
      { secs => $timeout, deadline => $pms->{master_deadline} });
    my $err = $timer->run_and_catch(sub {
      local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

      $pms->{dcc_sock} = $self->dccifd_connect($tag);
      if (!$pms->{dcc_sock}) {
	$self->{dccifd_available} = 0;
	# fall back on dccproc if the socket is an orphan from
	# a killed dccifd daemon or some other obvious (no timeout) problem
	dbg("$tag dccifd failed: trying dccproc as fallback");
	return;
      }

      # send the options and other parameters to the daemon
      my $client = $envelope->{ip};
      my $clientname = $envelope->{rdns};
      if (!defined $client) {
	$client = '';
      } else {
	$client .= ("\r" . $clientname) if defined $clientname;
      }
      my $helo = $envelope->{helo} || '';
      my $opts;
      if ($tag eq 'dcc:') {
	$opts = $self->{dccifd_lookup_options};
	if (defined $pms->{dcc_x_result}) {
	  # only query if there is an X-DCC header
	  $opts =~ s/grey-off/grey-off query/;
	}
      } else {
	$opts = $self->{dccifd_report_options};
      }

      $pms->{dcc_sock}->print($opts)  or die "failed write options\n";
      $pms->{dcc_sock}->print("$client\n")  or die "failed write SMTP client\n";
      $pms->{dcc_sock}->print("$helo\n")  or die "failed write HELO value\n";
      $pms->{dcc_sock}->print("\n")  or die "failed write sender\n";
      $pms->{dcc_sock}->print("unknown\n\n")  or die "failed write 1 recipient\n";
      $pms->{dcc_sock}->print($$fulltext)  or die "failed write mail message\n";
      $pms->{dcc_sock}->shutdown(1)  or die "failed socket shutdown: $!";

      # don't async report and learn
      if ($tag ne 'dcc:') {
        @resp = $pms->{dcc_sock}->getlines();
        delete $pms->{dcc_sock};
        shift @resp; shift @resp; # ignore status/multistatus line
        if (!@resp) {
          die("no response");
        }
      } else {
        $pms->{dcc_async_start} = time;
      }
    });

    if ($timer->timed_out()) {
      delete $pms->{dcc_sock};
      dbg("$tag dccifd timed out after $timeout seconds");
      return (undef, undef);
    } elsif ($err) {
      delete $pms->{dcc_sock};
      chomp $err;
      info("$tag dccifd failed: $err");
      return (undef, undef);
    }

    # report, learn
    if ($tag ne 'dcc:') {
      my ($raw_x_dcc, $cksums) = $self->parse_dcc_response(\@resp, 'dccifd');
      if ($raw_x_dcc) {
        dbg("$tag dccifd responded with '$raw_x_dcc'");
        return ($raw_x_dcc, $cksums);
      } else {
        return (undef, undef);
      }
    }

    # async lookup
    return ('async', undef) if $pms->{dcc_async_start};

    # or falling back to dccproc..
  }

  if ($self->is_dccproc_available()) {
    $pms->enter_helper_run_mode();

    my $pid;
    my @resp;
    my $timer = Mail::SpamAssassin::Timeout->new(
      { secs => $timeout, deadline => $pms->{master_deadline} });
    my $err = $timer->run_and_catch(sub {
      local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

      # use a temp file -- open2() is unreliable, buffering-wise, under spamd
      my $tmpf = $pms->create_fulltext_tmpfile();

      my @opts = split(/\s+/, $conf->{dcc_options} || '');
      untaint_var(\@opts);
      unshift(@opts, '-w', 'whiteclnt');
      my $client = $envelope->{ip};
      if ($client) {
        unshift(@opts, '-a', untaint_var($client));
      } else {
        # get external relay IP address from Received: header if not available
        unshift(@opts, '-R');
      }
      if ($tag eq 'dcc:') {
        # query instead of report if there is an X-DCC header from upstream
        unshift(@opts, '-Q') if defined $pms->{dcc_x_result};
      } else {
        # learn or report spam
        unshift(@opts, '-t', 'many');
      }
      if ($conf->{dcc_home}) {
        # set home directory explicitly
        unshift(@opts, '-h', $conf->{dcc_home});
      }

      dbg("$tag opening pipe to " .
        join(' ', $conf->{dcc_path}, "-C", "-x", "0", @opts, "<$tmpf"));

      $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
        $tmpf, 1, $conf->{dcc_path}, "-C", "-x", "0", @opts);
      $pid or die "DCC: $!\n";

      # read+split avoids a Perl I/O bug (Bug 5985)
      my($inbuf, $nread);
      my $resp = '';
      while ($nread = read(DCC, $inbuf, 8192)) { $resp .= $inbuf }
      defined $nread  or die "error reading from pipe: $!";
      @resp = split(/^/m, $resp, -1);

      my $errno = 0;
      close DCC or $errno = $!;
      proc_status_ok($?,$errno)
        or info("$tag [%s] finished: %s", $pid, exit_status_str($?,$errno));

      die "failed to read X-DCC header from dccproc\n" if !@resp;

    });

    if (defined(fileno(*DCC))) { # still open
      if ($pid) {
        if (kill('TERM', $pid)) {
	  dbg("$tag killed stale dccproc process [$pid]")
	} else {
	  dbg("$tag killing dccproc process [$pid] failed: $!")
	}
      }
      my $errno = 0;
      close(DCC) or $errno = $!;
      proc_status_ok($?,$errno) or info("$tag [%s] dccproc terminated: %s",
					$pid, exit_status_str($?,$errno));
    }

    $pms->leave_helper_run_mode();

    if ($timer->timed_out()) {
      dbg("$tag dccproc timed out after $timeout seconds");
      return (undef, undef);
    } elsif ($err) {
      chomp $err;
      info("$tag dccproc failed: $err");
      return (undef, undef);
    }

    my ($raw_x_dcc, $cksums) = $self->parse_dcc_response(\@resp, 'dccproc');
    if ($raw_x_dcc) {
      dbg("$tag dccproc responded with '$raw_x_dcc'");
      return ($raw_x_dcc, $cksums);
    } else {
      info("$tag instead of X-DCC header, dccproc returned '$raw_x_dcc'");
      return (undef, undef);
    }
  }

  return (undef, undef);
}

# tell DCC server that the message is spam according to SpamAssassin
sub check_post_learn {
  my ($self, $opts) = @_;

  return if $self->{dcc_disabled};
  return if !$self->{main}->{conf}->{use_dcc};

  my $pms = $opts->{permsgstatus};
  return if $pms->{dcc_abort};

  # learn only if allowed
  my $conf = $self->{main}->{conf};
  my $learn_score = $conf->{dcc_learn_score};
  if (!defined $learn_score || $learn_score eq '') {
    dbg("dcc: DCC learning not enabled by dcc_learn_score");
    $self->{learn_disabled} = 1;
    return;
  }

  # and if SpamAssassin concluded that the message is spam
  # worse than our threshold
  if ($pms->is_spam()) {
    my $score = $pms->get_score();
    my $required_score = $pms->get_required_score();
    if ($score < $required_score + $learn_score) {
      dbg("dcc: score=%d required_score=%d dcc_learn_score=%d",
	  $score, $required_score, $learn_score);
      return;
    }
  }

  # and if we checked the message
  return if (!defined $pms->{dcc_x_result});

  # and if the DCC server thinks it was not spam
  if ($pms->{dcc_x_result} !~ /\b(Body|Fuz1|Fuz2)=\d/) {
    dbg("dcc: already known as spam; no need to learn: $pms->{dcc_x_result}");
    return;
  }

  my $timer = $self->{main}->time_method("dcc_learn");

  # dccsight is faster than dccifd or dccproc if we have checksums,
  #   which we do not have with dccifd before 1.3.123
  my $old_cksums = $pms->{dcc_cksums};
  return if ($old_cksums && $self->dccsight_learn($pms, $old_cksums));

  # Fall back on dccifd or dccproc without saved checksums or dccsight.
  # get_dcc_interface() was called when the message was checked
  my $fulltext = $pms->{msg}->get_pristine();
  my $envelope = $pms->{relays_external}->[0];
  my ($raw_x_dcc, undef) = $self->ask_dcc('dcc: learn:', $pms,
					    \$fulltext, $envelope);
  dbg("dcc: learned as spam") if defined $raw_x_dcc;
}

sub dccsight_learn {
  my ($self, $pms, $old_cksums) = @_;

  return 0 if !$old_cksums;

  my $dccsight = $self->dcc_pgm_path('dccsight');
  if (!$dccsight) {
    info("dcc: cannot find dccsight") if $dccsight eq '';
    return 0;
  }

  $pms->enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
  my $tmpf = $pms->create_fulltext_tmpfile(\$old_cksums);

  my ($raw_x_dcc, $new_cksums);
  my $pid;

  my $timeout = $self->{main}->{conf}->{dcc_timeout};
  my $timer = Mail::SpamAssassin::Timeout->new(
	   { secs => $timeout, deadline => $pms->{master_deadline} });
  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    dbg("dcc: opening pipe to %s",
	join(' ', $dccsight, "-t", "many", "<$tmpf"));

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
	    $tmpf, 1, $dccsight, "-t", "many");
    $pid or die "$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf, $nread);
    my $resp = '';
    while ($nread = read(DCC, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";
    my @resp = split(/^/m, $resp, -1);

    my $errno = 0;
    close DCC or $errno = $!;
    proc_status_ok($?,$errno)
	  or info("dcc: [%s] finished: %s", $pid, exit_status_str($?,$errno));

    die "dcc: failed to read learning response\n" if !@resp;

    ($raw_x_dcc, $new_cksums) = $self->parse_dcc_response(\@resp, 'dccsight');
  });

  if (defined(fileno(*DCC))) {	  # still open
    if ($pid) {
      if (kill('TERM', $pid)) {
	dbg("dcc: killed stale dccsight process [$pid]");
      } else {
	dbg("dcc: killing stale dccsight process [$pid] failed: $!");
      }
    }
    my $errno = 0;
    close(DCC) or $errno = $!;
    proc_status_ok($?,$errno) or info("dcc: dccsight [%s] terminated: %s",
				      $pid, exit_status_str($?,$errno));
  }

  $pms->delete_fulltext_tmpfile($tmpf);

  $pms->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: dccsight timed out after $timeout seconds");
    return 0;
  } elsif ($err) {
    chomp $err;
    info("dcc: dccsight failed: $err\n");
    return 0;
  }

  if ($raw_x_dcc ne '') { #TODO check if working
    dbg("dcc: learned response: $raw_x_dcc");
    return 1;
  }

  return 0;
}

sub plugin_report {
  my ($self, $opts) = @_;

  return if $self->{dcc_disabled};
  return if !$self->{main}->{conf}->{use_dcc};
  return if $opts->{report}->{options}->{dont_report_to_dcc};

  return if !$self->get_dcc_interface();

  my $report = $opts->{report};

  my $timer = $self->{main}->time_method("dcc_report");

  # get the metadata from the message so we can report the external relay
  $opts->{msg}->extract_message_metadata($report->{main});
  my $envelope = $opts->{msg}->{metadata}->{relays_external}->[0];
  my ($raw_x_dcc, undef) = $self->ask_dcc('reporter:', $report,
					    $opts->{text}, $envelope);
  if (defined $raw_x_dcc) {
    $report->{report_available} = $report->{report_return} = 1;
    info("reporter: spam reported to DCC");
  } else {
    info("reporter: could not report spam to DCC");
  }
}

1;
