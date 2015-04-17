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

See http://www.dcc-servers.net/dcc/ for more information about DCC.

Note that DCC is disabled by default in C<v310.pre> because its use requires
software that is not distributed with SpamAssassin and that has license
restrictions for certain commercial uses.
See the DCC license at http://www.dcc-servers.net/dcc/LICENSE for details.

Enable it by uncommenting the "loadplugin Mail::SpamAssassin::Plugin::DCC"
confdir/v310.pre or by adding this line to your local.pre.  It might also
be necessary to install a DCC package, port, rpm, or equivalent from your
operating system distributor or a tarball from the primary DCC source
at http://www.dcc-servers.net/dcc/#download
See also http://www.dcc-servers.net/dcc/INSTALL.html

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
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str);
use Errno qw(ENOENT EACCES);
use IO::Socket;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

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
    $self->{use_dcc} = 0;
    dbg("dcc: local tests only, disabling DCC");
  }
  else {
    dbg("dcc: network tests on, registering DCC");
  }

  $self->register_eval_rule("check_dcc");
  $self->register_eval_rule("check_dcc_reputation_range");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER OPTIONS

=over 4

=item use_dcc (0|1)		(default: 1)

Whether to use DCC, if it is available.

=cut

  push(@cmds, {
    setting => 'use_dcc',
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

Only the commercial DCC software provides DCC Reputations.  A DCC Reputation
is the percentage of bulk mail received from the last untrusted relay in the
path taken by a mail message as measured by all commercial DCC installations.
See http://www.rhyolite.com/dcc/reputations.html
You C<must> whitelist your trusted relays or MX servers with MX or
MXDCC lines in /var/dcc/whiteclnt as described in the main DCC man page
to avoid seeing your own MX servers as sources of bulk mail.
See http://www.dcc-servers.net/dcc/dcc-tree/dcc.html#White-and-Blacklists
The default is C<90>.

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

=head1 ADMINISTRATOR OPTIONS

=over 4

=item dcc_timeout n		(default: 8)

How many seconds you wait for DCC to complete, before scanning continues
without the DCC results. A numeric value is optionally suffixed by a
time unit (s, m, h, d, w, indicating seconds (default), minutes, hours,
days, weeks).

=cut

  push (@cmds, {
    setting => 'dcc_timeout',
    is_admin => 1,
    default => 8,
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


  # Get the DCC software version for talking to dccifd and formating the
  # dccifd options and the built-in DCC homedir.  Use -q to prevent delays.
  my $cdcc_home;
  my $cdcc = $self->dcc_pgm_path('cdcc');
  my $cmd = '-qV homedir libexecdir';
  if ($cdcc && open(CDCC, "$cdcc $cmd 2>&1 |")) {
    my $cdcc_output = do { local $/ = undef; <CDCC> };
    close CDCC;

    $cdcc_output =~ s/\n/ /g;		# everything in 1 line for debugging
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
           "See http://www.dcc-servers.net/dcc/old-versions.html");
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
  my $conf = $self->{main}->{conf};

  # dccifd remains available until it breaks
  return $self->{dccifd_available} if $self->{dccifd_available};

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
  return $self->{dccproc_available} if  defined $self->{dccproc_available};

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
  my $conf = $self->{main}->{conf};

  if (!$conf->{use_dcc}) {
    $self->{dcc_disabled} = 1;
    return;
  }

  $self->find_dcc_home();
  if (!$self->is_dccifd_available() && !$self->is_dccproc_available()) {
    dbg("dcc: dccifd and dccproc are not available");
    $self->{dcc_disabled} = 1;
  }

  $self->{dcc_disabled} = 0;
}

sub dcc_query {
  my ($self, $permsgstatus, $fulltext) = @_;

  $permsgstatus->{dcc_checked} = 1;

  if (!$self->{main}->{conf}->{use_dcc}) {
    dbg("dcc: DCC is not available: use_dcc is 0");
    return;
  }

  # initialize valid tags
  $permsgstatus->{tag_data}->{DCCB} = "";
  $permsgstatus->{tag_data}->{DCCR} = "";
  $permsgstatus->{tag_data}->{DCCREP} = "";

  if ($$fulltext eq '') {
    dbg("dcc: empty message; skipping dcc check");
    return;
  }

  if ($permsgstatus->get('ALL') =~ /^(X-DCC-.*-Metrics:.*)$/m) {
    $permsgstatus->{dcc_raw_x_dcc} = $1;
    # short-circuit if there is already a X-DCC header with value of
    # "bulk" from an upstream DCC check
    # require "bulk" because then at least one body checksum will be "many"
    # and so we know the X-DCC header is not forged by spammers
    return if $permsgstatus->{dcc_raw_x_dcc} =~ / bulk /;
  }

  my $timer = $self->{main}->time_method("check_dcc");

  $self->get_dcc_interface();
  return if $self->{dcc_disabled};

  my $envelope = $permsgstatus->{relays_external}->[0];
  ($permsgstatus->{dcc_raw_x_dcc},
   $permsgstatus->{dcc_cksums}) = $self->ask_dcc("dcc:", $permsgstatus,
						 $fulltext, $envelope);
}

sub check_dcc {
  my ($self, $permsgstatus, $full) = @_;
  my $conf = $self->{main}->{conf};

  $self->dcc_query($permsgstatus, $full)  if !$permsgstatus->{dcc_checked};

  my $x_dcc = $permsgstatus->{dcc_raw_x_dcc};
  return 0  if !defined $x_dcc || $x_dcc eq '';

  if ($x_dcc =~ /^X-DCC-(.*)-Metrics: (.*)$/) {
    $permsgstatus->set_tag('DCCB', $1);
    $permsgstatus->set_tag('DCCR', $2);
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
  if ($x_dcc =~ /\brep=(\d+)/) {
    $count{rep}  = $1+0;
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
    return 1;
  }
  return 0;
}

sub check_dcc_reputation_range {
  my ($self, $permsgstatus, $fulltext, $min, $max) = @_;

  # this is called several times per message, so parse the X-DCC header once
  my $dcc_rep = $permsgstatus->{dcc_rep};
  if (!defined $dcc_rep) {
    $self->dcc_query($permsgstatus, $fulltext)  if !$permsgstatus->{dcc_checked};
    my $x_dcc = $permsgstatus->{dcc_raw_x_dcc};
    if (defined $x_dcc && $x_dcc =~ /\brep=(\d+)/) {
      $dcc_rep = $1+0;
      $permsgstatus->set_tag('DCCREP', $dcc_rep);
    } else {
      $dcc_rep = -1;
    }
    $permsgstatus->{dcc_rep} = $dcc_rep;
  }

  # no X-DCC header or no reputation in the X-DCC header, perhaps for lack
  # of data in the DCC Reputation server
  return 0 if $dcc_rep < 0;

  # cover the entire range of reputations if not told otherwise
  $min = 0   if !defined $min;
  $max = 100 if !defined $max;

  my $result = $dcc_rep >= $min && $dcc_rep <= $max ? 1 : 0;
  dbg("dcc: dcc_rep %s, min %s, max %s => result=%s",
      $dcc_rep, $min, $max, $result?'YES':'no');
  return $result;
}

# get the X-DCC header line and save the checksums from dccifd or dccproc
sub parse_dcc_response {
  my ($self, $resp) = @_;
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

  return ($raw_x_dcc, $cksums);
}

sub ask_dcc {
  my ($self, $tag, $permsgstatus, $fulltext, $envelope) = @_;
  my $conf = $self->{main}->{conf};
  my ($pgm, $err, $sock, $pid, @resp);
  my ($client, $clientname, $helo, $opts);

  $permsgstatus->enter_helper_run_mode();

  my $timeout = $conf->{dcc_timeout};
  my $timer = Mail::SpamAssassin::Timeout->new(
	  { secs => $timeout, deadline => $permsgstatus->{master_deadline} });

  $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    # prefer dccifd to dccproc
    if ($self->{dccifd_available}) {
      $pgm = 'dccifd';

      $sock = $self->dccifd_connect($tag);
      if (!$sock) {
	$self->{dccifd_available} = 0;
	die("dccproc not available") if (!$self->is_dccproc_available());

	# fall back on dccproc if the socket is an orphan from
	# a killed dccifd daemon or some other obvious (no timeout) problem
	dbg("$tag fall back on dccproc");
      }
    }

    if ($self->{dccifd_available}) {

      # send the options and other parameters to the daemon
      $client = $envelope->{ip};
      $clientname = $envelope->{rdns};
      if (!defined $client) {
	$client = '';
      } else {
	$client .= ("\r" . $clientname) if defined $clientname;
      }
      $helo = $envelope->{helo} || '';
      if ($tag ne "dcc:") {
	$opts = $self->{dccifd_report_options}
      } else {
	$opts = $self->{dccifd_lookup_options};
	if (defined $permsgstatus->{dcc_raw_x_dcc}) {
	  # only query if there is an X-DCC header
	  $opts =~ s/grey-off/grey-off query/;
	}
      }

      $sock->print($opts)	   or die "failed write options\n";
      $sock->print($client . "\n") or die "failed write SMTP client\n";
      $sock->print($helo . "\n")   or die "failed write HELO value\n";
      $sock->print("\n")	   or die "failed write sender\n";
      $sock->print("unknown\n\n")  or die "failed write 1 recipient\n";
      $sock->print($$fulltext)     or die "failed write mail message\n";
      $sock->shutdown(1) or die "failed socket shutdown: $!";

      $sock->getline()   or die "failed read status\n";
      $sock->getline()   or die "failed read multistatus\n";

      @resp = $sock->getlines();
      die "failed to read dccifd response\n" if !@resp;

    } else {
      $pgm = 'dccproc';
      # use a temp file -- open2() is unreliable, buffering-wise, under spamd
      # first ensure that we do not hit a stray file from some other filter.
      $permsgstatus->delete_fulltext_tmpfile();
      my $tmpf = $permsgstatus->create_fulltext_tmpfile($fulltext);

      my $path = $conf->{dcc_path};
      $opts = $conf->{dcc_options};
      my @opts = !defined $opts ? () : split(' ',$opts);
      untaint_var(\@opts);
      unshift(@opts, '-w', 'whiteclnt');
      $client = $envelope->{ip};
      if ($client) {
	unshift(@opts, '-a', untaint_var($client));
      } else {
	# get external relay IP address from Received: header if not available
	unshift(@opts, '-R');
      }
      if ($tag eq "dcc:") {
	# query instead of report if there is an X-DCC header from upstream
	unshift(@opts, '-Q') if defined $permsgstatus->{dcc_raw_x_dcc};
      } else {
	# learn or report spam
	unshift(@opts, '-t', 'many');
      }

      defined $path  or die "no dcc_path found\n";
      dbg("$tag opening pipe to " .
	  join(' ', $path, "-C", "-x", "0", @opts, "<$tmpf"));

      $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
		$tmpf, 1, $path, "-C", "-x", "0", @opts);
      $pid or die "DCC: $!\n";

      # read+split avoids a Perl I/O bug (Bug 5985)
      my($inbuf,$nread,$resp); $resp = '';
      while ( $nread=read(DCC,$inbuf,8192) ) { $resp .= $inbuf }
      defined $nread  or die "error reading from pipe: $!";
      @resp = split(/^/m, $resp, -1);  undef $resp;

      my $errno = 0;  close DCC or $errno = $!;
      proc_status_ok($?,$errno)
	  or info("$tag [%s] finished: %s", $pid, exit_status_str($?,$errno));

      die "failed to read X-DCC header from dccproc\n" if !@resp;
    }
  });

  if (defined $pgm && $pgm eq 'dccproc') {
    if (defined(fileno(*DCC))) {	# still open
      if ($pid) {
	if (kill('TERM',$pid)) {
	  dbg("$tag killed stale dccproc process [$pid]")
	} else {
	  dbg("$tag killing dccproc process [$pid] failed: $!")
	}
      }
      my $errno = 0;  close(DCC) or $errno = $!;
      proc_status_ok($?,$errno) or info("$tag [%s] dccproc terminated: %s",
					$pid, exit_status_str($?,$errno));
    }
  }

  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("$tag %s timed out after %d seconds", $pgm||'', $timeout);
    return (undef, undef);
  }

  if ($err) {
    chomp $err;
    info("$tag %s failed: %s", $pgm||'', $err);
    return (undef, undef);
  }

  my ($raw_x_dcc, $cksums) = $self->parse_dcc_response(\@resp);
  if (!defined $raw_x_dcc || $raw_x_dcc !~ /^X-DCC/) {
    info("$tag instead of X-DCC header, $pgm returned '$raw_x_dcc'");
    return (undef, undef);
  }
  dbg("$tag $pgm responded with '$raw_x_dcc'");
  return ($raw_x_dcc, $cksums);
}

# tell DCC server that the message is spam according to SpamAssassin
sub check_post_learn {
  my ($self, $options) = @_;

  # learn only if allowed
  return if $self->{learn_disabled};
  my $conf = $self->{main}->{conf};
  if (!$conf->{use_dcc}) {
    $self->{learn_disabled} = 1;
    return;
  }
  my $learn_score = $conf->{dcc_learn_score};
  if (!defined $learn_score || $learn_score eq '') {
    dbg("dcc: DCC learning not enabled by dcc_learn_score");
    $self->{learn_disabled} = 1;
    return;
  }

  # and if SpamAssassin concluded that the message is spam
  # worse than our threshold
  my $permsgstatus = $options->{permsgstatus};
  if ($permsgstatus->is_spam()) {
    my $score = $permsgstatus->get_score();
    my $required_score = $permsgstatus->get_required_score();
    if ($score < $required_score + $learn_score) {
      dbg("dcc: score=%d required_score=%d dcc_learn_score=%d",
	  $score, $required_score, $learn_score);
      return;
    }
  }

  # and if we checked the message
  return if (!defined $permsgstatus->{dcc_raw_x_dcc});

  # and if the DCC server thinks it was not spam
  if ($permsgstatus->{dcc_raw_x_dcc} !~ /\b(Body|Fuz1|Fuz2)=\d/) {
    dbg("dcc: already known as spam; no need to learn");
    return;
  }

  # dccsight is faster than dccifd or dccproc if we have checksums,
  #   which we do not have with dccifd before 1.3.123
  my $old_cksums = $permsgstatus->{dcc_cksums};
  return if ($old_cksums && $self->dccsight_learn($permsgstatus, $old_cksums));

  # Fall back on dccifd or dccproc without saved checksums or dccsight.
  # get_dcc_interface() was called when the message was checked

  # is getting the full text this way kosher?  Is get_pristine() public?
  my $fulltext = $permsgstatus->{msg}->get_pristine();
  my $envelope = $permsgstatus->{relays_external}->[0];
  my ($raw_x_dcc, $cksums) = $self->ask_dcc("dcc: learn:", $permsgstatus,
					    \$fulltext, $envelope);
  dbg("dcc: learned as spam") if defined $raw_x_dcc;
}

sub dccsight_learn {
  my ($self, $permsgstatus, $old_cksums) = @_;
  my ($raw_x_dcc, $new_cksums);

  return 0 if !$old_cksums;

  my $dccsight = $self->dcc_pgm_path('dccsight');
  if (!$dccsight) {
    info("dcc: cannot find dccsight") if $dccsight eq '';
    return 0;
  }

  $permsgstatus->enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
  # ensure that we do not hit a stray file from some other filter.
  $permsgstatus->delete_fulltext_tmpfile();
  my $tmpf = $permsgstatus->create_fulltext_tmpfile(\$old_cksums);
  my $pid;

  my $timeout = $self->{main}->{conf}->{dcc_timeout};
  my $timer = Mail::SpamAssassin::Timeout->new(
	   { secs => $timeout, deadline => $permsgstatus->{master_deadline} });
  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    dbg("dcc: opening pipe to %s",
	join(' ', $dccsight, "-t", "many", "<$tmpf"));

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
	    $tmpf, 1, $dccsight, "-t", "many");
    $pid or die "$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf,$nread,$resp); $resp = '';
    while ( $nread=read(DCC,$inbuf,8192) ) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";
    my @resp = split(/^/m, $resp, -1);  undef $resp;

    my $errno = 0;  close DCC or $errno = $!;
    proc_status_ok($?,$errno)
	  or info("dcc: [%s] finished: %s", $pid, exit_status_str($?,$errno));

    die "dcc: failed to read learning response\n" if !@resp;

    ($raw_x_dcc, $new_cksums) = $self->parse_dcc_response(\@resp);
  });

  if (defined(fileno(*DCC))) {	  # still open
    if ($pid) {
      if (kill('TERM',$pid)) {
	dbg("dcc: killed stale dccsight process [$pid]")
      } else {
	dbg("dcc: killing stale dccsight process [$pid] failed: $!") }
    }
    my $errno = 0;  close(DCC) or $errno = $!;
    proc_status_ok($?,$errno) or info("dcc: dccsight [%s] terminated: %s",
				      $pid, exit_status_str($?,$errno));
  }
  $permsgstatus->delete_fulltext_tmpfile();
  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: dccsight timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    info("dcc: dccsight failed: $err\n");
    return 0;
  }

  if ($raw_x_dcc) {
    dbg("dcc: learned response: %s", $raw_x_dcc);
    return 1;
  }

  return 0;
}

sub plugin_report {
  my ($self, $options) = @_;

  return if $options->{report}->{options}->{dont_report_to_dcc};
  $self->get_dcc_interface();
  return if $self->{dcc_disabled};

  # get the metadata from the message so we can report the external relay
  $options->{msg}->extract_message_metadata($options->{report}->{main});
  my $envelope = $options->{msg}->{metadata}->{relays_external}->[0];
  my ($raw_x_dcc, $cksums) = $self->ask_dcc("reporter:", $options->{report},
					    $options->{text}, $envelope);

  if (defined $raw_x_dcc) {
    $options->{report}->{report_available} = 1;
    info("reporter: spam reported to DCC");
    $options->{report}->{report_return} = 1;
  } else {
    info("reporter: could not report spam to DCC");
  }
}

1;
