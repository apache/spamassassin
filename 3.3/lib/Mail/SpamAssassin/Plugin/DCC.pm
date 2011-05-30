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

Mail::SpamAssassin::Plugin::DCC - perform DCC check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::DCC

  full DCC_CHECK        eval:check_dcc()
  full DCC_CHECK_50_79  eval:check_dcc_reputation_range('50','79')

=head1 DESCRIPTION

The DCC or Distributed Checksum Clearinghouse is a system of servers
collecting and counting checksums of millions of mail messages.
TheSpamAssassin.pm counts can be used by SpamAssassin to detect and
reject or filter spam.

Because simplistic checksums of spam can be easily defeated, the main
DCC checksums are fuzzy and ignore aspects of messages.  The fuzzy
checksums are changed as spam evolves.

Note that DCC is disabled by default in C<init.pre> because it is not
open source.  See the DCC license for more details.

See http://www.rhyolite.com/anti-spam/dcc/ for more information about
DCC.

=head1 TAGS

The following tags are added to the set, available for use in reports,
header fields, other plugins, etc.:

  _DCCB_    DCC server ID in a response
  _DCCR_    response from DCC - header field body in X-DCC-*-Metrics
  _DCCREP_  response from DCC - DCC reputation in percents (0..100)

Tag _DCCREP_ provides a nonempty value only with commercial DCC systems.
This is the percentage of spam vs. ham sent from the first untrusted relay.

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

use vars qw($have_inet6);

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

This option sets how often a message's body/fuz1/fuz2 checksum must have been
reported to the DCC server before SpamAssassin will consider the DCC check as
matched.

As nearly all DCC clients are auto-reporting these checksums, you should set
this to a relatively high value, e.g. C<999999> (this is DCC's MANY count).

The default is C<999999> for all these options.

=item dcc_rep_percent NUMBER

Only commercial DCC systems provide DCC reputation information. This is the
percentage of spam vs. ham sent from the first untrusted relay.  It will hit
on new spam from spam sources.  Default is C<90>.

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
without the DCC results.

=cut

  push (@cmds, {
    setting => 'dcc_timeout',
    is_admin => 1,
    default => 8,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item dcc_home STRING

This option tells SpamAssassin where to find the dcc homedir.
If not given, it will try to get dcc to specify one, and if that fails it
will try dcc's own default homedir of '/var/dcc'.
If C<dcc_path> is not specified, it will default to looking in
C<dcc_home/bin> for dcc client instead of relying on SpamAssassin to find it
in the current PATH.  If it isn't found there, it will look in the current
PATH. If a C<dccifd> socket is found in C<dcc_home> or specified explicitly,
it will use that interface instead of C<dccproc>.

=cut

  push (@cmds, {
    setting => 'dcc_home',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
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

This option tells SpamAssassin where to find the dccifd socket. If
C<dcc_dccifd_path> is not specified, it will default to looking for a socket
named C<dccifd> in a directory C<dcc_home>.  The C<dcc_dccifd_path> can be
a Unix socket name (absolute path), or an INET socket specification in a form
C<[host]:port> or C<host:port>, where a host can be an IPv4 or IPv6 address
or a host name, and port is a TCP port number. In case of an IPv6 address the
brackets are required syntax. If a C<dccifd> socket is found, the plugin will
use it instead of C<dccproc>.

=cut

  push (@cmds, {
    setting => 'dcc_dccifd_path',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $value = ''  if !defined $value;
      $self->{dcc_dccifd_path_raw} = $value;  # for logging purposes
      undef $self->{dcc_dccifd_host};
      undef $self->{dcc_dccifd_port};
      undef $self->{dcc_dccifd_socket};
      local($1,$2,$3);
      if ($value eq '') {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($value =~ m{^ (?: \[ ([^\]]*) \] | ([^:]*) ) : ([^:]*) \z}sx) {
        # "[host]:port" or "host:port", where a host can be an IPv4 or IPv6
        # address or a host name, and port is a TCP port number or service name
        my $host = defined $1 ? $1 : $2;
        my $port = $3;
        $self->{dcc_dccifd_host} = untaint_var($host);
        $self->{dcc_dccifd_port} = untaint_var($port);
        dbg("config: dcc_dccifd_path set to [%s]:%s", $host,$port);
      } else {  # assume a unix socket
        if ($value !~ m{^/}) {
          info("config: dcc_dccifd_path should be an absolute socket path");
        # return $Mail::SpamAssassin::Conf::INVALID_VALUE;  # abort or accept?
        }
        $value = untaint_file_path($value);
      # test disabled, dccifd may not yet be running at spamd startup time
      # if (!-S $value) {
      #   info("config: dcc_dccifd_path '$value' isn't a local socket");
      #   return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      # }
        $self->{dcc_dccifd_socket} = $value;
        dbg("config: dcc_dccifd_path set to local socket %s", $value);
      }
    }
  });

=item dcc_path STRING

This option tells SpamAssassin specifically where to find the C<dccproc>
client instead of relying on SpamAssassin to find it in the current PATH.
Note that if I<taint mode> is enabled in the Perl interpreter, you should
use this, as the current PATH will have been cleared.

=cut

  push (@cmds, {
    setting => 'dcc_path',
    is_admin => 1,
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = untaint_file_path($value);
      if (!-x $value) {
	info("config: dcc_path '$value' isn't an executable");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{dcc_path} = $value;
    }
  });

=item dcc_options options

Specify additional options to the dccproc(8) command. Please note that only
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
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{dcc_options} = $1;
    }
  });

=item dccifd_options options

Specify additional options to send to the dccifd(8) daemon. Please note that only
characters in the range [0-9A-Za-z ,._/-] are allowed for security reasons.

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
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{dccifd_options} = $1;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub find_dcc_home {
  my ($self) = @_;

  my $conf = $self->{main}->{conf};
  return if !$conf->{use_dcc};

  my $dcchome = $conf->{dcc_home} || '';

  # If we're not given the DCC homedir, try getting DCC to tell us it.
  # If that fails, try the DCC default homedir of '/var/dcc'.
  if ($dcchome eq '') {

    my $cdcc = Mail::SpamAssassin::Util::find_executable_in_env_path('cdcc');

    my $cdcc_home = '';
    if ($cdcc && -x $cdcc && open(CDCC, "$cdcc homedir 2>&1|")) {
      dbg("dcc: dcc_home not set, querying cdcc utility");
      $cdcc_home = <CDCC> || '';
      close CDCC;

      chomp $cdcc_home;
      $cdcc_home =~ s/\s+homedir=//;
      dbg("dcc: cdcc reports homedir as '%s'", $cdcc_home);
    }

    # try first with whatever the cdcc utility reported
    my $cdcc_home_errno = 0;
    if ($cdcc_home eq '') {
      $cdcc_home_errno = ENOENT;
    } elsif (!stat($cdcc_home)) {
      $cdcc_home_errno = 0+$!;
    }
    if ($cdcc_home_errno == ENOENT) {
      # no such file
    } elsif ($cdcc_home_errno != 0) {
      dbg("dcc: cdcc reported homedir $cdcc_home is not accessible: $!");
    } elsif (!-d _) {
      dbg("dcc: cdcc reported homedir $cdcc_home is not a directory");
    } else {  # ok
      dbg("dcc: cdcc reported homedir $cdcc_home exists, using it");
      $dcchome = untaint_var($cdcc_home);
    }

    # try falling back to /var/dcc
    if ($dcchome eq '') {
      my $var_dcc_errno = stat('/var/dcc') ? 0 : 0+$!;
      if ($var_dcc_errno == ENOENT) {
        # no such file
      } elsif ($var_dcc_errno != 0) {
        dbg("dcc: dcc_home not set and dcc default homedir /var/dcc ".
            "is not accessible: $!");
      } elsif (!-d _) {
        dbg("dcc: dcc_home not set and dcc default homedir /var/dcc ".
            "is not a directory");
      } else {  # ok
        dbg("dcc: dcc_home not set but dcc default homedir /var/dcc exists, ".
            "using it");
        $dcchome = '/var/dcc';
      }
    }

    if ($dcchome eq '') {
      dbg("dcc: unable to get homedir from cdcc ".
          "and the dcc default homedir was not found");
    }

    # Remember found homedir path
    dbg("dcc: using '%s' as DCC homedir", $dcchome);
    $conf->{dcc_home} = $dcchome;
  }
}

sub is_dccifd_available {
  my ($self) = @_;

  my $conf = $self->{main}->{conf};
  $self->{dccifd_available} = 0;

  if (!$conf->{use_dcc}) {
    dbg("dcc: dccifd is not available: use_dcc is false");
  } elsif (defined $conf->{dcc_dccifd_host}) {
    dbg("dcc: dccifd inet socket chosen: [%s]:%s",
        $conf->{dcc_dccifd_host}, $conf->{dcc_dccifd_port});
    $self->{dccifd_available} = 1;
  } else {
    my $sockpath = $conf->{dcc_dccifd_socket};
    my $dcchome = $conf->{dcc_home};
    if (defined $sockpath) {
      dbg("dcc: dccifd local socket chosen: %s", $sockpath);
    } elsif (defined $conf->{dcc_dccifd_path_raw}) {
      # avoid falling back to defaults if explicitly provided but wrong
    } elsif (defined $dcchome && $dcchome ne '' && -S "$dcchome/dccifd") {
      $sockpath = "$dcchome/dccifd";
      $conf->{dcc_dccifd_socket} = $sockpath;
      dbg("dcc: dccifd default local socket chosen: %s", $sockpath);
    }
    if (defined $sockpath && -S $sockpath && -w _ && -r _) {
      $self->{dccifd_available} = 1;
    } elsif (!defined $conf->{dcc_dccifd_path_raw}) {
      dbg("dcc: dccifd is not available: no r/w dccifd socket found");
    } else {
      dbg("dcc: dccifd is not available: no r/w dccifd socket found: %s",
          $conf->{dcc_dccifd_path_raw});
    }
  }

  return $self->{dccifd_available};
}

sub is_dccproc_available {
  my ($self) = @_;
  my $conf = $self->{main}->{conf};

  $self->{dccproc_available} = 0;

  if (!$conf->{use_dcc}) {
    dbg("dcc: dccproc is not available: use_dcc is false");
    return 0;
  }
  my $dcchome = $conf->{dcc_home} || '';
  my $dccproc = $conf->{dcc_path} || '';

  if ($dccproc eq '' && ($dcchome ne '' && -x "$dcchome/bin/dccproc")) {
    $dccproc = "$dcchome/bin/dccproc";
  }
  if ($dccproc eq '') {
    $dccproc = Mail::SpamAssassin::Util::find_executable_in_env_path('dccproc');
  }

  unless (defined $dccproc && $dccproc ne '' && -x $dccproc) {
    dbg("dcc: dccproc is not available: no dccproc executable found");
    return 0;
  }

  # remember any found dccproc
  $conf->{dcc_path} = $dccproc;

  dbg("dcc: dccproc is available: %s", $conf->{dcc_path});
  $self->{dccproc_available} = 1;
  return 1;
}

sub dccifd_connect {
  my($self) = @_;
  my $conf = $self->{main}->{conf};
  my $sockpath = $conf->{dcc_dccifd_socket};
  my $host = $conf->{dcc_dccifd_host};
  my $port = $conf->{dcc_dccifd_port};
  my $sock;
  if (defined $sockpath) {
    dbg("dcc: connecting to a local socket %s", $sockpath);
    $sock = IO::Socket::UNIX->new(
              Type => SOCK_STREAM, Peer => $sockpath);
    $sock or die "dcc: failed to connect to a socket $sockpath: $!\n";
  } elsif (defined $host) {
    my $specified_path = $conf->{dcc_dccifd_path_raw};
    if ($host eq '') {
      die "dcc: empty host specification: $specified_path\n";
    }
    if (!defined $port || $port !~ /^\d+\z/ || $port < 1 || $port > 65535) {
      die "dcc: bad TCP port number: $specified_path\n";
    }
    my $is_inet4 = $host =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/;
    if ($is_inet4) {  # inet4 socket (IPv4 address)
      dbg("dcc: connecting to inet4 socket [%s]:%s", $host,$port);
      $sock = IO::Socket::INET->new(
                Proto => 'tcp', PeerAddr => $host, PeerPort => $port);
    } else {
      if (!defined $have_inet6) {
        $have_inet6 = eval { require IO::Socket::INET6 };
        $have_inet6 = 0  if !defined $have_inet6;
      }
      if (!$have_inet6) {  # fallback to an inet4 socket (IPv4)
        dbg("dcc: connecting(2) to inet4 socket [%s]:%s", $host,$port);
        $sock = IO::Socket::INET->new(
                  Proto => 'tcp', PeerAddr => $host, PeerPort => $port);
      } else {  # inet6 socket (IPv6) or a host name
        dbg("dcc: connecting to inet6 socket [%s]:%s", $host,$port);
        $sock = IO::Socket::INET6->new(
                  Proto => 'tcp', PeerAddr => $host, PeerPort => $port);
      }
    }
    $sock or die "dcc: failed to connect to [$host]:$port : $!\n";
  } else {
    die "dcc: dccifd socket not provided: $conf->{dcc_dccifd_path_raw}\n";
  }
  return $sock;
}

sub get_dcc_interface {
  my ($self) = @_;

  if ($self->is_dccifd_available()) {
    $self->{dcc_interface} = "dccifd";
    $self->{dcc_disabled} = 0;
  }
  elsif ($self->is_dccproc_available()) {
    $self->{dcc_interface} = "dccproc";
    $self->{dcc_disabled} = 0;
  }
  else {
    dbg("dcc: dccifd and dccproc are not available, disabling DCC");
    $self->{dcc_interface} = "none";
    $self->{dcc_disabled} = 1;
  }
}

sub dcc_query {
  my ($self, $permsgstatus, $full) = @_;

  $permsgstatus->{dcc_checked} = 1;

  # initialize valid tags
  $permsgstatus->{tag_data}->{DCCB} = "";
  $permsgstatus->{tag_data}->{DCCR} = "";
  $permsgstatus->{tag_data}->{DCCREP} = "";

  # short-circuit if there's already a X-DCC header with value of
  # "bulk" from an upstream DCC check
  if ($permsgstatus->get('ALL') =~
      /^(X-DCC-([^:]{1,80})?-?Metrics:.*bulk.*)$/m) {
    $permsgstatus->{dcc_response} = $1;
    return;
  }

  my $timer = $self->{main}->time_method("check_dcc");

  $self->find_dcc_home();

  $self->get_dcc_interface();
  my $result;
  if ($self->{dcc_disabled}) {
    $result = 0;
  } elsif ($$full eq '') {
    dbg("dcc: empty message, skipping dcc check");
    $result = 0;
  } elsif ($self->{dccifd_available}) {
    my $client = $permsgstatus->{relays_external}->[0]->{ip};
    my $clientname = $permsgstatus->{relays_external}->[0]->{rdns};
    my $helo = $permsgstatus->{relays_external}->[0]->{helo} || "";
    if ($client) {
      $client = $client . "\r" . $clientname  if $clientname;
    } else {
      $client = "0.0.0.0";
    }
    $self->dccifd_lookup($permsgstatus, $full, $client, $clientname, $helo);
  } else {
    my $client = $permsgstatus->{relays_external}->[0]->{ip};
    $self->dccproc_lookup($permsgstatus, $full, $client);
  }
}

sub check_dcc {
  my ($self, $permsgstatus, $full) = @_;
  my $conf = $self->{main}->{conf};

  $self->dcc_query($permsgstatus, $full)  if !$permsgstatus->{dcc_checked};

  my $response = $permsgstatus->{dcc_response};
  return 0  if !defined $response || $response eq '';

  local($1,$2);
  if ($response =~ /^X-DCC-(.*)-Metrics: (.*)$/) {
    $permsgstatus->{tag_data}->{DCCB} = $1;
    $permsgstatus->{tag_data}->{DCCR} = $2;
  }
  $response =~ s/many/999999/ig;
  $response =~ s/ok\d?/0/ig;

  my %count = (body => 0, fuz1 => 0, fuz2 => 0, rep => 0);
  if ($response =~ /\bBody=(\d+)/) {
    $count{body} = $1+0;
  }
  if ($response =~ /\bFuz1=(\d+)/) {
    $count{fuz1} = $1+0;
  }
  if ($response =~ /\bFuz2=(\d+)/) {
    $count{fuz2} = $1+0;
  }
  if ($response =~ /\brep=(\d+)/) {
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
  my ($self, $permsgstatus, $full, $min, $max) = @_;
  $self->dcc_query($permsgstatus, $full)  if !$permsgstatus->{dcc_checked};

  my $response = $permsgstatus->{dcc_response};
  return 0  if !defined $response || $response eq '';

  $min = 0   if !defined $min;
  $max = 999 if !defined $max;

  local $1;
  my $dcc_rep;
  $dcc_rep = $1+0  if defined $response && $response =~ /\brep=(\d+)/;
  if (defined $dcc_rep) {
    $dcc_rep = int($dcc_rep);  # just in case, rule ranges are integer percents
    my $result = $dcc_rep >= $min && $dcc_rep <= $max ? 1 : 0;
    dbg("dcc: dcc_rep %s, min %s, max %s => result=%s",
        $dcc_rep, $min, $max, $result?'YES':'no');
    $permsgstatus->{tag_data}->{DCCREP} = $dcc_rep;
    return $dcc_rep >= $min && $dcc_rep <= $max ? 1 : 0;
  }
  return 0;
}

sub dccifd_lookup {
  my ($self, $permsgstatus, $fulltext, $client, $clientname, $helo) = @_;
  my $conf = $self->{main}->{conf};
  my $response;
  my $left;
  my $right;
  my $timeout = $conf->{dcc_timeout};
  my $opts = $conf->{dccifd_options};
  my @opts = !defined $opts ? () : split(' ',$opts);

  $permsgstatus->enter_helper_run_mode();

  my $timer = Mail::SpamAssassin::Timeout->new(
           { secs => $timeout, deadline => $permsgstatus->{master_deadline} });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    my $sock = $self->dccifd_connect();
    $sock or die "dcc: failed to connect to a dccifd socket";

    # send the options and other parameters to the daemon
    $sock->print("header " . join(" ",@opts) . "\n")
                                 or die "dcc: failed write";  # options
    $sock->print($client . "\n") or die "dcc: failed write";  # client
    $sock->print($helo . "\n")   or die "dcc: failed write";  # HELO value
    $sock->print("\n")           or die "dcc: failed write";  # sender
    $sock->print("unknown\r\n")  or die "dcc: failed write";  # recipients
    $sock->print("\n")           or die "dcc: failed write";  # recipients

    $sock->print($$fulltext)     or die "dcc: failed write";

    $sock->shutdown(1) or die "dcc: failed socket shutdown: $!";

    $sock->getline()   or die "dcc: failed read status";
    $sock->getline()   or die "dcc: failed read multistatus";

    my @null = $sock->getlines();
    if (!@null) {
      # no facility prefix on this
      die "dcc: failed to read header\n";
    }

    # the first line will be the header we want to look at
    chomp($response = shift @null);
    # but newer versions of DCC fold the header if it's too long...
    while (my $v = shift @null) {
      last unless ($v =~ s/^\s+/ /);  # if this line wasn't folded, stop
      chomp $v;
      $response .= $v;
    }

    dbg("dcc: dccifd got response: %s", $response);
  
  });

  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: dccifd check timed out after $timeout secs.");
    return;
  }

  if ($err) {
    chomp $err;
    warn("dcc: dccifd -> check skipped: $err\n");
    return;
  }

  if (!defined $response || $response !~ /^X-DCC/) {
    dbg("dcc: dccifd check failed - no X-DCC returned: %s", $response);
    return;
  }

  $response =~ s/[ \t]\z//;  # strip trailing whitespace
  $permsgstatus->{dcc_response} = $response;
}

sub dccproc_lookup {
  my ($self, $permsgstatus, $fulltext, $client) = @_;
  my $conf = $self->{main}->{conf};
  my $response;
  my %count = (body => 0, fuz1 => 0, fuz2 => 0, rep => 0);
  my $timeout = $conf->{dcc_timeout};

  $permsgstatus->enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
  my $tmpf = $permsgstatus->create_fulltext_tmpfile($fulltext);
  my $pid;

  my $timer = Mail::SpamAssassin::Timeout->new(
           { secs => $timeout, deadline => $permsgstatus->{master_deadline} });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    # note: not really tainted, this came from system configuration file
    my $path = untaint_file_path($conf->{dcc_path});

    my $opts = $conf->{dcc_options};
    my @opts = !defined $opts ? () : split(' ',$opts);
    untaint_var(\@opts);

    unshift(@opts, "-a",
            untaint_var($client))  if defined $client && $client ne '';

    dbg("dcc: opening pipe: %s",
         join(' ', $path, "-H", "-x", "0", @opts, "< $tmpf"));

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
             $tmpf, 1, $path, "-H", "-x", "0", @opts);
    $pid or die "$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf,$nread,$resp); $resp = '';
    while ( $nread=read(DCC,$inbuf,8192) ) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";
    my @null = split(/^/m, $resp, -1);  undef $resp;

    my $errno = 0;  close DCC or $errno = $!;
    proc_status_ok($?,$errno)
      or info("dcc: [%s] finished: %s", $pid, exit_status_str($?,$errno));

    if (!@null) {
      # no facility prefix on this
      die "failed to read header\n";
    }

    # the first line will be the header we want to look at
    chomp($response = shift @null);
    # but newer versions of DCC fold the header if it's too long...
    while (my $v = shift @null) {
      last unless ($v =~ s/^\s+/ /);  # if this line wasn't folded, stop
      chomp $v;
      $response .= $v;
    }

    unless (defined($response)) {
      # no facility prefix on this
      die "no response\n";	# yes, this is possible
    }

    dbg("dcc: got response: %s", $response);

  });

  if (defined(fileno(*DCC))) {  # still open
    if ($pid) {
      if (kill('TERM',$pid)) { dbg("dcc: killed stale helper [$pid]") }
      else { dbg("dcc: killing helper application [$pid] failed: $!") }
    }
    my $errno = 0;  close(DCC) or $errno = $!;
    proc_status_ok($?,$errno)
      or info("dcc: [%s] terminated: %s", $pid, exit_status_str($?,$errno));
  }
  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: check timed out after $timeout seconds");
    return;
  }

  if ($err) {
    chomp $err;
    if ($err eq "__brokenpipe__ignore__") {
      dbg("dcc: check failed: broken pipe");
    } elsif ($err eq "no response") {
      dbg("dcc: check failed: no response");
    } else {
      warn("dcc: check failed: $err\n");
    }
    return;
  }

  if (!defined($response) || $response !~ /^X-DCC/) {
    $response ||= '';
    dbg("dcc: check failed: no X-DCC returned (did you create a map file?): %s", $response);
    return;
  }

  $permsgstatus->{dcc_response} = $response;
}

# only supports dccproc right now
sub plugin_report {
  my ($self, $options) = @_;

  return if $options->{report}->{options}->{dont_report_to_dcc};
  $self->get_dcc_interface();
  return if $self->{dcc_disabled};

  # get the metadata from the message so we can pass the external relay information
  $options->{msg}->extract_message_metadata($options->{report}->{main});
  my $client = $options->{msg}->{metadata}->{relays_external}->[0]->{ip};
  if ($self->{dccifd_available}) {
    my $clientname = $options->{msg}->{metadata}->{relays_external}->[0]->{rdns};
    my $helo = $options->{msg}->{metadata}->{relays_external}->[0]->{helo} || "";
    if ($client) {
      if ($clientname) {
        $client = $client . "\r" . $clientname;
      }
    } else {
      $client = "0.0.0.0";
    }
    if ($self->dccifd_report($options, $options->{text}, $client, $helo)) {
      $options->{report}->{report_available} = 1;
      info("reporter: spam reported to DCC");
      $options->{report}->{report_return} = 1;
    }
    else {
      info("reporter: could not report spam to DCC via dccifd");
    }
  } else {
    # use temporary file: open2() is unreliable due to buffering under spamd
    my $tmpf = $options->{report}->create_fulltext_tmpfile($options->{text});
    
    if ($self->dcc_report($options, $tmpf, $client)) {
      $options->{report}->{report_available} = 1;
      info("reporter: spam reported to DCC");
      $options->{report}->{report_return} = 1;
    }
    else {
      info("reporter: could not report spam to DCC via dccproc");
    }
    $options->{report}->delete_fulltext_tmpfile();
  }
}

sub dccifd_report {
  my ($self, $options, $fulltext, $client, $helo) = @_;
  my $conf = $self->{main}->{conf};
  my $timeout = $conf->{dcc_timeout};
  # instead of header use whatever the report option is
  my $opts = $conf->{dccifd_options};
  my @opts = !defined $opts ? () : split(' ',$opts);

  $options->{report}->enter_helper_run_mode();
  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });

  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    my $sock = $self->dccifd_connect();
    $sock or die "report: failed to connect to a dccifd socket";

    # send the options and other parameters to the daemon
    $sock->print("spam " . join(" ",@opts) . "\n")
      or die "report: dccifd failed write"; # options
    $sock->print($client . "\n")
      or die "report: dccifd failed write"; # client
    $sock->print($helo . "\n")
      or die "report: dccifd failed write"; # HELO value
    $sock->print("\n")
      or die "report: dccifd failed write"; # sender
    $sock->print("unknown\r\n")
      or die "report: dccifd failed write"; # recipients
    $sock->print("\n")
      or die "report: dccifd failed write"; # recipients

    $sock->print($$fulltext) or die "report: dccifd failed write";

    $sock->shutdown(1) or die "report: dccifd failed socket shutdown: $!";

    $sock->getline() or die "report: dccifd failed read status";
    $sock->getline() or die "report: dccifd failed read multistatus";

    my @ignored = $sock->getlines();
  });

  $options->{report}->leave_helper_run_mode();
  
  if ($timer->timed_out()) {
    dbg("reporter: DCC report via dccifd timed out after $timeout secs.");
    return 0;
  }
  
  if ($err) {
    chomp $err;
    if ($err eq "__brokenpipe__ignore__") {
      dbg("reporter: DCC report via dccifd failed: broken pipe");
    } else {
      warn("reporter: DCC report via dccifd failed: $err\n");
    }
    return 0;
  }
  
  return 1;
}
  
sub dcc_report {
  my ($self, $options, $tmpf, $client) = @_;
  my $conf = $self->{main}->{conf};
  my $timeout = $options->{report}->{conf}->{dcc_timeout};

  # note: not really tainted, this came from system configuration file
  my $path = untaint_file_path($options->{report}->{conf}->{dcc_path});
  my $opts = $conf->{dcc_options};
  my @opts = !defined $opts ? () : split(' ',$opts);
  untaint_var(\@opts);

  # get the metadata from the message so we can pass the external relay info

  unshift(@opts, "-a",
          untaint_var($client))  if defined $client && $client ne '';

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });

  $options->{report}->enter_helper_run_mode();
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    dbg("report: opening pipe: %s",
        join(' ', $path, "-H", "-t", "many", "-x", "0", @opts, "< $tmpf"));

    my $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
                $tmpf, 1, $path, "-H", "-t", "many", "-x", "0", @opts);
    $pid or die "$!\n";

    my($inbuf,$nread,$nread_all); $nread_all = 0;
    # response is ignored, just check its existence
    while ( $nread=read(DCC,$inbuf,8192) ) { $nread_all += $nread }
    defined $nread  or die "error reading from pipe: $!";

    dbg("dcc: empty response")  if $nread_all < 1;

    my $errno = 0;  close DCC or $errno = $!;
    # closing a pipe also waits for the process executing on the pipe to
    # complete, no need to explicitly call waitpid
    # my $child_stat = waitpid($pid,0) > 0 ? $? : undef;
    proc_status_ok($?,$errno)
      or die "dcc: reporter error: ".exit_status_str($?,$errno)."\n";
  });
  $options->{report}->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("reporter: DCC report via dccproc timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    if ($err eq "__brokenpipe__ignore__") {
      dbg("reporter: DCC report via dccproc failed: broken pipe");
    } else {
      warn("reporter: DCC report via dccproc failed: $err\n");
    }
    return 0;
  }

  return 1;
}

1;

=back

=cut
