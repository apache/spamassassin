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

=head1 DESCRIPTION

The DCC or Distributed Checksum Clearinghouse is a system of servers
collecting and counting checksums of millions of mail messages. The
counts can be used by SpamAssassin to detect and reject or filter spam.

Because simplistic checksums of spam can be easily defeated, the main
DCC checksums are fuzzy and ignore aspects of messages.  The fuzzy
checksums are changed as spam evolves.

Note that DCC is disabled by default in C<init.pre> because it is not
open source.  See the DCC license for more details.

See http://www.rhyolite.com/anti-spam/dcc/ for more information about
DCC.

=cut

package Mail::SpamAssassin::Plugin::DCC;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use IO::Socket;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

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

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

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

This option tells SpamAssassin specifically where to find the dcc homedir.
If C<dcc_path> is not specified, it will default to looking in
C<dcc_home/bin> for dcc client instead of relying on SpamAssassin to find it
in the current PATH.  If it isn't found there, it will look in the current
PATH. If a C<dccifd> socket is found in C<dcc_home>, it will use that
interface that instead of C<dccproc>.

=cut

  push (@cmds, {
    setting => 'dcc_home',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = Mail::SpamAssassin::Util::untaint_file_path($value);
      if (!-d $value) {
	info("config: dcc_home \"$value\" isn't a directory");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{dcc_home} = $value;
    }
  });

=item dcc_dccifd_path STRING

This option tells SpamAssassin specifically where to find the dccifd socket.
If C<dcc_dccifd_path> is not specified, it will default to looking in
C<dcc_home> If a C<dccifd> socket is found, it will use it instead of
C<dccproc>.

=cut

  push (@cmds, {
    setting => 'dcc_dccifd_path',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = Mail::SpamAssassin::Util::untaint_file_path($value);
      if (!-S $value) {
	info("config: dcc_dccifd_path \"$value\" isn't a socket");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{dcc_dccifd_path} = $value;
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
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = Mail::SpamAssassin::Util::untaint_file_path($value);
      if (!-x $value) {
	info("config: dcc_path \"$value\" isn't an executable");
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

sub is_dccifd_available {
  my ($self) = @_;

  $self->{dccifd_available} = 0;
  if ($self->{main}->{conf}->{use_dcc} == 0) {
    dbg("dcc: dccifd is not available: use_dcc is set to 0");
    return 0;
  }
  my $dcchome = $self->{main}->{conf}->{dcc_home} || '';
  my $dccifd = $self->{main}->{conf}->{dcc_dccifd_path} || '';

  if (!$dccifd && ($dcchome && -S "$dcchome/dccifd")) {
    $dccifd = "$dcchome/dccifd";
  }

  unless ($dccifd && -S $dccifd && -w _ && -r _) {
    dbg("dcc: dccifd is not available: no r/w dccifd socket found");
    return 0;
  }

  # remember any found dccifd socket
  $self->{main}->{conf}->{dcc_dccifd_path} = $dccifd;

  dbg("dcc: dccifd is available: " . $self->{main}->{conf}->{dcc_dccifd_path});
  $self->{dccifd_available} = 1;
  return 1;
}

sub is_dccproc_available {
  my ($self) = @_;

  $self->{dccproc_available} = 0;
  if ($self->{main}->{conf}->{use_dcc} == 0) {
    dbg("dcc: dccproc is not available: use_dcc is set to 0");
    return 0;
  }
  my $dcchome = $self->{main}->{conf}->{dcc_home} || '';
  my $dccproc = $self->{main}->{conf}->{dcc_path} || '';

  if (!$dccproc && ($dcchome && -x "$dcchome/bin/dccproc")) {
    $dccproc  = "$dcchome/bin/dccproc";
  }
  unless ($dccproc) {
    $dccproc = Mail::SpamAssassin::Util::find_executable_in_env_path('dccproc');
  }

  unless ($dccproc && -x $dccproc) {
    dbg("dcc: dccproc is not available: no dccproc executable found");
    return 0;
  }

  # remember any found dccproc
  $self->{main}->{conf}->{dcc_path} = $dccproc;

  dbg("dcc: dccproc is available: " . $self->{main}->{conf}->{dcc_path});
  $self->{dccproc_available} = 1;
  return 1;
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

sub check_dcc {
  my ($self, $permsgstatus, $full) = @_;

  # short-circuit if there's already a X-DCC header with value of
  # "bulk" from an upstream DCC check
  if ($permsgstatus->get('ALL') =~ /^X-DCC-([^:]{1,80})?-?Metrics:.*bulk/m) {
    $permsgstatus->{tag_data}->{DCCB} = $1;
    $permsgstatus->{tag_data}->{DCCR} = "bulk";
    return 1;
  }

  # initialize valid tags
  $permsgstatus->{tag_data}->{DCCB} = "";
  $permsgstatus->{tag_data}->{DCCR} = "";

  $self->get_dcc_interface();
  return 0 if $self->{dcc_disabled};

  if ($$full eq '') {
    dbg("dcc: empty message, skipping dcc check");
    return 0;
  }

  my $client = $permsgstatus->{relays_external}->[0]->{ip};
  if ($self->{dccifd_available}) {
    my $clientname = $permsgstatus->{relays_external}->[0]->{rdns};
    my $helo = $permsgstatus->{relays_external}->[0]->{helo} || "";
    if ($client) {
      if ($clientname) {
        $client = $client . "\r" . $clientname;
      }
    } else {
      $client = "0.0.0.0";
    }
    return $self->dccifd_lookup($permsgstatus, $full, $client, $clientname, $helo);
  }
  else {
    return $self->dccproc_lookup($permsgstatus, $full, $client);
  }
  return 0;
}

sub dccifd_lookup {
  my ($self, $permsgstatus, $fulltext, $client, $clientname, $helo) = @_;
  my $response = "";
  my %count;
  my $left;
  my $right;
  my $timeout = $self->{main}->{conf}->{dcc_timeout};
  my $sockpath = $self->{main}->{conf}->{dcc_dccifd_path};
  my $opts = $self->{main}->{conf}->{dccifd_options} || '';

  $count{body} = 0;
  $count{fuz1} = 0;
  $count{fuz2} = 0;

  $permsgstatus->enter_helper_run_mode();

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM,
      Peer => $sockpath) || dbg("dcc: failed to open socket") && die;

    # send the options and other parameters to the daemon
    $sock->print("header " . $opts . "\n") || dbg("dcc: failed write") && die; # options
    $sock->print($client . "\n") || dbg("dcc: failed write") && die; # client
    $sock->print($helo . "\n") || dbg("dcc: failed write") && die; # HELO value
    $sock->print("\n") || dbg("dcc: failed write") && die; # sender
    $sock->print("unknown\r\n") || dbg("dcc: failed write") && die; # recipients
    $sock->print("\n") || dbg("dcc: failed write") && die; # recipients

    $sock->print($$fulltext);

    $sock->shutdown(1) || dbg("dcc: failed socket shutdown: $!") && die;

    $sock->getline() || dbg("dcc: failed read status") && die;
    $sock->getline() || dbg("dcc: failed read multistatus") && die;

    my @null = $sock->getlines();
    if (!@null) {
      # no facility prefix on this
      die("failed to read header\n");
    }

    # the first line will be the header we want to look at
    chomp($response = shift @null);
    # but newer versions of DCC fold the header if it's too long...
    while (my $v = shift @null) {
      last unless ($v =~ s/^\s+/ /);  # if this line wasn't folded, stop
      chomp $v;
      $response .= $v;
    }

    dbg("dcc: dccifd got response: $response");
  
  });

  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: dccifd check timed out after $timeout secs.");
    return 0;
  }

  if ($err) {
    chomp $err;
    warn("dcc: dccifd -> check skipped: $! $err");
    return 0;
  }

  if (!defined $response || $response !~ /^X-DCC/) {
    dbg("dcc: dccifd check failed - no X-DCC returned: $response");
    return 0;
  }

  if ($response =~ /^X-DCC-(.*)-Metrics: (.*)$/) {
    $permsgstatus->{tag_data}->{DCCB} = $1;
    $permsgstatus->{tag_data}->{DCCR} = $2;
  }

  $response =~ s/many/999999/ig;
  $response =~ s/ok\d?/0/ig;

  if ($response =~ /Body=(\d+)/) {
    $count{body} = $1+0;
  }
  if ($response =~ /Fuz1=(\d+)/) {
    $count{fuz1} = $1+0;
  }
  if ($response =~ /Fuz2=(\d+)/) {
    $count{fuz2} = $1+0;
  }

  if ($count{body} >= $self->{main}->{conf}->{dcc_body_max} ||
      $count{fuz1} >= $self->{main}->{conf}->{dcc_fuz1_max} ||
      $count{fuz2} >= $self->{main}->{conf}->{dcc_fuz2_max})
  {
    dbg(sprintf("dcc: listed: BODY=%s/%s FUZ1=%s/%s FUZ2=%s/%s",
		$count{body}, $self->{main}->{conf}->{dcc_body_max},
		$count{fuz1}, $self->{main}->{conf}->{dcc_fuz1_max},
		$count{fuz2}, $self->{main}->{conf}->{dcc_fuz2_max}));
    return 1;
  }
  
  return 0;
}

sub dccproc_lookup {
  my ($self, $permsgstatus, $fulltext, $client) = @_;
  my $response = undef;
  my %count;
  my $timeout = $self->{main}->{conf}->{dcc_timeout};

  $count{body} = 0;
  $count{fuz1} = 0;
  $count{fuz2} = 0;

  $permsgstatus->enter_helper_run_mode();

  # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
  my $tmpf = $permsgstatus->create_fulltext_tmpfile($fulltext);
  my $pid;

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    # note: not really tainted, this came from system configuration file
    my $path = Mail::SpamAssassin::Util::untaint_file_path($self->{main}->{conf}->{dcc_path});

    my $opts = $self->{main}->{conf}->{dcc_options} || '';
    $opts = "-a " . $client . " " . $opts if $client;

    dbg("dcc: opening pipe: " . join(' ', $path, "-H", "-x", "0", $opts, "< $tmpf"));

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
	$tmpf, 1, $path, "-H", "-x", "0", split(' ', $opts));
    $pid or die "$!\n";

    my @null = <DCC>;
    close DCC
      or dbg(sprintf("dcc: [%s] finished: %s exit=0x%04x",$pid,$!,$?));

    if (!@null) {
      # no facility prefix on this
      die("failed to read header\n");
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
      die("no response\n");	# yes, this is possible
    }

    dbg("dcc: got response: $response");

  });

  if (defined(fileno(*DCC))) {  # still open
    if ($pid) {
      if (kill('TERM',$pid)) { dbg("dcc: killed stale helper [$pid]") }
      else { dbg("dcc: killing helper application [$pid] failed: $!") }
    }
    close DCC
      or dbg(sprintf("dcc: [%s] terminated: %s exit=0x%04x",$pid,$!,$?));
  }
  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("dcc: check timed out after $timeout seconds");
    return 0;
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
    return 0;
  }

  if (!defined($response) || $response !~ /^X-DCC/) {
    $response ||= '';
    dbg("dcc: check failed: no X-DCC returned (did you create a map file?): $response");
    return 0;
  }

  if ($response =~ /^X-DCC-(.*)-Metrics: (.*)$/) {
    $permsgstatus->{tag_data}->{DCCB} = $1;
    $permsgstatus->{tag_data}->{DCCR} = $2;
  }

  $response =~ s/many/999999/ig;
  $response =~ s/ok\d?/0/ig;

  if ($response =~ /Body=(\d+)/) {
    $count{body} = $1+0;
  }
  if ($response =~ /Fuz1=(\d+)/) {
    $count{fuz1} = $1+0;
  }
  if ($response =~ /Fuz2=(\d+)/) {
    $count{fuz2} = $1+0;
  }

  if ($count{body} >= $self->{main}->{conf}->{dcc_body_max} ||
      $count{fuz1} >= $self->{main}->{conf}->{dcc_fuz1_max} ||
      $count{fuz2} >= $self->{main}->{conf}->{dcc_fuz2_max})
  {
    dbg(sprintf("dcc: listed: BODY=%s/%s FUZ1=%s/%s FUZ2=%s/%s",
		$count{body}, $self->{main}->{conf}->{dcc_body_max},
		$count{fuz1}, $self->{main}->{conf}->{dcc_fuz1_max},
		$count{fuz2}, $self->{main}->{conf}->{dcc_fuz2_max}));
    return 1;
  }

  return 0;
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
  my $timeout = $self->{main}->{conf}->{dcc_timeout};
  my $sockpath = $self->{main}->{conf}->{dcc_dccifd_path};
  my $opts = $self->{main}->{conf}->{dccifd_options} || ''; # instead of header use whatever the report option is

  $options->{report}->enter_helper_run_mode();
  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });

  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    my $sock = IO::Socket::UNIX->new(Type => SOCK_STREAM,
                                     Peer => $sockpath) || dbg("report: dccifd failed to open socket") && die;

    # send the options and other parameters to the daemon
    $sock->print("spam " . $opts . "\n") || dbg("report: dccifd failed write") && die; # options
    $sock->print($client . "\n") || dbg("report: dccifd failed write") && die; # client
    $sock->print($helo . "\n") || dbg("report: dccifd failed write") && die; # HELO value
    $sock->print("\n") || dbg("report: dccifd failed write") && die; # sender
    $sock->print("unknown\r\n") || dbg("report: dccifd failed write") && die; # recipients
    $sock->print("\n") || dbg("report: dccifd failed write") && die; # recipients

    $sock->print($$fulltext);

    $sock->shutdown(1) || dbg("report: dccifd failed socket shutdown: $!") && die;

    $sock->getline() || dbg("report: dccifd failed read status") && die;
    $sock->getline() || dbg("report: dccifd failed read multistatus") && die;

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
  my $timeout = $options->{report}->{conf}->{dcc_timeout};

  # note: not really tainted, this came from system configuration file
  my $path = Mail::SpamAssassin::Util::untaint_file_path($options->{report}->{conf}->{dcc_path});

  my $opts = $options->{report}->{conf}->{dcc_options} || '';

  # get the metadata from the message so we can pass the external relay information
  $opts = "-a " . $client . " " . $opts if $client;

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });

  $options->{report}->enter_helper_run_mode();
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    dbg("report: opening pipe: " . join(' ', $path, "-H", "-t", "many", "-x", "0", $opts, "< $tmpf"));

    my $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*DCC,
        $tmpf, 1, $path, "-H", "-t", "many", "-x", "0", split(' ', $opts));
    $pid or die "$!\n";

    my @ignored = <DCC>;
    $options->{report}->close_pipe_fh(\*DCC);
    waitpid ($pid, 0);
  
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
