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

Mail::SpamAssassin::Client - Client for spamd Protocol

=head1 SYNOPSIS

  my $client = Mail::SpamAssassin::Client->new({
                                port => 783,
                                host => 'localhost',
                                username => 'someuser'});
  or

  my $client = Mail::SpamAssassin::Client->new({
                                socketpath => '/path/to/socket',
                                username => 'someuser'});

  Optionally takes timeout, which is applied to IO::Socket for the
  initial connection.  If not supplied, it defaults to 30 seconds.

  if ($client->ping()) {
    print "Ping is ok\n";
  }

  my $result = $client->process($testmsg);

  if ($result->{isspam} eq 'True') {
    do something with spam message here
  }

=head1 DESCRIPTION

Mail::SpamAssassin::Client is a module which provides a perl implementation of
the spamd protocol.

=cut

package Mail::SpamAssassin::Client;

use strict;
use warnings;
use re 'taint';

use IO::Socket;
use Errno qw(EBADF);

our($io_socket_module_name);
BEGIN {
  if (eval { require IO::Socket::IP }) {
    $io_socket_module_name = 'IO::Socket::IP';
  } elsif (eval { require IO::Socket::INET6 }) {
    $io_socket_module_name = 'IO::Socket::INET6';
  } elsif (eval { require IO::Socket::INET }) {
    $io_socket_module_name = 'IO::Socket::INET';
  }
}

my $EOL = "\015\012";
my $BLANK = $EOL x 2;
my $PROTOVERSION = 'SPAMC/1.5';

=head1 PUBLIC METHODS

=head2 new

public class (Mail::SpamAssassin::Client) new (\% $args)

Description:
This method creates a new Mail::SpamAssassin::Client object.

=cut

sub new {
  my ($class, $args) = @_;

  $class = ref($class) || $class;

  my $self = {};

  # with a sockets_path set then it makes no sense to set host and port
  if ($args->{socketpath}) {
    $self->{socketpath} = $args->{socketpath};
  }
  else {
    $self->{port} = $args->{port};
    $self->{host} = $args->{host};
  }

  if (defined $args->{username}) {
    $self->{username} = $args->{username};
  }

  if ($args->{max_size}) {
    $self->{max_size} = $args->{max_size};
  }

  if ($args->{timeout}) {
    $self->{timeout} = $args->{timeout} || 30;
  }

  bless($self, $class);

  $self;
}

=head2 process

public instance (\%) process (String $msg)

Description:
This method calls the spamd server with the PROCESS command.

The return value is a hash reference containing several pieces of information,
if available:

content_length

isspam

score

threshold

message

report

=cut

sub process {
  my ($self, $msg, $is_check_p) = @_;

  my $command = 'PROCESS';

  if ($is_check_p) {
    warn "Passing in \$is_check_p is deprecated, just call the check method instead.\n";
    $command = 'CHECK';
  }

  return $self->_filter($msg, $command);
}

=head2 spam_report

public instance (\%) spam_report (String $msg)

Description:
The method implements the report call.

See the process method for the return value.

=cut

sub spam_report {
  my ($self, $msg) = @_;

  return $self->_filter($msg, 'REPORT');
}

=head2 spam_report_ifspam

public instance (\%) spam_report_ifspam (String $msg)

Description:
The method implements the report_ifspam call.
A report will be returned only if the message is spam.

See the process method for the return value.

=cut

sub spam_report_ifspam {
  my ($self, $msg) = @_;

  return $self->_filter($msg, 'REPORT_IFSPAM');
}

=head2 check

public instance (\%) check (String $msg)

Description:
The method implements the check call.

See the process method for the return value.

=cut

sub check {
  my ($self, $msg) = @_;

  return $self->_filter($msg, 'CHECK');
}

=head2 headers

public instance (\%) headers (String $msg)

Description:
This method implements the headers call.

See the process method for the return value.

=cut

sub headers {
  my ($self, $msg) = @_;

  return $self->_filter($msg, 'HEADERS');
}

=head2 learn

public instance (Boolean) learn (String $msg, Integer $learntype)

Description:
This method implements the learn call.  C<$learntype> should be
an integer, 0 for spam, 1 for ham and 2 for forget.  The return
value is a boolean indicating if the message was learned or not.

An undef return value indicates that there was an error and you
should check the resp_code/resp_msg values to determine what
the error was.

=cut

sub learn {
  my ($self, $msg, $learntype) = @_;

  $self->_clear_errors();

  my $remote = $self->_create_connection();

  return unless $remote;

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if defined $self->{username};

  if ($learntype == 0) {
    print $remote "Message-class: spam$EOL";
    print $remote "Set: local$EOL";
  }
  elsif ($learntype == 1) {
    print $remote "Message-class: ham$EOL";
    print $remote "Set: local$EOL";
  }
  elsif ($learntype == 2) {
    print $remote "Remove: local$EOL";
  }
  else { # bad learntype
    $self->{resp_code} = 00;
    $self->{resp_msg} = 'do not know';
    return;
  }

  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  $! = 0; my $line = <$remote>;
  # deal gracefully with a Perl I/O bug which may return status EBADF at eof
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (1): $!")
              : die "error reading from spamd (1): $!";
  return unless defined $line;

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return unless $resp_code == 0;

  my $did_set = '';
  my $did_remove = '';

  for ($!=0; defined($line=<$remote>); $!=0) {
    local $1;
    if ($line =~ /DidSet: (.*)/i) {
      $did_set = $1;
    }
    elsif ($line =~ /DidRemove: (.*)/i) {
      $did_remove = $1;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (2): $!")
              : die "error reading from spamd (2): $!";
  close $remote  or die "error closing socket: $!";

  if ($learntype == 0 || $learntype == 1) {
    return index($did_set, 'local') >= 0;
  }
  else { #safe since we've already checked the $learntype values
    return index($did_remove, 'local') >= 0;
  }
}

=head2 report

public instance (Boolean) report (String $msg)

Description:
This method provides the report interface to spamd.

=cut

sub report {
  my ($self, $msg) = @_;

  $self->_clear_errors();

  my $remote = $self->_create_connection();

  return unless $remote;

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if defined $self->{username};
  print $remote "Message-class: spam$EOL";
  print $remote "Set: local,remote$EOL";
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  $! = 0; my $line = <$remote>;
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (3): $!")
              : die "error reading from spamd (3): $!";
  return unless defined $line;

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return unless $resp_code == 0;

  my $reported_p = 0;

  for ($!=0; defined($line=<$remote>); $!=0) {
    if ($line =~ /DidSet:\s+.*remote/i) {
      $reported_p = 1;
      last;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (4): $!")
              : die "error reading from spamd (4): $!";
  close $remote  or die "error closing socket: $!";

  return $reported_p;
}

=head2 revoke

public instance (Boolean) revoke (String $msg)

Description:
This method provides the revoke interface to spamd.

=cut

sub revoke {
  my ($self, $msg) = @_;

  $self->_clear_errors();

  my $remote = $self->_create_connection();

  return unless $remote;

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if defined $self->{username};
  print $remote "Message-class: ham$EOL";
  print $remote "Set: local$EOL";
  print $remote "Remove: remote$EOL";
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  $! = 0; my $line = <$remote>;
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (5): $!")
              : die "error reading from spamd (5): $!";
  return unless defined $line;

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return unless $resp_code == 0;

  my $revoked_p = 0;

  for ($!=0; defined($line=<$remote>); $!=0) {
    if ($line =~ /DidRemove:\s+remote/i) {
      $revoked_p = 1;
      last;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (6): $!")
              : die "error reading from spamd (6): $!";
  close $remote  or die "error closing socket: $!";

  return $revoked_p;
}


=head2 ping

public instance (Boolean) ping ()

Description:
This method performs a server ping and returns 0 or 1 depending on
if the server responded correctly.

=cut

sub ping {
  my ($self) = @_;

  my $remote = $self->_create_connection();

  return 0 unless ($remote);

  print $remote "PING $PROTOVERSION$EOL";
  print $remote "$EOL";  # bug 6187, bumps protocol version to 1.5

  $! = 0; my $line = <$remote>;
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (7): $!")
              : die "error reading from spamd (7): $!";
  close $remote  or die "error closing socket: $!";
  return unless defined $line;

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);
  return 0 unless ($resp_msg eq 'PONG');

  return 1;
}

=head1 PRIVATE METHODS

=head2 _create_connection

private instance (IO::Socket) _create_connection ()

Description:
This method sets up a proper IO::Socket connection based on the arguments
used when creating the client object.

On failure, it sets an internal error code and returns undef.

=cut

sub _create_connection {
  my ($self) = @_;

  my $remote;

  if ($self->{socketpath}) {
    $remote = IO::Socket::UNIX->new( Peer => $self->{socketpath},
				     Type => SOCK_STREAM,
				     Timeout => $self->{timeout},
				   );
  }
  else {
    my %params = ( Proto    => "tcp",
		   PeerAddr => $self->{host},
		   PeerPort => $self->{port},
		   Timeout  => $self->{timeout},
		 );
    $remote = $io_socket_module_name->new(%params);
  }

  unless ($remote) {
    warn "Failed to create connection to spamd daemon: $!\n";
    return;
  }

  $remote;
}

=head2 _parse_response_line

private instance (@) _parse_response_line (String $line)

Description:
This method parses the initial response line/header from the server
and returns its parts.

We have this as a separate method in case we ever decide to get fancy
with the response line.

=cut

sub _parse_response_line {
  my ($self, $line) = @_;

  $line =~ s/\r?\n$//;
  return split(/\s+/, $line, 3);
}

=head2 _clear_errors

private instance () _clear_errors ()

Description:
This method clears out any current errors.

=cut

sub _clear_errors {
  my ($self) = @_;

  $self->{resp_code} = undef;
  $self->{resp_msg} = undef;
}

=head2 _filter

private instance (\%) _filter (String $msg, String $command)

Description:
Makes the actual call to the spamd server for the various filter method
(ie PROCESS, CHECK, HEADERS, etc).  The command that is passed in is
sent to the spamd server.

The return value is a hash reference containing several pieces of information,
if available:

content_length

isspam

score

threshold

message (if available)

report (if available)

=cut

sub _filter {
  my ($self, $msg, $command) = @_;

  my %data;
  my $msgsize;

  $self->_clear_errors();

  my $remote = $self->_create_connection();

  return 0 unless ($remote);

  if(defined $self->{max_size}) {
    $msg = substr($msg,0,$self->{max_size});
  }
  $msgsize = length($msg);

  print $remote "$command $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if defined $self->{username};
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  $! = 0; my $line = <$remote>;
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (8): $!")
              : die "error reading from spamd (8): $!";
  return unless defined $line;

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);
  
  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return unless $resp_code == 0;

  for ($!=0; defined($line=<$remote>); $!=0) {
    local($1,$2,$3);
    if ($line =~ /Content-length: (\d+)/) {
      $data{content_length} = $1;
    }
    elsif ($line =~ m!Spam: (\S+) ; (\S+) / (\S+)!) {
      $data{isspam} = $1;
      $data{score} = $2 + 0;
      $data{threshold} = $3 + 0;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (9): $!")
              : die "error reading from spamd (9): $!";

  my $return_msg;
  for ($!=0; defined($line=<$remote>); $!=0) {
    $return_msg .= $line;
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("error reading from spamd (10): $!")
              : die "error reading from spamd (10): $!";

  if($command =~ /^REPORT/) {
    $data{report} = $return_msg if ($return_msg);
  } else {
    $data{message} = $return_msg if ($return_msg);
  }

  close $remote  or die "error closing socket: $!";

  return \%data;
}

1;

