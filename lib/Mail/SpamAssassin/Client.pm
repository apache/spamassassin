# NOTE: This interface is alpha at best, and almost guaranteed to change
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

NOTE: This interface is alpha at best, and almost guaranteed to change

=head1 SYNOPSIS

  my $client = new Mail::SpamAssassin::Client({port => 783,
                                               host => 'localhost',
                                               username => 'someuser'});

  if ($client->ping()) {
    print "Ping is ok\n";
  }

  my $result = $client->process($testmsg);

  if ($result->{isspam} eq 'True') {
    do something with spam message here
  }

=head1 DESCRIPTION

Mail::SpamAssassin::Client is a module that provides a perl implementation for
the spamd protocol.

=cut

package Mail::SpamAssassin::Client;

use IO::Socket;

my $EOL = "\015\012";
my $BLANK = $EOL x 2;
my $PROTOVERSION = 'SPAMC/1.3';

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

  if ($args->{username}) {
    $self->{username} = $args->{username};
  }

  bless($self, $class);

  $self;
}

=head2 process

public instance (\%) process (String $msg, Boolean $is_check_p)

Description:
This method makes a call to the spamd server and depending on the value of
C<$is_check_p> either calls PROCESS or CHECK.

The return value is a hash reference containing several pieces of information,
if available:

content_length

isspam

score

threshold

message

=cut

sub process {
  my ($self, $msg, $is_check_p) = @_;

  my %data;

  my $command = $is_check_p ? 'CHECK' : 'PROCESS';

  $self->_clear_errors();

  my $remote = $self->_create_connection();

  return 0 unless ($remote);

  my $msgsize = length($msg.$EOL);

  print $remote "$command $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if ($self->{username});
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  my $line = <$remote>;
  return undef unless (defined $line);

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return undef unless ($resp_code == 0);

  while ($line = <$remote>) {
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

  my $return_msg;
  while(<$remote>) {
    $return_msg .= $_;
  }

  $data{message} = $return_msg if ($return_msg);

  close $remote;

  return \%data;
}

=head2 check

public instance (\%) check (String $msg)

Description:
The method implements the check call.

Since check and process are so similar, we simply pass this
call along to the process method with a flag to indicate
to actually make the CHECK call.

See the process method for the return value.

=cut

sub check {
  my ($self, $msg) = @_;

  return $self->process($msg, 1);
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

  return undef unless ($remote);

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if ($self->{username});

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
    return undef;
  }

  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  my $line = <$remote>;
  return undef unless (defined $line);

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return undef unless ($resp_code == 0);

  my $did_set;
  my $did_remove;

  while ($line = <$remote>) {
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

  close $remote;

  if ($learntype == 0 || $learntype == 1) {
    return $did_set =~ /local/;
  }
  else { #safe since we've already checked the $learntype values
    return $did_remove =~ /local/;
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

  return undef unless ($remote);

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if ($self->{username});
  print $remote "Message-class: spam$EOL";
  print $remote "Set: local,remote$EOL";
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  my $line = <$remote>;
  return undef unless (defined $line);

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return undef unless ($resp_code == 0);

  my $reported_p = 0;

  while (($line = <$remote>)) {
    if ($line =~ /DidSet:\s+.*remote/i) {
      $reported_p = 1;
      last;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }

  close $remote;

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

  return undef unless ($remote);

  my $msgsize = length($msg.$EOL);

  print $remote "TELL $PROTOVERSION$EOL";
  print $remote "Content-length: $msgsize$EOL";
  print $remote "User: $self->{username}$EOL" if ($self->{username});
  print $remote "Message-class: ham$EOL";
  print $remote "Set: local$EOL";
  print $remote "Remove: remote$EOL";
  print $remote "$EOL";
  print $remote $msg;
  print $remote "$EOL";

  my $line = <$remote>;
  return undef unless (defined $line);

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);

  $self->{resp_code} = $resp_code;
  $self->{resp_msg} = $resp_msg;

  return undef unless ($resp_code == 0);

  my $revoked_p = 0;

  while (!$revoked_p && ($line = <$remote>)) {
    if ($line =~ /DidRemove:\s+remote/i) {
      $revoked_p = 1;
      last;
    }
    elsif ($line =~ /^${EOL}$/) {
      last;
    }
  }

  close $remote;

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
  print $remote "$EOL";

  my $line = <$remote>;
  close $remote;
  return undef unless (defined $line);

  my ($version, $resp_code, $resp_msg) = $self->_parse_response_line($line);
  return 0 unless ($resp_msg eq 'PONG');

  return 1;
}

=head1 PRIVATE METHODS

=head2 _create_connection

private instance (IO::Socket) _create_connection ()

Description:
This method sets up a proper IO::Socket connection based on the arguments
used when greating the client object.

On failure, it sets an internal error code and returns undef.

=cut

sub _create_connection {
  my ($self) = @_;

  my $remote;

  if ($self->{socketpath}) {
    $remote = IO::Socket::UNIX->new( Peer => $self->{socketpath},
				     Type => SOCK_STREAM,
				   );
  }
  else {
    $remote = IO::Socket::INET->new( Proto     => "tcp",
				     PeerAddr  => $self->{host},
				     PeerPort  => $self->{port},
				   );
  }

  unless ($remote) {
    print "Failed to create connection to spamd daemon: $!\n";
    return undef;
  }

  $remote;
}

=head2 _parse_response_line

private instance (@) _parse_response_line (String $line)

Description:
This method parses the initial response line/header from the server
and returns its parts.

We have this as a seperate method in case we ever decide to get fancy
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

1;

