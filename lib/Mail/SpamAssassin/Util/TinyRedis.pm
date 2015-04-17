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

package Mail::SpamAssassin::Util::TinyRedis;
# Implements the new unified request protocol, introduced in Redis 1.2 .

use strict;
use re 'taint';
use warnings;

use Errno qw(EINTR EAGAIN EPIPE ENOTCONN ECONNRESET ECONNABORTED);
use IO::Socket::UNIX;
use Time::HiRes ();

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
  my($class, %args) = @_;
  my $self = bless { args => {%args} }, $class;
  my $outbuf = ''; $self->{outbuf} = \$outbuf;
  $self->{batch_size} = 0;
  $self->{server} = $args{server} || $args{sock} || '127.0.0.1:6379';
  $self->{on_connect} = $args{on_connect};
  return if !$self->connect;
  $self;
}

sub DESTROY {
  my $self = $_[0];
  local($@, $!, $_);
  undef $self->{sock};
}

sub disconnect {
  my $self = $_[0];
  local($@, $!);
  undef $self->{sock};
}

sub connect {
  my $self = $_[0];

  $self->disconnect;
  my $sock;
  my $server = $self->{server};
  if ($server =~ m{^/}) {
    $sock = IO::Socket::UNIX->new(
              Peer => $server, Type => SOCK_STREAM);
  } elsif ($server =~ /^(?: \[ ([^\]]+) \] | ([^:]+) ) : ([^:]+) \z/xs) {
    $server = defined $1 ? $1 : $2;  my $port = $3;
    $sock = $io_socket_module_name->new(
              PeerAddr => $server, PeerPort => $port, Proto => 'tcp');
  } else {
    die "Invalid 'server:port' specification: $server";
  }
  if ($sock) {
    $self->{sock} = $sock;

    $self->{sock_fd} = $sock->fileno; $self->{fd_mask} = '';
    vec($self->{fd_mask}, $self->{sock_fd}, 1) = 1;

    # an on_connect() callback must not use batched calls!
    $self->{on_connect}->($self)  if $self->{on_connect};
  }
  $sock;
}

# Receive, parse and return $cnt consecutive redis replies as a list.
#
sub _response {
  my($self, $cnt) = @_;

  my $sock = $self->{sock};
  if (!$sock) {
    $self->connect  or die "Connect failed: $!";
    $sock = $self->{sock};
  };

  my @list;

  for (1 .. $cnt) {

    my $result = <$sock>;
    if (!defined $result) {
      $self->disconnect;
      die "Error reading from Redis server: $!";
    }
    chomp $result;
    my $resp_type = substr($result, 0, 1, '');

    if ($resp_type eq '$') {  # bulk reply
      if ($result < 0) {
        push(@list, undef);  # null bulk reply
      } else {
        my $data = ''; my $ofs = 0; my $len = $result + 2;
        while ($len > 0) {
          my $nbytes = read($sock, $data, $len, $ofs);
          if (!$nbytes) {
            $self->disconnect;
            defined $nbytes  or die "Error reading from Redis server: $!";
            die "Redis server closed connection";
          }
          $ofs += $nbytes; $len -= $nbytes;
        }
        chomp $data;
        push(@list, $data);
      }

    } elsif ($resp_type eq ':') {  # integer reply
      push(@list, 0+$result);

    } elsif ($resp_type eq '+') {  # status reply
      push(@list, $result);

    } elsif ($resp_type eq '*') {  # multi-bulk reply
      push(@list, $result < 0 ? undef : $self->_response(0+$result) );

    } elsif ($resp_type eq '-') {  # error reply
      die "$result\n";

    } else {
      die "Unknown Redis reply: $resp_type ($result)";
    }
  }
  \@list;
}

sub _write_buff {
  my($self, $bufref) = @_;

  if (!$self->{sock}) { $self->connect or die "Connect failed: $!" };
  my $nwrite;
  for (my $ofs = 0; $ofs < length($$bufref); $ofs += $nwrite) {
    # to reliably detect a disconnect we need to check for an input event
    # using a select; checking status of syswrite is not sufficient
    my($rout, $wout, $inbuff); my $fd_mask = $self->{fd_mask};
    my $nfound = select($rout=$fd_mask, $wout=$fd_mask, undef, undef);
    defined $nfound && $nfound >= 0 or die "Select failed: $!";
    if (vec($rout, $self->{sock_fd}, 1) &&
        !sysread($self->{sock}, $inbuff, 1024)) {
      # eof, try reconnecting
      $self->connect  or die "Connect failed: $!";
    }
    local $SIG{PIPE} = 'IGNORE';  # don't signal on a write to a widowed pipe
    $nwrite = syswrite($self->{sock}, $$bufref, length($$bufref)-$ofs, $ofs);
    next if defined $nwrite;
    $nwrite = 0;
    if ($! == EINTR || $! == EAGAIN) {  # no big deal, try again
      Time::HiRes::sleep(0.1);  # slow down, just in case
    } else {
      $self->disconnect;
      if ($! == ENOTCONN   || $! == EPIPE ||
          $! == ECONNRESET || $! == ECONNABORTED) {
        $self->connect  or die "Connect failed: $!";
      } else {
        die "Error writing to redis socket: $!";
      }
    }
  }
  1;
}

# Send a redis command with arguments, returning a redis reply.
#
sub call {
  my $self = shift;

  my $buff = '*' . scalar(@_) . "\015\012";
  $buff .= '$' . length($_) . "\015\012" . $_ . "\015\012"  for @_;

  $self->_write_buff(\$buff);
  local($/) = "\015\012";
  my $arr_ref = $self->_response(1);
  $arr_ref && $arr_ref->[0];
}

# Append a redis command with arguments to a batch.
#
sub b_call {
  my $self = shift;

  my $bufref = $self->{outbuf};
  $$bufref .= '*' . scalar(@_) . "\015\012";
  $$bufref .= '$' . length($_) . "\015\012" . $_ . "\015\012"  for @_;
  ++ $self->{batch_size};
}

# Send a batch of commands, returning an arrayref of redis replies,
# each array element corresponding to one command in a batch.
#
sub b_results {
  my $self = $_[0];
  my $batch_size = $self->{batch_size};
  return if !$batch_size;
  my $bufref = $self->{outbuf};
  $self->_write_buff($bufref);
  $$bufref = ''; $self->{batch_size} = 0;
  local($/) = "\015\012";
  $self->_response($batch_size);
}

1;
