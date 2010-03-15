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

Mail::SpamAssassin::DnsResolver - DNS resolution engine

=head1 DESCRIPTION

This is a DNS resolution engine for SpamAssassin, implemented in order to
reduce file descriptor usage by Net::DNS and avoid a response collision bug in
that module.

=head1 METHODS

=over 4

=cut

# TODO: caching in this layer instead of in callers.

package Mail::SpamAssassin::DnsResolver;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

use Socket;
use IO::Socket::INET;
use Errno qw(EADDRINUSE EACCES);
use Time::HiRes qw(time);

use constant HAS_SOCKET_INET6 => eval { require IO::Socket::INET6; };

our @ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    'main'              => $main,
    'conf'		=> $main->{conf},
    'id_to_callback'    => { },
  };
  bless ($self, $class);

  $self->load_resolver();
  $self;
}

###########################################################################

=item $res->load_resolver()

Load the C<Net::DNS::Resolver> object.  Returns 0 if Net::DNS cannot be used,
1 if it is available.

=cut

sub load_resolver {
  my ($self) = @_;

  if (defined $self->{res}) { return 1; }
  $self->{no_resolver} = 1;
  # force only ipv4 if no IO::Socket::INET6 or ipv6 doesn't work
  # to be safe test both ipv6 and ipv4 addresses in INET6
  my $force_ipv4 = (!HAS_SOCKET_INET6) || $self->{main}->{force_ipv4} ||
    !eval {
      my $sock6 = IO::Socket::INET6->new(
                                         LocalAddr => "::",
                                         Proto     => 'udp',
                                         );
      if ($sock6) {
        $sock6->close()  or die "error closing inet6 socket: $!";
        1;
      }
    } ||
    !eval {
      my $sock6 = IO::Socket::INET6->new(
                                         LocalAddr => "0.0.0.0",
                                         PeerAddr => "0.0.0.0",
					 PeerPort => 53,
                                         Proto     => 'udp',
                                         );
      if ($sock6) {
        $sock6->close()  or die "error closing inet4 socket: $!";
        1;
      }
    };
  
  eval {
    require Net::DNS;
    # force_v4 is set in new() to avoid error in older versions of Net::DNS that don't have it
    # other options are set by function calls so a typo or API change will cause an error here
    $self->{res} = Net::DNS::Resolver->new(force_v4 => $force_ipv4);
    if (defined $self->{res}) {
      $self->{no_resolver} = 0;
      $self->{force_ipv4} = $force_ipv4;
      $self->{retry} = 1;               # retries for non-backgrounded query
      $self->{retrans} = 3;   # initial timeout for "non-backgrounded" query run in background
      $self->{res}->retry(1);           # If it fails, it fails
      $self->{res}->retrans(0);         # If it fails, it fails
      $self->{res}->dnsrch(0);          # ignore domain search-list
      $self->{res}->defnames(0);        # don't append stuff to end of query
      $self->{res}->tcp_timeout(3);     # timeout of 3 seconds only
      $self->{res}->udp_timeout(3);     # timeout of 3 seconds only
      $self->{res}->persistent_tcp(0);  # bug 3997
      $self->{res}->persistent_udp(0);  # bug 3997
    }
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("dns: eval failed: $eval_stat");
  };

  dbg("dns: no ipv6") if $force_ipv4;
  dbg("dns: is Net::DNS::Resolver available? %s",
      $self->{no_resolver} ? "no" : "yes" );
  if (!$self->{no_resolver} && defined $Net::DNS::VERSION) {
    dbg("dns: Net::DNS version: %s", $Net::DNS::VERSION);
  }

  return (!$self->{no_resolver});
}

=item $resolver = $res->get_resolver()

Return the C<Net::DNS::Resolver> object.

=cut

sub get_resolver {
  my ($self) = @_;
  return $self->{res};
}

=item $res->nameservers()

Wrapper for Net::DNS::Resolver->nameservers to get or set list of nameservers

=cut

sub nameservers {
  my $self = shift;
  my $res = $self->{res};
  $self->connect_sock_if_reqd();
  return $res->nameservers(@_) if $res;
}

=item $res->connect_sock()

Re-connect to the first nameserver listed in C</etc/resolv.conf> or similar
platform-dependent source, as provided by C<Net::DNS>.

=cut

sub connect_sock {
  my ($self) = @_;

  return if $self->{no_resolver};

  if ($self->{sock}) {
    $self->{sock}->close()  or die "error closing socket: $!";
  }
  my $sock;
  my $errno;

  # IO::Socket::INET6 may choose wrong LocalAddr if family is unspecified,
  # causing EINVAL failure when automatically assigned local IP address
  # and remote address do not belong to the same address family:
  use Mail::SpamAssassin::Constants qw(:ip);
  my $ip64 = IP_ADDRESS;
  my $ip4 = IPV4_ADDRESS;
  my $ns = $self->{res}->{nameservers}[0];
  my $ipv6opt = !($self->{force_ipv4});

  # ensure families of src and dest addresses match (bug 4412 comment 29)
  my $srcaddr;
  if ($ipv6opt && $ns=~/^${ip64}$/o && $ns!~/^${ip4}$/o) {
    $srcaddr = "::";
  } else {
    $srcaddr = "0.0.0.0";
  }

  dbg("dns: name server: %s, LocalAddr: %s", $ns,$srcaddr);

  # find next available unprivileged port (1024 - 65535)
  # starting at a random value to spread out use of ports
  my $port_offset = int(rand(64511));  # 65535 - 1024
  for (my $i = 0; $i<64511; $i++) {
    my $lport = 1024 + (($port_offset + $i) % 64511);

    my %args = (
        PeerAddr => $ns,
        PeerPort => $self->{res}->{port},
        Proto => 'udp',
        LocalPort => $lport,
        Type => SOCK_DGRAM,
        LocalAddr => $srcaddr,
    );

    if ($ipv6opt) {
      $sock = IO::Socket::INET6->new(%args);
    } else {
      $sock = IO::Socket::INET->new(%args);
    }
    $errno = $!;
    if (defined $sock) {  # ok, got it
      last;
    } elsif ($! == EADDRINUSE || $! == EACCES) {  # in use, let's try another source port
      dbg("dns: UDP port %s already in use, trying another port", $lport);
    } else {
      warn "error creating a DNS resolver socket: $errno";
      goto no_sock;
    }
  }
  if (!defined $sock) {
    warn "cannot create a DNS resolver socket: $errno";
    goto no_sock;
  }

  eval {
    my($bufsiz,$newbufsiz);
    $bufsiz = $sock->sockopt(Socket::SO_RCVBUF)
      or die "cannot get a resolver socket rx buffer size: $!";
    if ($bufsiz >= 32*1024) {
      dbg("dns: resolver socket rx buffer size is %d bytes", $bufsiz);
    } else {
      $sock->sockopt(Socket::SO_RCVBUF, 32*1024)
        or die "cannot set a resolver socket rx buffer size: $!";
      $newbufsiz = $sock->sockopt(Socket::SO_RCVBUF)
        or die "cannot get a resolver socket rx buffer size: $!";
      dbg("dns: resolver socket rx buffer size changed from %d to %d bytes",
          $bufsiz, $newbufsiz);
    }
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    info("dns: socket buffer size error: $eval_stat");
  };

  $self->{sock} = $sock;
  $self->{sock_as_vec} = $self->fhs_to_vec($self->{sock});
  return;

no_sock:
  $self->{no_resolver} = 1;
}

sub connect_sock_if_reqd {
  my ($self) = @_;
  $self->connect_sock() if !$self->{sock};
}

=item $res->get_sock()

Return the C<IO::Socket::INET> object used to communicate with
the nameserver.

=cut

sub get_sock {
  my ($self) = @_;
  $self->connect_sock_if_reqd();
  return $self->{sock};
}

###########################################################################

=item $packet = new_dns_packet ($host, $type, $class)

A wrapper for C<Net::DNS::Packet::new()> which traps a die thrown by it.

To use this, change calls to C<Net::DNS::Resolver::bgsend> from:

    $res->bgsend($hostname, $type);

to:

    $res->bgsend(Mail::SpamAssassin::DnsResolver::new_dns_packet($hostname, $type, $class));

=cut

sub new_dns_packet {
  my ($self, $host, $type, $class) = @_;

  return if $self->{no_resolver};

  # construct a PTR query if it looks like an IPv4 address
  if ((!defined($type) || $type eq 'PTR') && $host =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
    $host = "$4.$3.$2.$1.in-addr.arpa.";
    $type = 'PTR';
  }

  $self->connect_sock_if_reqd();
  my $packet;
  eval {
    $packet = Net::DNS::Packet->new($host, $type, $class);

    # a bit noisy, so commented by default...
    #dbg("dns: new DNS packet time=%s host=%s type=%s id=%s",
    #    time, $host, $type, $packet->id);
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # this can happen if Net::DNS isn't available -- but in this
    # case this function should never be called!
    warn "dns: cannot create Net::DNS::Packet, but new_dns_packet() was called: $eval_stat";
  };

  return $packet;
}

# Internal function used only in this file
## compute an unique ID for a packet to match the query to the reply
## It must use only data that is returned unchanged by the nameserver.
## Argument is a Net::DNS::Packet that has a non-empty question section,
## return is an (opaque) string that can be used as a hash key
sub _packet_id {
  my ($self, $packet) = @_;
  my $header = $packet->header;
  my $id = $header->id;
  my @questions = $packet->question;
  my $ques = $questions[0];

  if (defined $ques) {
    # Bug 6232: Net::DNS::Packet::new is not consistent in keeping data in
    # sections of a packet either as original bytes or presentation-encoded:
    # creating a query packet as above in new_dns_packet() keeps label in
    # non-encoded form, yet on parsing an answer packet, its query section
    # is converted to presentation form by Net::DNS::Question::parse calling
    # Net::DNS::Packet::dn_expand and Net::DNS::wire2presentation in turn.
    # Let's undo the effect of the wire2presentation routine here to make
    # sure the query section of an answer packet matches the query section
    # in our packet formed by new_dns_packet():
    #
    my $qname = $ques->qname;
    $qname =~ s/\\([0-9]{3}|.)/length($1)==1 ? $1 : chr($1)/gse;
    return join '/', $id, $qname, $ques->qtype, $ques->qclass;

  } else {
    # odd.  this should not happen, but clearly some DNS servers
    # can return something that Net::DNS interprets as having no
    # question section.  Better support it; just return the
    # (safe) ID part, along with a text token indicating that
    # the packet had no question part.
    #
    return $id . "NO_QUESTION_IN_PACKET";
  }
}

###########################################################################

=item $id = $res->bgsend($host, $type, $class, $cb)

Quite similar to C<Net::DNS::Resolver::bgsend>, except that when a response
packet eventually arrives, and C<poll_responses> is called, the callback
sub reference C<$cb> will be called.

Note that C<$type> and C<$class> may be C<undef>, in which case they
will default to C<A> and C<IN>, respectively.

The callback sub will be called with three arguments -- the packet that was
delivered, and an id string that fingerprints the query packet and the expected
reply. The third argument is a timestamp (Unix time, floating point), captured
at the time the packet was collected. It is expected that a closure callback
be used, like so:

  my $id = $self->{resolver}->bgsend($host, $type, undef, sub {
        my ($reply, $reply_id, $timestamp) = @_;
        $self->got_a_reply ($reply, $reply_id);
      });

The callback can ignore the reply as an invalid packet sent to the listening
port if the reply id does not match the return value from bgsend.

=cut

sub bgsend {
  my ($self, $host, $type, $class, $cb) = @_;
  return if $self->{no_resolver};

  $self->{send_timed_out} = 0;

  my $pkt = $self->new_dns_packet($host, $type, $class);

  $self->connect_sock_if_reqd();
  if (!defined($self->{sock}->send($pkt->data, 0))) {
    warn "dns: sendto() failed: $!";
    return;
  }
  my $id = $self->_packet_id($pkt);
  dbg("dns: providing a callback for id: $id");
  $self->{id_to_callback}->{$id} = $cb;
  return $id;
}

###########################################################################

=item $nfound = $res->poll_responses()

See if there are any C<bgsend> response packets ready, and return
the number of such packets delivered to their callbacks.

=cut

sub poll_responses {
  my ($self, $timeout) = @_;
  return if $self->{no_resolver};
  return if !$self->{sock};
  my $cnt = 0;

  my $rin = $self->{sock_as_vec};
  my $rout;

  for (;;) {
    my ($nfound, $timeleft);
    { my $timer;  # collects timestamp when variable goes out of scope
      if (!defined($timeout) || $timeout > 0)
        { $timer = $self->{main}->time_method("poll_dns_idle") }
      ($nfound, $timeleft) = select($rout=$rin, undef, undef, $timeout);
    }
    if (!defined $nfound || $nfound < 0) {
      warn "dns: select failed: $!";
      return;
    }

    my $now = time;
    $timeout = 0;  # next time around collect whatever is available, then exit
    last  if $nfound == 0;

    my $packet = $self->{res}->bgread($self->{sock});
    my $err = $self->{res}->errorstring;

    if (defined $packet &&
        defined $packet->header &&
        defined $packet->question &&
        defined $packet->answer)
    {
      my $id = $self->_packet_id($packet);

      my $cb = delete $self->{id_to_callback}->{$id};
      if (!$cb) {
        dbg("dns: no callback for id: %s, ignored; packet: %s",
            $id,  $packet ? $packet->string : "undef" );
      } else {
        $cb->($packet, $id, $now);
        $cnt++;
      }
    }
    else {
      dbg("dns: no packet! err=%s packet=%s",
          $err,  $packet ? $packet->string : "undef" );
    }
  }

  return $cnt;
}

###########################################################################

=item $res->bgabort()

Call this to release pending requests from memory, when aborting backgrounded
requests, or when the scan is complete.
C<Mail::SpamAssassin::PerMsgStatus::check> calls this before returning.

=cut

sub bgabort {
  my ($self) = @_;
  $self->{id_to_callback} = {};
}

###########################################################################

=item $packet = $res->send($name, $type, $class)

Emulates C<Net::DNS::Resolver::send()>.

=cut

sub send {
  my ($self, $name, $type, $class) = @_;
  return if $self->{no_resolver};

  my $retrans = $self->{retrans};
  my $retries = $self->{retry};
  my $timeout = $retrans;
  my $answerpkt;
  my $answerpkt_avail = 0;
  for (my $i = 0;
       (($i < $retries) && !defined($answerpkt));
       ++$i, $retrans *= 2, $timeout = $retrans) {

    $timeout = 1 if ($timeout < 1);
    # note nifty use of a closure here.  I love closures ;)
    $self->bgsend($name, $type, $class, sub {
      my ($reply, $reply_id, $timestamp) = @_;
      $answerpkt = $reply; $answerpkt_avail = 1;
    });

    my $now = time;
    my $deadline = $now + $timeout;

    while (!$answerpkt_avail) {
      if ($now >= $deadline) { $self->{send_timed_out} = 1; last }
      $self->poll_responses(1);
      $now = time;
    }
  }
  return $answerpkt;
}

###########################################################################

=item $res->errorstring()

Little more than a stub for callers expecting this from C<Net::DNS::Resolver>.

If called immediately after a call to $res->send this will return
C<query timed out> if the $res->send DNS query timed out.  Otherwise 
C<unknown error or no error> will be returned.

No other errors are reported.

=cut

sub errorstring {
  my ($self) = @_;
  return 'query timed out' if $self->{send_timed_out};
  return 'unknown error or no error';
}

###########################################################################

=item $res->finish_socket()

Reset socket when done with it.

=cut

sub finish_socket {
  my ($self) = @_;
  if ($self->{sock}) {
    $self->{sock}->close()  or die "error closing socket: $!";
    delete $self->{sock};
  }
}

###########################################################################

=item $res->finish()

Clean up for destruction.

=cut

sub finish {
  my ($self) = @_;
  $self->finish_socket();
  %{$self} = ();
}

###########################################################################
# non-public methods.

# should move to Util.pm (TODO)
sub fhs_to_vec {
  my ($self, @fhlist) = @_;
  my $rin = '';
  foreach my $sock (@fhlist) {
    my $fno = fileno($sock);
    if (!defined $fno) {
      warn "dns: oops! fileno now undef for $sock";
    } else {
      vec ($rin, $fno, 1) = 1;
    }
  }
  return $rin;
}

# call Mail::SA::init() instead
sub reinit_post_fork {
  my ($self) = @_;
  # and a new socket, so we don't have 5 spamds sharing the same
  # socket
  $self->connect_sock();
}

1;

=back

=cut
