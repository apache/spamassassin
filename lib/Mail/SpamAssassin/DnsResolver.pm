# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

=head1 SYNOPSIS

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

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

use IO::Socket::INET;

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
  $self->connect_sock();
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

  eval {
    require Net::DNS;
    $self->{res} = Net::DNS::Resolver->new;
    if (defined $self->{res}) {
      $self->{no_resolver} = 0;
      $self->{retry} = 1;               # retries for non-nackgrounded search
      $self->{retrans} = 3;   # initial timeout for "non-backgrounded" search run in background
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
  };   #  or warn "dns: eval failed: $@ $!\n";

  dbg("dns: is Net::DNS::Resolver available? " .
       ($self->{no_resolver} ? "no" : "yes"));
  if (!$self->{no_resolver} && defined $Net::DNS::VERSION) {
    dbg("dns: Net::DNS version: ".$Net::DNS::VERSION);
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

Wrapper for Net::DNS::Reslolver->nameservers to get or set list of nameservers

=cut

sub nameservers {
  my $self = shift;
  my $res = $self->{res};
  return $res->nameservers(@_) if $res;
}

=item $res->connect_sock()

Re-connect to the first nameserver listed in C</etc/resolv.conf> or similar
platform-dependent source, as provided by C<Net::DNS>.

=cut

sub connect_sock {
  my ($self) = @_;

  return if $self->{no_resolver};

  $self->{sock}->close() if $self->{sock};
  $self->{sock} = IO::Socket::INET->new (
    Proto => 'udp',
    Type => SOCK_DGRAM,
  );

  $self->{dest} = sockaddr_in($self->{res}->{port},
            inet_aton($self->{res}->{nameservers}[0]));

  $self->{sock_as_vec} = $self->fhs_to_vec($self->{sock});
}

=item $res->get_sock()

Return the C<IO::Socket::INET> object used to communicate with
the nameserver.

=cut

sub get_sock {
  my ($self) = @_;
  return $self->{sock};
}

###########################################################################

=item $packet = new_dns_packet ($host, $type, $class)

A wrapper for C<Net::DNS::Packet::new()> which ensures that the
packet's ID field uses a new, unique value for this process.
This is to avoid SpamAssassin bug 3997.

To use this, change calls to C<Net::DNS::Resolver::bgsend> from:

    $res->bgsend($hostname, $type);

to:

    $res->bgsend(Mail::SpamAssassin::DnsResolver::new_dns_packet($hostname, $type, $class));

This documentation should be more specific about usage of $type and $class.

=cut

sub new_dns_packet {
  my ($self, $host, $type, $class) = @_;

  return if $self->{no_resolver};

  my $packet;
  eval {
    $packet = Net::DNS::Packet->new($host, $type, $class);

    # a bit noisy, so commented by default...
    #dbg("dns: new DNS packet time=".time()." host=$host type=$type id=".$packet->id);
  };

  if ($@) {
    # this can happen if Net::DNS isn't available -- but in this
    # case this function should never be called!
    warn "dns: cannot create Net::DNS::Packet, but new_dns_packet() was called: $@ $!";
  }
  return $packet;
}

###########################################################################

=item $id = $res->bgsend($host, $type, $class, $cb)

Quite similar to C<Net::DNS::Resolver::bgsend>, except that when a response
packet eventually arrives, and C<poll_responses> is called, the callback
sub reference C<$cb> will be called.

Note that C<$type> and C<$class> may be C<undef>, in which case they
will default to C<A> and C<IN>, respectively.

The callback sub will be called with one argument -- the packet that was
delivered.  It is expected that a closure callback be used, like so:

  my $pkt = $self->{resolver}->bgsend($host, $type, undef, sub {
        my $reply = shift;
        $self->got_a_reply ($reply);
      });

=cut

sub bgsend {
  my ($self, $host, $type, $class, $cb) = @_;
  return if $self->{no_resolver};

  my $pkt = $self->new_dns_packet($host, $type, $class);

  my $id = $pkt->header->id;
  my $data = $pkt->data;
  my $dest = $self->{dest};
  $self->connect_sock() if !$self->{sock};
  if (!$self->{sock}->send ($pkt->data, 0, $self->{dest})) {
    warn "dns: sendto() failed: $@";
    return;
  }

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

  my $rin = $self->{sock_as_vec};
  my $rout;
  my ($nfound, $timeleft) = select($rout=$rin, undef, undef, $timeout);

  if (!defined $nfound || $nfound < 0) {
    warn "dns: select failed: $!";
    return;
  }

  if ($nfound == 0) {
    return 0;           # nothing's ready yet
  }

  my $packet = $self->{res}->bgread($self->{sock});
  my $err = $self->{res}->errorstring;

  if (defined $packet &&
      defined $packet->header &&
      defined $packet->question &&
      defined $packet->answer)
  {
    my $header = $packet->header;
    my $id = $header->id;

    # dbg("dns: reply id=$id");

    my $cb = delete $self->{id_to_callback}->{$id};
    if (!$cb) {
      dbg("dns: no callback for id number: $id, ignored; packet: ".
                                $packet->string);
      return 0;
    }

    $cb->($packet);
    return 1;
  }
  else {
    dbg("dns: no packet! err=$err packet=".$packet->string);
  }

  return 0;
}

###########################################################################

=item $packet = $res->search($name, $type, $class)

Emulates C<Net::DNS::Resolver::search()>.

=cut

sub search {
  my ($self, $name, $type, $class) = @_;
  return if $self->{no_resolver};

  my $retrans = $self->{retrans};
  my $retries = $self->{retry};
  my $timeout = $retrans;
  my $answerpkt;
  for (my $i = 0;
       (($i < $retries) && !defined($answerpkt));
       ++$i, $retrans *= 2, $timeout = $retrans) {

    $timeout = 1 if ($timeout < 1);
    # note nifty use of a closure here.  I love closures ;)
    $self->bgsend($name, $type, $class, sub {
      $answerpkt = shift;
    });

    my $now = time;
    my $deadline = $now + $timeout;

    while (($now < $deadline) && (!defined($answerpkt))) {
      $self->poll_responses(1);
      $now = time;
    }
  }
  return $answerpkt;
}

###########################################################################

=item $res->finish_socket()

Reset socket when done with it.

=cut

sub finish_socket {
  my ($self) = @_;
  if ($self->{sock}) {
    $self->{sock}->close();
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
  if (!$self->{no_resolver}) {
    delete $self->{res};
  }
  delete $self->{main};
}

###########################################################################
# non-public methods.

# should move to Util.pm (TODO)
sub fhs_to_vec {
  my ($self, @fhlist) = @_;
  my $rin = '';
  foreach my $sock (@fhlist) {
    my $fno = fileno($sock);
    warn "dns: oops! fileno now undef for $sock" unless defined($fno);
    vec ($rin, $fno, 1) = 1;
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
