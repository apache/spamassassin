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
# use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(untaint_var decode_dns_question_entry
                                idn_to_ascii reverse_ip_address
                                domain_to_search_list);

use Socket;
use Errno qw(EADDRINUSE EACCES);
use Time::HiRes qw(time);
use version 0.77;

our @ISA = qw();

our $have_net_dns;
our $io_socket_module_name;
BEGIN {
  $have_net_dns = eval { require Net::DNS; };
  if (eval { require IO::Socket::IP }) {
    $io_socket_module_name = 'IO::Socket::IP';
  } elsif (eval { require IO::Socket::INET6 }) {
    $io_socket_module_name = 'IO::Socket::INET6';
  } elsif (eval { require IO::Socket::INET }) {
    $io_socket_module_name = 'IO::Socket::INET';
  }
}

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

  $self;
}

###########################################################################

=item $res-E<gt>load_resolver()

Load the C<Net::DNS::Resolver> object.  Returns 0 if Net::DNS cannot be used,
1 if it is available.

=cut

sub load_resolver {
  my ($self) = @_;

  return 0 if $self->{no_resolver};
  return 1 if $self->{res};

  # force only ipv4 if no IO::Socket::INET6 or ipv6 doesn't work
  my $force_ipv4 = $self->{main}->{force_ipv4};
  my $force_ipv6 = $self->{main}->{force_ipv6};

  if (!$force_ipv4 && $io_socket_module_name eq 'IO::Socket::INET') {
    dbg("dns: socket module for IPv6 support not available");
    die "Use of IPv6 requested, but not available\n"  if $force_ipv6;
    $force_ipv4 = 1; $force_ipv6 = 0;
  }
  if (!$force_ipv4) {  # test drive IPv6
    eval {
      my $sock6;
      if ($io_socket_module_name) {
        $sock6 = $io_socket_module_name->new(LocalAddr=>'::', Proto=>'udp');
      }
      if ($sock6) { $sock6->close() or warn "dns: error closing socket: $!\n" }
      $sock6;
    } or do {
      dbg("dns: socket module %s is available, but no host support for IPv6",
          $io_socket_module_name);
      die "Use of IPv6 requested, but not available\n"  if $force_ipv6;
      $force_ipv4 = 1; $force_ipv6 = 0;
    }
  }
  
  eval {
    die "Net::DNS required\n" if !$have_net_dns;
    die "Net::DNS 0.69 required\n"
      if (version->parse(Net::DNS->VERSION) < version->parse(0.69));
    # force_v4 is set in new() to avoid error in older versions of Net::DNS
    # that don't have it; other options are set by function calls so a typo
    # or API change will cause an error here
    my $res = $self->{res} = Net::DNS::Resolver->new(force_v4 => $force_ipv4);
    if ($res) {
      $self->{force_ipv4} = $force_ipv4;
      $self->{force_ipv6} = $force_ipv6;
      $self->{retry} = 1;       # retries for non-backgrounded query
      $self->{retrans} = 3;     # initial timeout for "non-backgrounded"
                                #   query run in background

      $res->retry(1);           # If it fails, it fails
      $res->retrans(0);         # If it fails, it fails
      $res->dnsrch(0);          # ignore domain search-list
      $res->defnames(0);        # don't append stuff to end of query
      $res->tcp_timeout(3);     # timeout of 3 seconds only
      $res->udp_timeout(3);     # timeout of 3 seconds only
      $res->persistent_tcp(0);  # bug 3997
      $res->persistent_udp(0);  # bug 3997

      # RFC 6891 (ex RFC 2671): EDNS0, value is a requestor's UDP payload size
      my $edns = $self->{conf}->{dns_options}->{edns};
      if ($edns && $edns > 512) {
        $res->udppacketsize($edns);
        dbg("dns: EDNS, UDP payload size %d", $edns);
      }

      # set $res->nameservers for the benefit of plugins which don't use
      # our send/bgsend infrastructure but rely on Net::DNS::Resolver entirely
      my @ns_addr_port = $self->available_nameservers();
      local($1,$2);
      # drop port numbers, Net::DNS::Resolver can't take them
      @ns_addr_port = map(/^\[(.*)\]:(\d+)\z/ ? $1 : $_, @ns_addr_port);
      dbg("dns: nameservers set to %s", join(', ', @ns_addr_port));
      $res->nameservers(@ns_addr_port);
    }
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn("dns: resolver create failed: $eval_stat\n");
  };

  dbg("dns: using socket module: %s version %s%s",
      $io_socket_module_name,
      $io_socket_module_name->VERSION,
      $self->{force_ipv4} ? ', forced IPv4' :
      $self->{force_ipv6} ? ', forced IPv6' : '');
  dbg("dns: is Net::DNS::Resolver available? %s",
      $self->{res} ? "yes" : "no" );
  if ($self->{res} && defined $Net::DNS::VERSION) {
    dbg("dns: Net::DNS version: %s", $Net::DNS::VERSION);
  }

  $self->{no_resolver} = !$self->{res};
  return defined $self->{res};
}

=item $resolver = $res-E<gt>get_resolver()

Return the C<Net::DNS::Resolver> object.

=cut

sub get_resolver {
  my ($self) = @_;
  return $self->{res};
}

=item $res-E<gt>configured_nameservers()

Get a list of nameservers as configured by dns_server directives
or as provided by Net::DNS, typically from /etc/resolv.conf

=cut

sub configured_nameservers {
  my $self = shift;

  my $res = $self->{res};
  my @ns_addr_port;  # list of name servers: [addr]:port entries
  if ($self->{conf}->{dns_servers}) {  # specified in a config file
    @ns_addr_port = @{$self->{conf}->{dns_servers}};
    dbg("dns: servers set by config to: %s", join(', ',@ns_addr_port));
  } elsif ($res) {  # default as provided by Net::DNS, e.g. /etc/resolv.conf
    my @ns = $res->UNIVERSAL::can('nameservers') ? $res->nameservers
                                                 : @{$res->{nameservers}};
    my $port = $res->UNIVERSAL::can('port') ? $res->port : $res->{port};
    @ns_addr_port = map(untaint_var("[$_]:" . $port), @ns);
    dbg("dns: servers obtained from Net::DNS : %s", join(', ',@ns_addr_port));
  }
  return @ns_addr_port;
}

=item $res-E<gt>available_nameservers()

Get or set a list of currently available nameservers,
which is typically a known-to-be-good subset of configured nameservers

=cut

sub available_nameservers {
  my $self = shift;

  if (@_) {
    $self->{available_dns_servers} = [ @_ ];  # copy
    dbg("dns: servers set by a caller to: %s",
         join(', ',@{$self->{available_dns_servers}}));
  } elsif (!$self->{available_dns_servers}) {
    # a list of configured name servers: [addr]:port entries
    $self->{available_dns_servers} = [ $self->configured_nameservers() ];
  }
  if ($self->{force_ipv4} || $self->{force_ipv6}) {
    # filter the list according to a chosen protocol family
    my(@filtered_addr_port);
    for (@{$self->{available_dns_servers}}) {
      local($1,$2);
      /^ \[ (.*) \] : (\d+) \z/xs  or next;
      my($addr,$port) = ($1,$2);
      if ($addr =~ IS_IPV4_ADDRESS) {
        push(@filtered_addr_port, $_)  unless $self->{force_ipv6};
      } elsif ($addr =~ /:.*:/) {
        push(@filtered_addr_port, $_)  unless $self->{force_ipv4};
      } else {
        warn "dns: Unrecognized DNS server specification: $_\n";
      }
    }
    if (@filtered_addr_port < @{$self->{available_dns_servers}}) {
      dbg("dns: filtered DNS servers according to protocol family: %s",
          join(", ",@filtered_addr_port));
    }
    @{$self->{available_dns_servers}} = @filtered_addr_port;
  }
  die "available_nameservers: No DNS servers available!\n"
    if !@{$self->{available_dns_servers}};
  return @{$self->{available_dns_servers}};
}

sub disable_available_port {
  my($self, $lport) = @_;
  if ($lport >= 0 && $lport <= 65535) {
    my $conf = $self->{conf};
    if (!defined $conf->{dns_available_portscount}) {
      $self->pick_random_available_port();  # initialize
    }
    if (vec($conf->{dns_available_ports_bitset}, $lport, 1)) {
      dbg("dns: disabling local port %d", $lport);
      vec($conf->{dns_available_ports_bitset}, $lport, 1) = 0;
      $conf->{dns_available_portscount_buckets}->[$lport >> 8] --;
      $conf->{dns_available_portscount} --;
    }
  }
}

sub pick_random_available_port {
  my $self = shift;
  my $port_number;  # resulting port number, or undef if none available

  my $conf = $self->{conf};
  my $available_portscount = $conf->{dns_available_portscount};

  # initialize when called for the first time or after a config change
  if (!defined $available_portscount) {
    my $ports_bitset = $conf->{dns_available_ports_bitset};
    if (!defined $ports_bitset) {  # ensure it is initialized
      Mail::SpamAssassin::Conf::set_ports_range(\$ports_bitset, 0, 0, 0);
      $conf->{dns_available_ports_bitset} = $ports_bitset;
    }
    # prepare auxiliary data structure to speed up further free-port lookups;
    # 256 buckets, each accounting for 256 ports: 8+8 = 16 bit port numbers;
    # each bucket holds a count of available ports in its range
    my @bucket_counts = (0) x 256;
    my $all_zeroes = "\000" x 32;  # one bucket's worth (256) of zeroes
    my $all_ones   = "\377" x 32;  # one bucket's worth (256) of ones
    my $ind = 0;
    $available_portscount = 0;  # number of all available ports
    foreach my $bucket (0..255) {
      my $cnt = 0;
      my $b = substr($ports_bitset, $bucket*32, 32);  # one bucket: 256 bits
      if  ($b eq $all_zeroes) { $ind += 256 }
      elsif ($b eq $all_ones) { $ind += 256; $cnt += 256 }
      else {  # count nontrivial cases the slow way
        vec($ports_bitset, $ind++, 1) && $cnt++  for 0..255;
      }
      $available_portscount += $cnt;
      $bucket_counts[$bucket] = $cnt;
    }
    $conf->{dns_available_portscount} = $available_portscount;
    if ($available_portscount) {
      $conf->{dns_available_portscount_buckets} = \@bucket_counts;
    } else {  # save some storage
      $conf->{dns_available_portscount_buckets} = undef;
      $conf->{dns_available_ports_bitset} = '';
    }
  }

  # find the n-th port number from the ordered set of available port numbers
  dbg("dns: %d configured local ports for DNS queries", $available_portscount);
  if ($available_portscount > 0) {
    my $ports_bitset = $conf->{dns_available_ports_bitset};
    my $n = int(rand($available_portscount));
    my $bucket_counts_ref = $conf->{dns_available_portscount_buckets};
    my $ind = 0;
    foreach my $bucket (0..255) {
      # find the bucket containing n-th turned-on bit
      my $cnt = $bucket_counts_ref->[$bucket];
      if ($cnt > $n) { last } else { $n -= $cnt; $ind += 256 }
    }
    while ($ind <= 65535) {  # scans one bucket, runs at most 256 iterations
      # find the n-th turned-on bit within the corresponding bucket
      if (vec($ports_bitset, $ind, 1)) {
        if ($n <= 0) { $port_number = $ind; last } else { $n-- }
      }
      $ind++;
    }
  }
  return $port_number;
}

=item $res-E<gt>connect_sock()

Re-connect to the first nameserver listed in C</etc/resolv.conf> or similar
platform-dependent source, as provided by C<Net::DNS>.

=cut

sub connect_sock {
  my ($self) = @_;

  dbg("dns: connect_sock, resolver: %s", $self->{no_resolver} ? "no" : "yes");
  return if $self->{no_resolver};

  $io_socket_module_name
    or die "No Perl modules for network socket available";

  if ($self->{sock}) {
    $self->{sock}->close()
      or info("dns: connect_sock: error closing socket %s: %s", $self->{sock}, $!);
    $self->{sock} = undef;
  }
  my $sock;
  my $errno;

  # list of name servers: [addr]:port entries
  my @ns_addr_port = $self->available_nameservers();
  # use the first name server in a list
  my($ns_addr,$ns_port); local($1,$2);
  ($ns_addr,$ns_port) = ($1,$2)  if $ns_addr_port[0] =~ /^\[(.*)\]:(\d+)\z/;

  # Ensure families of src and dest addresses match (bug 4412 comment 29).
  # Older IO::Socket::INET6 may choose a wrong LocalAddr if protocol family
  # is unspecified, causing EINVAL failure when automatically assigned local
  # IP address and a remote address do not belong to the same address family.
  # Let's choose a suitable source address if possible.
  my $srcaddr;
  if ($self->{force_ipv4}) {
    $srcaddr = "0.0.0.0";
  } elsif ($self->{force_ipv6}) {
    $srcaddr = "::";
  } elsif ($ns_addr =~ IS_IPV4_ADDRESS) {
    $srcaddr = "0.0.0.0";
  } elsif ($ns_addr =~ /:.*:/) {
    $srcaddr = "::";
  } else {  # unrecognized
    # unspecified address, unspecified protocol family
  }

  # find a free local random port from a set of declared-to-be-available ports
  my $lport;
  my $attempts = 0;
  for (;;) {
    $attempts++;
    $lport = $self->pick_random_available_port();
    if (!defined $lport) {
      $lport = 0;
      dbg("dns: no configured local ports for DNS queries, letting OS choose");
    }
    if ($attempts+1 > 50) {  # sanity check
      warn "dns: could not create a DNS resolver socket in $attempts attempts\n";
      $errno = 0;
      last;
    }
    dbg("dns: LocalAddr: [%s]:%d, name server: [%s]:%d, module %s",
        $srcaddr||'x', $lport,  $ns_addr, $ns_port,  $io_socket_module_name);
    my %args = (
        PeerAddr => $ns_addr,
        PeerPort => $ns_port,
        LocalAddr => $srcaddr,
        LocalPort => $lport,
        Type => SOCK_DGRAM,
        Proto => 'udp',
    );
    $sock = $io_socket_module_name->new(%args);

    last if $sock;  # ok, got it

    # IO::Socket::IP constructor provides full error messages in $@
    $errno = $io_socket_module_name eq 'IO::Socket::IP' ? $@ : $!;

    if ($! == EADDRINUSE || $! == EACCES) {
      # in use, let's try another source port
      dbg("dns: UDP port $lport already in use, trying another port");
      if ($self->{conf}->{dns_available_portscount} > 100) {  # still abundant
        $self->disable_available_port($lport);
      }
    } else {
      warn "dns: error creating a DNS resolver socket: $errno";
      goto no_sock;
    }
  }
  if (!$sock) {
    warn "dns: could not create a DNS resolver socket in $attempts attempts: $errno\n";
    goto no_sock;
  }

  eval {
    my($bufsiz,$newbufsiz);
    $bufsiz = $sock->sockopt(Socket::SO_RCVBUF)
      or die "cannot get a resolver socket rx buffer size: $!";
    if ($bufsiz >= 32*1024) {
      dbg("dns: resolver socket rx buffer size is %d bytes, local port %d",
           $bufsiz, $lport);
    } else {
      $sock->sockopt(Socket::SO_RCVBUF, 32*1024)
        or die "cannot set a resolver socket rx buffer size: $!";
      $newbufsiz = $sock->sockopt(Socket::SO_RCVBUF)
        or die "cannot get a resolver socket rx buffer size: $!";
      dbg("dns: resolver socket rx buffer size changed from %d to %d bytes, ".
          "local port %d", $bufsiz, $newbufsiz, $lport);
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
  undef $self->{sock};
  undef $self->{sock_as_vec};
}

sub connect_sock_if_reqd {
  my ($self) = @_;
  $self->connect_sock() if !$self->{sock};
}

=item $res-E<gt>get_sock()

Return the C<IO::Socket::INET> object used to communicate with
the nameserver.

=cut

sub get_sock {
  my ($self) = @_;
  $self->connect_sock_if_reqd();
  return $self->{sock};
}

###########################################################################

=item $packet = new_dns_packet ($domain, $type, $class)

A wrapper for C<Net::DNS::Packet::new()> which traps a die thrown by it.

To use this, change calls to C<Net::DNS::Resolver::bgsend> from:

    $res->bgsend($domain, $type);

to:

    $res->bgsend(Mail::SpamAssassin::DnsResolver::new_dns_packet($domain, $type, $class));

=cut

# implements draft-vixie-dnsext-dns0x20-00
#
sub dnsext_dns0x20 {
  my ($string) = @_;
  my $rnd;
  my $have_rnd_bits = 0;
  my $result = '';
  for my $ic (unpack("C*",$string)) {
    if (chr($ic) =~ /^[A-Za-z]\z/) {
      if ($have_rnd_bits < 1) {
        # only reveal few bits at a time, hiding most of the accumulator
        $rnd = int(rand(0x7fffffff)) & 0xff;  $have_rnd_bits = 8;
      }
      $ic ^= 0x20  if $rnd & 1;  # flip the 0x20 bit in name if dice says so
      $rnd = $rnd >> 1;  $have_rnd_bits--;
    }
    $result .= chr($ic);
  }
  return $result;
}

# this subroutine mimics the Net::DNS::Resolver::Base::make_query_packet()
#
sub new_dns_packet {
  my ($self, $domain, $type, $class) = @_;

  return if $self->{no_resolver};

  # construct a PTR query if it looks like an IPv4 address
  if (!defined($type) || $type eq 'PTR') {
    if ($domain =~ IS_IPV4_ADDRESS) {
      $domain = reverse_ip_address($domain).".in-addr.arpa.";
      $type = 'PTR';
    }
  }
  $type  = 'A'   if !defined $type;   # a Net::DNS::Packet default
  $class = 'IN'  if !defined $class;  # a Net::DNS::Packet default

  my $packet;
  eval {

    if (utf8::is_utf8($domain)) {  # since Perl 5.8.1
      dbg("dns: new_dns_packet: domain is utf8 flagged: %s", $domain);
    }

    $domain =~ s/\.*\z/./s;
    if (length($domain) > 255) {
      die "domain name longer than 255 bytes\n";
    } elsif ($domain !~ /^ (?: [^.]{1,63} \. )+ \z/sx) {
      if ($domain !~ /^ (?: [^.]+ \. )+ \z/sx) {
        die "a domain name contains a null label\n";
      } else {
        die "a label in a domain name is longer than 63 bytes\n";
      }
    }

    if ($self->{conf}->{dns_options}->{dns0x20}) {
      $domain = dnsext_dns0x20($domain);
    } else {
      $domain =~ tr/A-Z/a-z/;  # lowercase, limited to plain ASCII
    }

    # Net::DNS expects RFC 1035 zone format encoding even in its API, silly!
    # Since 0.68 it also assumes that domain names containing characters
    # with codes above 0177 imply that IDN translation is to be performed.
    # Protect also nonprintable characters just in case, ensuring transparency.
    $domain =~ s{ ( [\000-\037\177-\377\\] ) }
                { $1 eq '\\' ? "\\$1" : sprintf("\\%03d",ord($1)) }xgse;

    $packet = Net::DNS::Packet->new($domain, $type, $class);

    # a bit noisy, so commented by default...
    #dbg("dns: new DNS packet time=%.3f domain=%s type=%s id=%s",
    #    time, $domain, $type, $packet->id);
    1;
  } or do {
    # get here if a domain name in a query is invalid, or if a timeout signal
    # happened to be trapped by this eval, or if Net::DNS signalled an error
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # resignal if alarm went off
    die "dns: (1) $eval_stat\n"  if $eval_stat =~ /__alarm__ignore__\(.*\)/s;
    info("dns: new_dns_packet (domain=%s type=%s class=%s) failed: %s",
           $domain, $type, $class, $eval_stat);
  };

  if ($packet) {
    # RD flag needs to be set explicitly since Net::DNS 1.01, Bug 7223	
    $packet->header->rd(1);

    # my $udp_payload_size = $self->{res}->udppacketsize;
    my $udp_payload_size = $self->{conf}->{dns_options}->{edns};
    if ($udp_payload_size && $udp_payload_size > 512) {
      # dbg("dns: adding EDNS ext, UDP payload size %d", $udp_payload_size);
      if ($packet->edns->can('udpsize')) { # since Net::DNS 1.38
        $packet->edns->udpsize($udp_payload_size);
      } else {
        $packet->edns->size($udp_payload_size);
      }
    }
  }

  return $packet;
}

# Internal function used only in this file
## compute a unique ID for a packet to match the query to the reply
## It must use only data that is returned unchanged by the nameserver.
## Argument is a Net::DNS::Packet that has a non-empty question section,
## return is an (opaque) string that can be used as a hash key
sub _packet_id {
  my ($self, $packet) = @_;
  my $header = $packet->header;
  my $id = $header->id;
  my @questions = $packet->question;

  @questions <= 1
    or warn "dns: packet has multiple questions: " . $packet->string . "\n";

  if ($questions[0]) {
    # Bug 6232: Net::DNS::Packet::new is not consistent in keeping data in
    # sections of a packet either as original bytes or presentation-encoded:
    # creating a query packet as above in new_dns_packet() keeps label in
    # non-encoded form, yet on parsing an answer packet, its query section
    # is converted to presentation form by Net::DNS::Question::parse calling
    # Net::DNS::Packet::dn_expand and Net::DNS::wire2presentation in turn.
    # Let's undo the effect of the wire2presentation routine here to make
    # sure the query section of an answer packet matches the query section
    # in our packet as formed by new_dns_packet():
    #
    my($class,$type,$qname) = decode_dns_question_entry($questions[0]);
    $qname =~ tr/A-Z/a-z/  if !$self->{conf}->{dns_options}->{dns0x20};
    return join('/', $id, $class, $type, $qname);

  } else {
    # Odd, this should not happen, a DNS servers is supposed to retain
    # a question section in its reply.  There is a bug in Net::DNS 0.72
    # and earlier where a signal (e.g. a timeout alarm) during decoding
    # of a reply packet produces a seemingly valid packet object, but
    # with missing sections - see [rt.cpan.org #83451] .
    #
    # Better support it; just return the (safe) ID part, along with
    # a text token indicating that the packet had no question part.
    #
    return $id . "/NO_QUESTION_IN_PACKET";
  }
}

###########################################################################

=item $id = $res-E<gt>bgsend($domain, $type, $class, $cb)

DIRECT USE DISCOURAGED, please use bgsend_and_start_lookup in plugins.

Quite similar to C<Net::DNS::Resolver::bgsend>, except that when a reply
packet eventually arrives, and C<poll_responses> is called, the callback
sub reference C<$cb> will be called.

Note that C<$type> and C<$class> may be C<undef>, in which case they
will default to C<A> and C<IN>, respectively.

The callback sub will be called with three arguments -- the packet that was
delivered, and an id string that fingerprints the query packet and the expected
reply. The third argument is a timestamp (Unix time, floating point), captured
at the time the packet was collected. It is expected that a closure callback
be used, like so:

  my $id = $self->{resolver}->bgsend($domain, $type, undef, sub {
        my ($reply, $reply_id, $timestamp) = @_;
        $self->got_a_reply($reply, $reply_id);
      });

The callback can ignore the reply as an invalid packet sent to the listening
port if the reply id does not match the return value from bgsend.

=cut

sub bgsend {
  my ($self, $domain, $type, $class, $cb) = @_;
  return if $self->{no_resolver};

  my $dns_query_blockages = $self->{main}->{conf}->{dns_query_blocked};
  if ($dns_query_blockages) {
    my $search_list = domain_to_search_list($domain);
    foreach my $parent_domain ((@$search_list, '*')) {
      my $blocked = $dns_query_blockages->{$parent_domain};
      next if !defined $blocked; # not listed
      last if !$blocked; # allowed
      # blocked
      dbg("dns: bgsend, query $type/$domain blocked by dns_query_restriction: $parent_domain");
      return;
    }
  }

  $self->{send_timed_out} = 0;

  my $pkt = $self->new_dns_packet($domain, $type, $class);
  return if !$pkt;  # just bail out, new_dns_packet already reported a failure

  my @ns_addr_port = $self->available_nameservers();
  dbg("dns: bgsend, DNS servers: %s", join(', ',@ns_addr_port));
  my $n_servers = scalar @ns_addr_port;

  my $ok;
  for (my $attempts=1; $attempts <= $n_servers; $attempts++) {
    dbg("dns: attempt %d/%d, trying connect/sendto to %s",
        $attempts, $n_servers, $ns_addr_port[0]);
    $self->connect_sock_if_reqd();
    if ($self->{sock} && defined($self->{sock}->send($pkt->data, 0))) {
      $ok = 1; last;
    } else {  # any other DNS servers in a list to try?
      my $msg = !$self->{sock} ? "unable to connect to $ns_addr_port[0]"
                               : "sendto() to $ns_addr_port[0] failed: $!";
      $self->finish_socket();
      if ($attempts >= $n_servers) {
        warn "dns: $msg, no more alternatives\n";
        last;
      }
      # try with a next DNS server, rotate the list left
      warn "dns: $msg, failing over to $ns_addr_port[1]\n";
      push(@ns_addr_port, shift(@ns_addr_port));
      $self->available_nameservers(@ns_addr_port);
    }
  }
  return if !$ok;
  my $id = $self->_packet_id($pkt);
  dbg("dns: providing a callback for id: $id");
  $self->{id_to_callback}->{$id} = $cb;
  return $id;
}

###########################################################################

=item $id = $res-E<gt>bgread()

Similar to C<Net::DNS::Resolver::bgread>.  Reads a DNS packet from
a supplied socket, decodes it, and returns a Net::DNS::Packet object
if successful.  Dies on error.

=cut

sub bgread {
  my ($self) = @_;
  my $sock = $self->{sock};
  my $packetsize = $self->{res}->udppacketsize;
  $packetsize = 512  if $packetsize < 512;  # just in case
  my $data = '';
  my $peeraddr = $sock->recv($data, $packetsize+256);  # with some size margin for troubleshooting
  defined $peeraddr or die "bgread: recv() failed: $!";
  my $peerhost = $sock->peerhost;
  $data ne '' or die "bgread: received empty packet from $peerhost";
  dbg("dns: bgread: received %d bytes from %s", length($data), $peerhost);
  my($answerpkt, $decoded_length) = Net::DNS::Packet->new(\$data);
  $answerpkt or die "bgread: decoding DNS packet failed: $@";
  $answerpkt->answerfrom($peerhost);
  if (defined $decoded_length && $decoded_length ne "" && $decoded_length != length($data)) {
    warn sprintf("dns: bgread: received a %d bytes packet from %s, decoded %d bytes\n",
                 length($data), $peerhost, $decoded_length);
  }
  return $answerpkt;
}

###########################################################################

=item $nfound = $res-E<gt>poll_responses()

See if there are any C<bgsend> reply packets ready, and return
the number of such packets delivered to their callbacks.

=cut

sub poll_responses {
  my ($self, $timeout) = @_;
  return if $self->{no_resolver};
  return if !$self->{sock};
  my $cnt = 0;
  my $cnt_cb = 0;

  my $rin = $self->{sock_as_vec};
  my $rout;

  for (;;) {
    my ($nfound, $timeleft, $eval_stat);
    # if a restartable signal is caught, retry 3 times before aborting
    my $eintrcount = 3;
    eval {  # use eval to caught alarm signal
      my $timer;  # collects timestamp when variable goes out of scope
      if (!defined($timeout) || $timeout > 0)
        { $timer = $self->{main}->time_method("poll_dns_idle") }
      $! = 0;
      ($nfound, $timeleft) = select($rout=$rin, undef, undef, $timeout);
      1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };
    if (defined $eval_stat) {
      # most likely due to an alarm signal, resignal if so
      die "dns: (2) $eval_stat\n"  if $eval_stat =~ /__alarm__ignore__\(.*\)/s;
      warn "dns: select aborted: $eval_stat\n";
      last;
    } elsif (!defined $nfound || $nfound < 0) {
      if ($!{EINTR} and $eintrcount > 0) {
        $eintrcount--;
        next;
      }
      if ($!) { warn "dns: select failed: $!\n" }
      else    { info("dns: select interrupted") }  # shouldn't happen
      last;
    } elsif (!$nfound) {
      if (!defined $timeout) { warn("dns: select returned empty-handed\n") }
      elsif ($timeout > 0) { dbg("dns: select timed out %.3f s", $timeout) }
      last;
    }
    $cnt += $nfound;

    my $now = time;
    $timeout = 0;  # next time around collect whatever is available, then exit
    last  if $nfound == 0;

    my $packet;
    # Bug 7265, use our own bgread() below
    # $packet = $self->{res}->bgread($self->{sock});
    eval {
      $packet = $self->bgread();  # Bug 7265, use our own bgread()
    } or do {
      undef $packet;
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      # resignal if alarm went off
      die $eval_stat  if $eval_stat =~ /__alarm__ignore__\(.*\)/s;
      info("dns: bad dns reply: %s", $eval_stat);
    };

    # bug 8225 - Do TCP fallback when UDP reply packet is too long, by retrying using Net::DNS::Resolver bgsend and bgread
    my ($id, $packet_id);
    if ($packet && $packet->header) {
      my $header = $packet->header;
      $packet_id = $header->id;  # set these here in case we need to retry for TCP fallback
      $id = $self->_packet_id($packet);  # which will change $packet to a different class object
      if ($header->rcode eq 'NOERROR' && $header->tc) {
        # Use original Resolver which can handle TCP fallback, but keep id from the custom packet
        my (undef, $qclass, $qtype, $qname) = split('/', $id);
        dbg("dns: TCP fallback retry with %s, %s, %s", $qname, $qtype, $qclass);
        my $orig_resolver =  $self->{main}->{resolver}->get_resolver();
        eval {
          my $handle = $orig_resolver->bgsend($qname, $qtype, $qclass);
          $packet = $orig_resolver->bgread($handle);
        } or do {
          undef $packet;
          my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
          # resignal if alarm went off
          die $eval_stat  if $eval_stat =~ /__alarm__ignore__\(.*\)/s;
          info("dns: bad dns tcp fallback reply: %s", $eval_stat);
        };
      }
    }

    if (!$packet) {
      # error already reported above
#     my $dns_err = $self->{res}->errorstring;
#     die "dns (3) $dns_err\n"  if $dns_err =~ /__alarm__ignore__\(.*\)/s;
#     info("dns: bad dns reply: $dns_err");
    } else {
      my $header = $packet->header;
      if (!$header) {
        info("dns: dns reply is missing a header section");
      } else {
        my $rcode = $header->rcode;
        if ($rcode eq 'NOERROR') {  # success
          # NOERROR, may or may not have answer records
          dbg("dns: dns reply %s is OK, %d answer records",
              $packet_id, $header->ancount);
          if ($header->tc) {  # truncation flag turned on
            my $edns = $self->{conf}->{dns_options}->{edns} || 512;
            info("dns: reply to %s truncated (%s), %d answer records", $id,
                 $edns == 512 ? "EDNS off" : "EDNS $edns bytes",
                 $header->ancount);
          }
        } else {
          # some failure, e.g. NXDOMAIN, SERVFAIL, FORMERR, REFUSED, ...
          # btw, one reason for SERVFAIL is an RR signature failure in DNSSEC
          dbg("dns: dns reply to %s: %s", $id, $rcode);
        }

        # A hash lookup: the id must match exactly (case-sensitively).
        # The domain name part of the id was lowercased if dns0x20 is off,
        # and case-randomized when dns0x20 option is on.
        #
        my $cb = delete $self->{id_to_callback}->{$id};

        if ($cb) {
          $cb->($packet, $id, $now);
          $cnt_cb++;
        } else {  # no match, report the problem
          if ($rcode eq 'REFUSED' || $id =~ m{^\d+/NO_QUESTION_IN_PACKET\z}) {
            # the failure was already reported above
          } else {
            info("dns: no callback for id $id, ignored, packet on next debug line");
            # prevent filling normal logs with huge packet dumps
            dbg("dns: %s", $packet ? $packet->string : "undef");
          }
          # report a likely matching query for diagnostic purposes
          local $1;
          if ($id =~ m{^(\d+)/}) {
            my $dnsid = $1;  # the raw DNS packet id
            my @matches =
              grep(m{^\Q$dnsid\E/}o, keys %{$self->{id_to_callback}});
            if (!@matches) {
              info("dns: no likely matching queries for id %s", $dnsid);
            } else {
              info("dns: a likely matching query: %s", join(', ', @matches));
            }
          }
        }
      }
    }
  }

  return ($cnt, $cnt_cb);
}

use constant RECV_FLAGS => eval { MSG_DONTWAIT } || 0; # Not in Windows

# Used to flush stale DNS responses, which we don't need to process
sub flush_responses {
  my ($self) = @_;
  return if $self->{no_resolver};
  return if !$self->{sock};

  my $rin = $self->{sock_as_vec};
  my $rout;
  my $nfound;

  my $packetsize = $self->{res}->udppacketsize;
  $packetsize = 512  if $packetsize < 512;  # just in case
  $self->{sock}->blocking(0) unless(RECV_FLAGS);
  for (;;) {
    eval {  # use eval to catch alarm signal
      ($nfound, undef) = select($rout=$rin, undef, undef, 0);
      1;
    } or do {
	  last;
    };
    last if !$nfound;
    last if !$self->{sock}->recv(my $data, $packetsize+256, RECV_FLAGS);
  }
  $self->{sock}->blocking(1) unless(RECV_FLAGS);
}

###########################################################################

=item $res-E<gt>bgabort()

Call this to release pending requests from memory, when aborting backgrounded
requests, or when the scan is complete.
C<Mail::SpamAssassin::PerMsgStatus::check> calls this before returning.

=cut

sub bgabort {
  my ($self) = @_;
  $self->{id_to_callback} = {};
}

###########################################################################

=item $packet = $res-E<gt>send($name, $type, $class)

Emulates C<Net::DNS::Resolver::send()>.

This subroutine is a simple synchronous leftover from SpamAssassin version
3.3 and does not participate in packet query caching and callback grouping
as implemented by AsyncLoop::bgsend_and_start_lookup().  As such it should
be avoided for mainstream usage.  Currently used through Mail::SPF::Server
by the SPF plugin.

=cut

sub send {
  my ($self, $name, $type, $class) = @_;
  return if $self->{no_resolver};

  # Avoid passing utf8 character strings to DNS, as it has no notion of
  # character set encodings - encode characters somehow to plain bytes
  # using some arbitrary encoding (they are normally just 7-bit ascii
  # characters anyway, just need to get rid of the utf8 flag).  Bug 6959
  # Most if not all af these come from a SPF plugin.
  #   (was a call to utf8::encode($name), now we prefer a proper idn_to_ascii)
  #
  $name = idn_to_ascii($name);

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
    my $id = $self->bgsend($name, $type, $class, sub {
      my ($reply, $reply_id, $timestamp) = @_;
      $answerpkt = $reply; $answerpkt_avail = 1;
    });

    last if !defined $id;  # perhaps a restricted zone or a serious failure

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

=item $res-E<gt>errorstring()

Little more than a stub for callers expecting this from C<Net::DNS::Resolver>.

If called immediately after a call to $res-E<gt>send this will return
C<query timed out> if the $res-E<gt>send DNS query timed out.  Otherwise 
C<unknown error or no error> will be returned.

No other errors are reported.

=cut

sub errorstring {
  my ($self) = @_;
  return 'query timed out' if $self->{send_timed_out};
  return 'unknown error or no error';
}

###########################################################################

=item $res-E<gt>finish_socket()

Reset socket when done with it.

=cut

sub finish_socket {
  my ($self) = @_;
  if ($self->{sock}) {
    $self->{sock}->close()
      or warn "dns: finish_socket: error closing socket $self->{sock}: $!\n";
    undef $self->{sock};
  }
}

###########################################################################

=item $res-E<gt>finish()

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
      warn "dns: oops! fileno now undef for $sock\n";
    } else {
      vec ($rin, $fno, 1) = 1;
    }
  }
  return $rin;
}

# call Mail::SA::init() instead
sub reinit_post_fork {
  my ($self) = @_;
  # release parent's socket, don't want all spamds sharing the same socket
  $self->finish_socket();
}

1;

=back

=cut
