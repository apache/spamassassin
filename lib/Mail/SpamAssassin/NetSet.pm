# Mail::SpamAssassin::NetSet - object to manipulate CIDR net IP addrs
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

package Mail::SpamAssassin::NetSet;

use strict;
use warnings;
use bytes;
use re 'taint';
use Time::HiRes qw(time);
use NetAddr::IP 4.000;

use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;

use vars qw{
  @ISA $TESTCODE $NUMTESTS $have_patricia
};

BEGIN {
  eval {
    require Net::Patricia;
    Net::Patricia->VERSION(1.16);  # need AF_INET6 support
    import Net::Patricia;
    $have_patricia = 1;
  };
}

###########################################################################

sub new {
  my ($class,$netset_name) = @_;
  $class = ref($class) || $class;

  $netset_name = ''  if !defined $netset_name;  # object name for debugging
  my $self = {
    name => $netset_name, num_nets => 0,
    cache_hits => 0, cache_attempts => 0,
  };
  $self->{pt} = Net::Patricia->new(&AF_INET6)  if $have_patricia;

  bless $self, $class;
  $self;
}

###########################################################################

sub DESTROY {
  my($self) = shift;
  if (exists $self->{cache}) {
    local($@, $!, $_);  # protect outer layers from a potential surprise
    my($hits, $attempts) = ($self->{cache_hits}, $self->{cache_attempts});
    dbg("netset: cache %s hits/attempts: %d/%d, %.1f %%",
        $self->{name}, $hits, $attempts, 100*$hits/$attempts) if $attempts > 0;
  }
}

###########################################################################

sub add_cidr {
  my ($self, @nets) = @_;

  $self->{nets} ||= [ ];
  my $numadded = 0;
  delete $self->{cache};  # invalidate cache (in case of late additions)

  foreach my $cidr_orig (@nets) {
    my $cidr = $cidr_orig;  # leave original unchanged, useful for logging

    # recognizes syntax:
    #   [IPaddr%scope]/len or IPaddr%scope/len or IPv4addr/mask
    # optionally prefixed by a '!' to indicate negation (exclusion);
    # the %scope (i.e. interface), /len or /mask are optional

    local($1,$2,$3,$4);
    $cidr =~ s/^\s+//;
    my $exclude = ($cidr =~ s/^!\s*//) ? 1 : 0;

    my $masklen;  # netmask or a prefix length
    $masklen = $1  if $cidr =~ s{ / (.*) \z }{}xs;

    # discard optional brackets
    $cidr = $1  if $cidr =~ /^ \[ ( [^\]]* ) \] \z/xs;

    my $scope;
    # IPv6 Scoped Address (RFC 4007, RFC 6874, RFC 3986 "unreserved" charset)
    if ($cidr =~ s/ % ( [A-Z0-9._~-]* ) \z //xsi) {  # scope <zone_id> ?
      $scope = $1;  # interface specification
      # discard interface specification, currently just ignored
      info("netset: ignoring interface scope '%%%s' in IP address %s",
           $scope, $cidr_orig);
    }

    my $is_ip4 = 0;
    if ($cidr =~ /^ \d+ (\. | \z) /x) {  # looks like an IPv4 address
      if ($cidr =~ /^ (\d+) \. (\d+) \. (\d+) \. (\d+) \z/x) {
        # also strips leading zeroes, not liked by inet_pton
        $cidr = sprintf('%d.%d.%d.%d', $1,$2,$3,$4);
        $masklen = 32  if !defined $masklen;
      } elsif ($cidr =~ /^ (\d+) \. (\d+) \. (\d+) \.? \z/x) {
        $cidr = sprintf('%d.%d.%d.0', $1,$2,$3);
        $masklen = 24  if !defined $masklen;
      } elsif ($cidr =~ /^ (\d+) \. (\d+) \.? \z/x) {
        $cidr = sprintf('%d.%d.0.0', $1,$2);
        $masklen = 16  if !defined $masklen;
      } elsif ($cidr =~ /^ (\d+) \.? \z/x) {
        $cidr = sprintf('%d.0.0.0', $1);
        $masklen = 8  if !defined $masklen;
      } else {
        warn "netset: illegal IPv4 address given: '$cidr_orig'\n";
        next;
      }
      $is_ip4 = 1;
    }

    if ($self->{pt}) {
      if (defined $masklen) {
        $masklen =~ /^\d{1,3}\z/
          or die "Network mask not supported, use a CIDR syntax: '$cidr_orig'";
      }
      my $key = $cidr;
      my $prefix_len = $masklen;
      if ($is_ip4) {
        $key = '::ffff:' . $key;  # turn it into an IPv4-mapped IPv6 addresses
        $prefix_len += 96  if defined $prefix_len;
      }
      $prefix_len = 128  if !defined $prefix_len;
      $key .= '/' . $prefix_len;
    # dbg("netset: add_cidr (patricia trie) %s => %s",
    #     $cidr_orig, $exclude ? '!'.$key : $key);
      defined eval {
        $self->{pt}->add_string($key, $exclude ? '!'.$key : $key)
      } or warn "netset: illegal IP address given (patricia trie): ".
                "'$key': $@\n";
    }

    $cidr .= '/' . $masklen  if defined $masklen;

    my $ip = NetAddr::IP->new($cidr);
    if (!defined $ip) {
      warn "netset: illegal IP address given: '$cidr_orig'\n";
      next;
    }
  # dbg("netset: add_cidr %s => %s => %s", $cidr_orig, $cidr, $ip);

    # if this is an IPv4 address, create an IPv6 representation, too
    my ($ip4, $ip6);
    if ($is_ip4) {
      $ip4 = $ip;
      $ip6 = $self->_convert_ipv4_cidr_to_ipv6($cidr);
    } else {
      $ip6 = $ip;
    }

    # bug 5931: this is O(n^2).  bad if there are lots of nets. There are  good
    # reasons to keep it for linting purposes, though, so don't start skipping
    # it until we have over 200 nets in our list
    if (scalar @{$self->{nets}} < 200) {
      next if ($self->is_net_declared($ip4, $ip6, $exclude, 0));
    }

    # note: it appears a NetAddr::IP object takes up about 279 bytes
    push @{$self->{nets}}, {
      exclude => $exclude,
      ip4     => $ip4,
      ip6     => $ip6,
      as_string => $cidr_orig,
    };
    $numadded++;
  }

  $self->{num_nets} += $numadded;
  $numadded;
}

sub get_num_nets {
  my ($self) = @_;
  return $self->{num_nets};
}

sub _convert_ipv4_cidr_to_ipv6 {
  my ($self, $cidr) = @_;

  # only do this for IPv4 addresses
  return unless $cidr =~ /^\d+[.\/]/;

  if ($cidr !~ /\//) {      # no mask
    return NetAddr::IP->new6("::ffff:".$cidr);
  }

  # else we have a CIDR mask specified. use new6() to do this
  #
  my $ip6 = ""+(NetAddr::IP->new6($cidr));
  # 127.0.0.1 -> 0:0:0:0:0:0:7F00:0001/128
  # 127/8 -> 0:0:0:0:0:0:7F00:0/104

  # now, move that from 0:0:0:0:0:0: space to 0:0:0:0:0:ffff: space
  if (!defined $ip6 || $ip6 !~ /^0:0:0:0:0:0:(.*)$/) {
    warn "oops! unparseable IPv6 address for $cidr: $ip6";
    return;
  }

  return NetAddr::IP->new6("::ffff:$1");
}

sub _nets_contains_network {
  my ($self, $net4, $net6, $exclude, $quiet, $netname, $declared) = @_;

  return 0 unless (defined $self->{nets});

  foreach my $net (@{$self->{nets}}) {
    # check to see if the new network is contained by the old network
    my $in4 = defined $net4 && defined $net->{ip4} && $net->{ip4}->contains($net4);
    my $in6 = defined $net6 && defined $net->{ip6} && $net->{ip6}->contains($net6);
    if ($in4 || $in6) {
      warn sprintf("netset: cannot %s %s as it has already been %s\n",
                   $exclude ? "exclude" : "include",
                   $netname,
                   $net->{exclude} ? "excluded" : "included") unless $quiet;
      # a network that matches an excluded network isn't contained by "nets"
      # return 0 if we're not just looking to see if the network was declared
      return 0 if (!$declared && $net->{exclude});
      return 1;
    }
  }
  return 0;
}

sub is_net_declared {
  my ($self, $net4, $net6, $exclude, $quiet) = @_;
  return $self->_nets_contains_network($net4, $net6, $exclude,
                $quiet, $net4 || $net6, 1);
}

sub contains_ip {
  my ($self, $ip) = @_;
  my $result = 0;

  if (!$self->{num_nets}) { return 0 }

  $self->{cache_attempts}++;
  if ($self->{cache} && exists $self->{cache}{$ip}) {
    dbg("netset: %s cached lookup on %s, %d networks, result: %s",
        $self->{name}, $ip, $self->{num_nets}, $self->{cache}{$ip});
    $self->{cache_hits}++;
    return $self->{cache}{$ip};

  } elsif ($self->{pt}) {
    # do a quick lookup on a Patricia Trie
    my $t0 = time;
    local($1,$2,$3,$4); local $_ = $ip;
    $_ = $1  if /^ \[ ( [^\]]* ) \] \z/xs;  # discard optional brackets
    s/%[A-Z0-9:._-]+\z//si;  # discard interface specification
    if (m{^ (\d+) \. (\d+) \. (\d+) \. (\d+) \z}x) {
      $_ = sprintf('::ffff:%d.%d.%d.%d', $1,$2,$3,$4);
    } else {
      s/^IPv6://si;  # discard optional 'IPv6:' prefix
    }
    eval { $result = $self->{pt}->match_string($_); 1 }  or undef $result;
    $result = defined $result && $result !~ /^!/ ? 1 : 0;
    dbg("netset: %s patricia lookup on %s, %d networks, result: %s, %.3f ms",
         $self->{name}, $ip, $self->{num_nets}, $result, 1000*(time - $t0));
  } else {
    # do a sequential search on a list of NetAddr::IP objects
    my $t0 = time;
    my ($ip4, $ip6);
    if ($ip =~ /^\d+\./) {
      $ip4 = NetAddr::IP->new($ip);
      $ip6 = $self->_convert_ipv4_cidr_to_ipv6($ip);
    } else {
      $ip6 = NetAddr::IP->new($ip);
    }
    foreach my $net (@{$self->{nets}}) {
      if ((defined $ip4 && defined $net->{ip4} && $net->{ip4}->contains($ip4))
       || (defined $ip6 && defined $net->{ip6} && $net->{ip6}->contains($ip6))){
        $result = !$net->{exclude};
        last;
      }
    }
    dbg("netset: %s lookup on %s, %d networks, result: %s, %.3f ms",
         $self->{name}, $ip, $self->{num_nets}, $result, 1000*(time - $t0));
  }

  $self->{cache}{$ip} = $result;
  return $result;
}

sub contains_net {
  my ($self, $net) = @_;
  my $exclude = $net->{exclude};
  my $net4 = $net->{ip4};
  my $net6 = $net->{ip6};
  return $self->_nets_contains_network($net4, $net6, $exclude, 1, "", 0);
}

sub ditch_cache {
  my ($self) = @_;
  if (exists $self->{cache}) {
    dbg("netset: ditch cache on %s", $self->{name});
    delete $self->{cache};
  }
}

sub clone {
  my ($self) = @_;
  my $dup = Mail::SpamAssassin::NetSet->new($self->{name});
  if ($self->{nets}) {
    @{$dup->{nets}} = @{$self->{nets}};
  }
  if ($self->{pt}) {
    my $dup_pt = $dup->{pt};
    $self->{pt}->climb(sub {
      my $key = $_[0]; $key =~ s/^!//;
      defined eval { $dup_pt->add_string($key, $_[0]) }
        or die "Adding a network $_[0] to a patricia trie failed: $@";
      1;
    });
  }
  $dup->{num_nets} = $self->{num_nets};
  return $dup;
}

###########################################################################

1;
