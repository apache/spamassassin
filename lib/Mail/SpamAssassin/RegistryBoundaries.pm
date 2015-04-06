# The (extremely complex) rules for domain delegation.

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

Mail::SpamAssassin::RegistryBoundaries - domain delegation rules

=cut

package Mail::SpamAssassin::RegistryBoundaries;

use strict;
use warnings;
use bytes;
use re 'taint';

our @ISA = qw();
use vars qw(%US_STATES);

# called from SpamAssassin->init() to create $self->{util_rb}
sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    'main'              => $main,
    'conf'              => $main->{conf},
  };
  bless ($self, $class);

  # Initialize valid_tlds_re for schemeless uri parsing, FreeMail etc
  if ($self->{conf}->{valid_tlds}) {
    my $tlds = join('|', keys %{$self->{conf}->{valid_tlds}});
    # Perl 5.10+ trie optimizes lists, no need for fancy regex optimizing
    $self->{valid_tlds_re} = qr/(?:$tlds)/i;
  }
  else {
    # Failsafe in case no tlds defined, we don't want this to match everything..
    $self->{valid_tlds_re} = qr/no_tlds_defined/;
  }

  $self;
}

# This is required because the .us domain is nuts. See split_domain.
foreach (qw/
  ak al ar az ca co ct dc de fl ga gu hi ia id il in ks ky la ma md me mi
  mn mo ms mt nc nd ne nh nj nm nv ny oh ok or pa pr ri sc sd tn tx ut va vi
  vt wa wi wv wy
  /) {
  $US_STATES{$_} = 1;
}

###########################################################################

=head1 METHODS

=over 4

=item ($hostname, $domain) = split_domain ($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, splitting at the DNS registry boundary.

Examples:

    "www.foo.com" => ( "www", "foo.com" )
    "www.foo.co.uk" => ( "www", "foo.co.uk" )

=cut

sub split_domain {
  my $self = shift;
  my $domain = lc shift;

  my $hostname = '';

  if (defined $domain && $domain ne '') {
    # www..spamassassin.org -> www.spamassassin.org
    $domain =~ tr/././s;

    # leading/trailing dots
    $domain =~ s/^\.+//;
    $domain =~ s/\.+$//;

    # Split scalar domain into components
    my @domparts = split(/\./, $domain);
    my @hostname;

    while (@domparts > 1) { # go until we find the TLD
      if (@domparts == 4) {
        if ($domparts[3] eq 'us' &&
            (($domparts[0] eq 'pvt' && $domparts[1] eq 'k12') ||
             ($domparts[0] =~ /^c[io]$/)))
        {
          # http://www.neustar.us/policies/docs/rfc_1480.txt
          # "Fire-Dept.CI.Los-Angeles.CA.US"
          # "<school-name>.PVT.K12.<state>.US"
          last if ($US_STATES{$domparts[2]});
        }
      }
      elsif (@domparts == 3) {
        # http://www.neustar.us/policies/docs/rfc_1480.txt
        # demon.co.uk
        # esc.edu.ar
        # [^\.]+\.${US_STATES}\.us
        if ($domparts[2] eq 'us') {
          last if ($US_STATES{$domparts[1]});
        }
        else {
          my $temp = join(".", @domparts);
          last if ($self->{conf}->{three_level_domains}{$temp});
        }
      }
      elsif (@domparts == 2) {
        # co.uk, etc.
        my $temp = join(".", @domparts);
        last if ($self->{conf}->{two_level_domains}{$temp});
      }
      push(@hostname, shift @domparts);
    }

    # Look for a sub-delegated TLD
    # use @domparts to skip trying to match on TLDs that can't possibly
    # match, but keep in mind that the hostname can be blank, so 4TLD needs 4,
    # 3TLD needs 3, 2TLD needs 2 ...
    #
    unshift @domparts, pop @hostname if @hostname;
    $domain = join(".", @domparts);
    $hostname = join(".", @hostname);
  }

  ($hostname, $domain);
}

###########################################################################

=item $domain = trim_domain($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, returning just the domain.

Examples:

    "www.foo.com" => "foo.com"
    "www.foo.co.uk" => "foo.co.uk"

=cut

sub trim_domain {
  my $self = shift;
  my $domain = shift;

  my ($host, $dom) = $self->split_domain($domain);
  return $dom;
}

###########################################################################

=item $ok = is_domain_valid($dom)

Return C<1> if the domain is valid, C<undef> otherwise.  A valid domain
(a) does not contain whitespace, (b) contains at least one dot, and (c)
uses a valid TLD or ccTLD.

=back

=cut

sub is_domain_valid {
  my $self = shift;
  my $dom = lc shift;

  # domains don't have whitespace
  return 0 if ($dom =~ /\s/);

  # ensure it ends in a known-valid TLD, and has at least 1 dot
  return 0 unless ($dom =~ /\.([^.]+)$/);
  return 0 unless ($self->{conf}->{valid_tlds}{$1});

  return 1;     # nah, it's ok.
}

#

sub uri_to_domain {
  my $self = shift;
  my $uri = lc shift;

  # Javascript is not going to help us, so return.
  return if ($uri =~ /^javascript:/);

  $uri =~ s{\#.*$}{}gs;			# drop fragment
  $uri =~ s{^[a-z]+:/{0,2}}{}gs;	# drop the protocol
  $uri =~ s{^[^/]*\@}{}gs;		# username/passwd

  # strip path and CGI params.  note: bug 4213 shows that "&" should
  # *not* be likewise stripped here -- it's permitted in hostnames by
  # some common MUAs!
  $uri =~ s{[/?].*$}{}gs;              

  $uri =~ s{:\d*$}{}gs;		# port, bug 4191: sometimes the # is missing

  # skip undecoded URIs if the encoded bits shouldn't be.
  # we'll see the decoded version as well.  see url_encode()
  return if $uri =~ /\%(?:2[1-9a-f]|[3-6][0-9a-f]|7[0-9a-e])/;

  my $host = $uri;  # unstripped/full domain name

  # keep IPs intact
  if ($uri !~ /^\d+\.\d+\.\d+\.\d+$/) { 
    # get rid of hostname part of domain, understanding delegation
    $uri = $self->trim_domain($uri);

    # ignore invalid domains
    return unless ($self->is_domain_valid($uri));
  }
  
  # $uri is now the domain only, optionally return unstripped host name
  return !wantarray ? $uri : ($uri, $host);
}

1;

