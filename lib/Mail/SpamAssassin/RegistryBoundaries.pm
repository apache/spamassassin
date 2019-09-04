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
# use bytes;
use re 'taint';

our @ISA = qw();

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(idn_to_ascii is_fqdn_valid);
use Mail::SpamAssassin::Constants qw(:ip);

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
  if ($self->{conf}->{valid_tlds} && %{$self->{conf}->{valid_tlds}}) {
    # International domain names are already in ASCII-compatible encoding (ACE)
    my $tlds = 
      '(?<![a-zA-Z0-9-])(?:'. # make sure tld starts at boundary
      join('|', keys %{$self->{conf}->{valid_tlds}}).
      ')(?!(?:[a-zA-Z0-9-]|\.[a-zA-Z0-9]))'; # make sure it ends
    # Perl 5.10+ trie optimizes lists, no need for fancy regex optimizing
    if (eval { $self->{valid_tlds_re} = qr/$tlds/i; 1; }) {
      dbg("config: registryboundaries: %d tlds loaded",
        scalar keys %{$self->{conf}->{valid_tlds}});
    } else {
      warn "config: registryboundaries: failed to compile valid_tlds_re: $@\n";
      $self->{valid_tlds_re} = qr/no_tlds_defined/;
    }
  }
  else {
    # Failsafe in case no tlds defined, we don't want this to match everything..
    $self->{valid_tlds_re} = qr/no_tlds_defined/;
    warn "config: registryboundaries: no tlds defined, need to run sa-update\n"
      if !$self->{main}->{ignore_site_cf_files};
  }

  $self;
}

# This is required because the .us domain is nuts. See split_domain.
our %US_STATES = qw(
  ak 1 al 1 ar 1 az 1 ca 1 co 1 ct 1 dc 1 de 1 fl 1 ga 1 gu 1 hi 1 ia 1 id 1 il 1 in 1 ks 1 ky 1 la 1 ma 1 md 1 me 1 mi 1
  mn 1 mo 1 ms 1 mt 1 nc 1 nd 1 ne 1 nh 1 nj 1 nm 1 nv 1 ny 1 oh 1 ok 1 or 1 pa 1 pr 1 ri 1 sc 1 sd 1 tn 1 tx 1 ut 1 va 1
  vi 1 vt 1 wa 1 wi 1 wv 1 wy 1
  );

###########################################################################

=head1 METHODS

=over 4

=item ($hostname, $domain) = split_domain ($fqdn, $is_ascii)

Cut a fully-qualified hostname into the hostname part and the domain
part, splitting at the DNS registry boundary.

Examples:

    "www.foo.com" => ( "www", "foo.com" )
    "www.foo.co.uk" => ( "www", "foo.co.uk" )

If $is_ascii given and true, skip idn_to_ascii() conversion

=cut

sub split_domain {
  my ($self, $domain, $is_ascii) = @_;

  if ($is_ascii) {
    utf8::encode($domain)  if utf8::is_utf8($domain); # force octets
    $domain = lc $domain;
  } else {
    # convert to ascii, handles Unicode dot normalization also
    $domain = idn_to_ascii($domain);
  }

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
      if (@domparts == 2) {
        # co.uk, etc.
        my $temp = join(".", @domparts);
        # International domain names in ASCII-compatible encoding (ACE)
        last if ($self->{conf}->{two_level_domains}{$temp});
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
          # International domain names in ASCII-compatible encoding (ACE)
          last if ($self->{conf}->{three_level_domains}{$temp});
        }
      }
      elsif (@domparts == 4) {
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

=item $domain = trim_domain($fqdn, $is_ascii)

Cut a fully-qualified hostname into the hostname part and the domain
part, returning just the domain.

Examples:

    "www.foo.com" => "foo.com"
    "www.foo.co.uk" => "foo.co.uk"

If $is_ascii given and true, skip idn_to_ascii() conversion

=cut

sub trim_domain {
  my ($self, $domain, $is_ascii) = @_;

  my (undef, $dom) = $self->split_domain($domain, $is_ascii);
  return $dom;
}

###########################################################################

=item $ok = is_domain_valid($dom, $is_ascii)

Return C<1> if the domain/hostname uses valid known TLD, C<undef> otherwise.

If $is_ascii given and true, skip idn_to_ascii() conversion.

Note that this only checks the TLD validity and nothing else.  To verify
that the complete fqdn is in a valid legal format, Util::is_fqdn_valid() can
additionally be used.

=back

=cut

sub is_domain_valid {
  my ($self, $dom, $is_ascii) = @_;

  return 0 unless defined $dom;
  if ($is_ascii) {
    utf8::encode($dom)  if utf8::is_utf8($dom); # force octets
    $dom = lc $dom;
  } else {
    # convert to ascii, handles Unicode dot normalization also
    $dom = idn_to_ascii($dom);
  }

  # domains don't have whitespace
  return 0 if ($dom =~ /\s/);

  # ensure it ends in a known-valid TLD, and has at least 1 dot
  return 0 unless ($dom =~ /\.([^.]+)$/);
  return 0 unless exists $self->{conf}->{valid_tlds}{$1};

  return 1;     # nah, it's ok.
}

#

sub uri_to_domain {
  my $self = shift;
  my $uri = lc shift;

  # Javascript is not going to help us, so return.
  # Likewise ignore cid, file
  return if ($uri =~ /^(?:javascript|cid|file):/);

  if ($uri =~ s/^mailto://) { # handle mailto: specially
    $uri =~ s/\?.*//;			# drop parameters ?subject= etc
    # note above, Outlook linkifies foo@bar%2Ecom&x.com to foo@bar.com !!
    # uri_list_canonicalize should have made versions without ? &
    # Keep testing with & here just in case..
    return if $uri =~ /\@.*?\@/;	# abort if multiple @
    return unless $uri =~ s/.*@//;	# drop username or abort
  } else {
    $uri =~ s{^[a-z]+:/{0,2}}{}gs;	# drop the protocol
    # strip path, CGI params, fragment.  note: bug 4213 shows that "&" should
    # *not* be likewise stripped here -- it's permitted in hostnames by
    # some common MUAs!
    $uri =~ s{[/?#].*}{}gs;              
    $uri =~ s{^[^/]*\@}{}gs;		# drop username/passwd
    $uri =~ s{:\d*$}{}gs;		# port, bug 4191: sometimes the # is missing
  }

  # skip undecoded URIs if the encoded bits shouldn't be.
  # we'll see the decoded version as well.  see url_encode()
  return if $uri =~ /\%(?:2[1-9a-f]|[3-6][0-9a-f]|7[0-9a-e])/;

  my $host = idn_to_ascii($uri);  # unstripped/full domain name
  my $domain = $host;

  # keep IPs intact
  if ($host !~ IS_IP_ADDRESS) {
    # check that it's a valid hostname/fqdn
    return unless is_fqdn_valid($host, 1);
    # ignore invalid TLDs
    return unless $self->is_domain_valid($host, 1);
    # get rid of hostname part of domain, understanding delegation
    $domain = $self->trim_domain($host, 1);
  }
  
  # optionally return unstripped host name
  return !wantarray ? $domain : ($domain, $host);
}

1;

