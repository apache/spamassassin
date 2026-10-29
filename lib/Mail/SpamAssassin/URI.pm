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

package Mail::SpamAssassin::URI;

use strict;
use warnings;

use Mail::SpamAssassin::Util ();

# Interpolating an object yields the URI it was built from, so an object can
# be passed to anything that expects the string -- a log message, a cache key,
# a hash key -- without the caller having to know which it is holding.
use overload
  '""'   => sub { $_[0]->{raw} },
  # An object is always true, even one built from an empty string: with only
  # '""' overloaded, bool would be derived from it and a parsed-but-empty URI
  # would read as false.
  'bool' => sub { 1 },
  fallback => 1;

=head1 NAME

Mail::SpamAssassin::URI - parse a URI into its components

=head1 SYNOPSIS

  use Mail::SpamAssassin::URI;

  my $uri = Mail::SpamAssassin::URI->new('https://example.com/a?url=http%3A%2F%2Fevil.com');

  $uri->scheme;                 # https
  $uri->host;                   # example.com
  $uri->path;                   # /a
  $uri->param('url');           # http://evil.com

  for my $p ($uri->params) {
    printf "%s = %s\n", $p->{name}, $p->{value};
  }

=head1 DESCRIPTION

Splits a URI into its RFC 3986 components and percent-decodes each one
separately.

The order matters.  Percent-encoding exists so that a reserved character can
appear as B<data> inside a component, so the component boundaries have to be
found in the raw string and only then may each component be decoded.  Decoding
the whole URI first would invent boundaries that no server or MUA ever sees:
in C<https://host/a%3Fx=1> the C<%3F> is part of the path, not the start of a
query string, and in C<?url=a%26b=c> the C<%26> belongs to the value of C<url>
rather than separating two parameters.

Accessors therefore come in two flavours.  C<authority>, C<raw_path>, C<query>
and C<fragment> return the component exactly as it appeared, while C<host>,
C<path> and the parameter accessors return decoded values.

Nothing here validates a URI.  Every string parses, including the empty one,
so a caller that needs to know whether it has something usable should ask a
question it actually cares about, such as C<is_http> or whether C<host> is
defined.  Note this differs from L<Mail::SpamAssassin::HTML::Color>, which
throws on malformed input; a URI arrives from a hostile message rather than
from a configuration file, so refusing to parse it is not helpful.

=head1 METHODS

=over 4

=item new($string)

Parses C<$string> and returns an object.  Never returns undef and never dies;
an undefined argument is treated as an empty string.

=cut

sub new {
  my ($class, $string) = @_;

  $string = '' unless defined $string;

  my $self = bless { raw => $string }, $class;

  # RFC 3986 Appendix B.  Every group is optional, so this matches any string.
  local($1,$2,$3,$4,$5);
  @{$self}{qw(scheme authority path query fragment)} =
    $string =~ m|^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  $self->{scheme} = lc $self->{scheme} if defined $self->{scheme};
  $self->{path} = '' unless defined $self->{path};

  return $self;
}

=item raw()

The string the object was built from.  An object also stringifies to this, so
it can be interpolated, compared or used as a hash key wherever the original
string would have been; an object is always true, even when that string is
empty.

=cut

sub raw { return $_[0]->{raw}; }

=item scheme()

The scheme, lowercased and without the trailing colon, or undef.

=cut

sub scheme { return $_[0]->{scheme}; }

=item authority()

The authority exactly as it appeared, including any userinfo and port, or
undef when the URI has none.  See C<host> for the decoded hostname.

=cut

sub authority { return $_[0]->{authority}; }

=item path()

The path, percent-decoded.  Always defined, but may be empty.

An encoded separator is not distinguished from a real one: C</tr%2Fop> and
C</tr/op> both come back as C</tr/op>.  A caller that needs to tell them apart
wants C<raw_path>.

=cut

sub path {
  my ($self) = @_;

  $self->{_path} = Mail::SpamAssassin::Util::url_decode($self->{path})
    unless exists $self->{_path};

  return $self->{_path};
}

=item raw_path()

The path exactly as it appeared, still percent-encoded.

=cut

sub raw_path { return $_[0]->{path}; }

=item query()

The query string exactly as it appeared, without the leading C<?>, or undef.
See C<params> for the decoded parameters.

=cut

sub query { return $_[0]->{query}; }

=item fragment()

The fragment exactly as it appeared, without the leading C<#>, or undef.

=cut

sub fragment { return $_[0]->{fragment}; }

# Split the authority into userinfo, host and port once, on first use.
sub _split_authority {
  my ($self) = @_;

  return if $self->{_authority_split}++;

  my $auth = $self->{authority};
  return unless defined $auth;

  local($1);
  $self->{userinfo} = $1 if $auth =~ s/^([^\@]*)\@//;
  $self->{port} = $1 if $auth =~ s/:(\d*)$//;

  my $host = lc Mail::SpamAssassin::Util::url_decode($auth);
  # A hostname has one identity however it is spelled, so an internationalised
  # one is folded to its ASCII form alongside the lowercasing and decoding
  # above.  Guarded, so that something which is not a hostname at all is left
  # to be judged by the caller rather than rewritten here.
  $host = Mail::SpamAssassin::Util::idn_to_ascii($host)
    if Mail::SpamAssassin::Util::is_fqdn_valid($host);
  $self->{host} = $host;

  return;
}

=item host()

The hostname, decoded, lowercased and folded to ASCII (an internationalised
name is returned in its xn-- form), with any userinfo and port removed, or
undef when the URI has no authority.

The authority is decoded but never re-split, so a C<%2F> inside it stays part
of the hostname rather than starting a path.  C<https://host.example%2Fa/b>
therefore has the (unresolvable) host C<host.example/a> and the path C</b>,
which is what the CPAN L<URI> module reports.

The folding goes further than L<URI> does, deliberately.  L<URI> folds an
internationalised name given as a character string but leaves a percent-encoded
or a mixed-case one alone, so C<b%C3%BCcher.de>, C<BUECHER.de> spelled with an
umlaut, and C<xn--bcher-kva.de> are three different hosts to it.  Here they are
one: a configured hostname has to match however the message spelled it, and
mail carries octets rather than character strings.

=cut

sub host { my $s = shift; $s->_split_authority; return $s->{host}; }

=item userinfo()

The userinfo from the authority, undecoded and without the C<@>, or undef.

=cut

sub userinfo { my $s = shift; $s->_split_authority; return $s->{userinfo}; }

=item port()

The port from the authority, or undef.

=cut

sub port { my $s = shift; $s->_split_authority; return $s->{port}; }

=item http_url()

The http(s) URL to request from a server, rebuilt from the URI's parts, or
undef when there is nothing a client could request.

The result is C<scheme://host[:port]path[?query]>, built from the canonical
C<host> (decoded, lowercased and IDN-folded to its C<xn--> form, exactly as a
browser resolves it), so an obfuscated spelling of the host is requested as the
real one -- C<b%C3%BCcher.de> is fetched as C<xn--bcher-kva.de>, not as the
raw octets LWP would otherwise try to resolve and fail on.  The path and query
keep their original percent-encoding.

Two things are deliberately left out, because neither reaches the server the
way a browser sends the request: the fragment, which is client-side only (RFC
3986); and the userinfo (the C<user[:pass]@> before the host), which a browser
does not send preemptively -- it is held back until the server answers C<401>
-- whereas an HTTP client library typically turns it into a preemptive
C<Authorization: Basic> header that some servers reject.

undef is returned when the URI is not http(s), or when its host is not a
requestable name -- an encoded-slash authority such as C<host.example%2Fa>
decodes to something no client would resolve, and a browser likewise refuses
it rather than guessing a host and path from it.  A caller treats undef as
"nothing to fetch".

This is the form to request from a server, to use as a cache key, or to compare
against a Location header.

=cut

sub http_url {
  my ($self) = @_;

  return unless $self->is_http;

  my $host = $self->host;
  return unless defined $host && length $host;

  # The host has to be something a client would actually resolve. host() has
  # already decoded and folded it, so a leftover "/" (from an encoded slash in
  # the authority) or any other non-host junk means there is nothing to fetch;
  # a browser refuses such a URL too. An IP literal is bracketed for IPv6.
  return unless $host =~ /^\[[0-9A-Fa-f:.]+\]\z/
             || Mail::SpamAssassin::Util::is_fqdn_valid($host);

  my $s = $self->{scheme} . '://' . $host;
  $s .= ':' . $self->{port} if defined $self->{port} && length $self->{port};
  $s .= $self->{path};
  $s .= '?' . $self->{query} if defined $self->{query};

  return $s;
}

=item is_http()

True when the scheme is http or https.

=cut

sub is_http {
  my $scheme = $_[0]->{scheme};
  return defined $scheme && ($scheme eq 'http' || $scheme eq 'https');
}

# Split the query into name/value pairs once, on first use.  The query is
# split while still encoded so that an encoded separator inside a value (%26,
# %3D) stays part of that value; only then is each name and value decoded.
sub _split_query {
  my ($self) = @_;

  return $self->{_params} if $self->{_params};

  my @params;
  my $query = $self->{query};

  if (defined $query) {
    # Accept &amp; as a separator: message HTML routinely carries entity-encoded
    # URIs, and splitting on a bare & would leave "amp;" on the next name.
    foreach my $pair (split(/&(?:amp;)?/, $query, -1)) {
      next unless length $pair;
      # Limit 2: an = inside the value is data, not another separator.
      my ($name, $value) = split(/=/, $pair, 2);
      push @params, {
        name  => Mail::SpamAssassin::Util::url_decode($name),
        # A parameter with no = at all has no value, which is not the same as
        # an empty one; only the latter could ever hold a URI.
        value => defined $value
                   ? Mail::SpamAssassin::Util::url_decode($value) : undef,
      };
    }
  }

  return $self->{_params} = \@params;
}

=item params()

The query parameters as a list of hashrefs with C<name> and C<value> keys, in
the order they appeared.  Both are decoded; C<value> is undef for a parameter
that had no C<=> at all.

This is the complete form: unlike C<param_hash> it keeps every occurrence of a
repeated name.

=cut

sub params { return @{ $_[0]->_split_query }; }

=item param($name)

In list context every value for C<$name>, in order.  In scalar context the
first, or undef when there is none.

=cut

sub param {
  my ($self, $name) = @_;

  return unless defined $name;

  my @values = map { $_->{value} }
               grep { $_->{name} eq $name } @{ $self->_split_query };

  return wantarray ? @values : $values[0];
}

=item param_hash()

The query parameters as a hashref of name to value.

Lossy by nature: a repeated name keeps its B<first> value, matching C<param>
in scalar context.  Use C<params> when every occurrence matters.

=cut

sub param_hash {
  my ($self) = @_;

  my %h;
  foreach my $p (@{ $self->_split_query }) {
    $h{$p->{name}} = $p->{value} unless exists $h{$p->{name}};
  }

  return \%h;
}

=back

=head1 NOTES

Decoding uses C<Mail::SpamAssassin::Util::url_decode>, which resolves both
single and double encoding in one pass (C<%253A> and C<%3A> both yield C<:>)
but stops one layer short of triple encoding.

A C<+> is not converted to a space.  That is a convention of HTML form
submission rather than of URI syntax, and this class parses URIs.

Only C<&> (and C<&amp;>) separates query parameters.  A C<;> is left alone, so
values such as C<data:text/html;base64,...> survive intact.

=cut

1;
