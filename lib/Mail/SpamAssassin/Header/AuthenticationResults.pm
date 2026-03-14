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

package Mail::SpamAssassin::Header::AuthenticationResults;
use strict;
use warnings FATAL => 'all';

use Mail::SpamAssassin::Header::ParameterHeader;

use parent qw(Mail::SpamAssassin::Header::ParameterHeader);

my $QUOTED_STRING = qr/"((?:[^"\\]++|\\.)*+)"?/;

=head1 NAME

Mail::SpamAssassin::Header::AuthenticationResults - parser for Authentication-Results headers

=head1 SYNOPSIS

    my $ar = Mail::SpamAssassin::Header::AuthenticationResults->new($hdr_value);
    print $ar->authserv_id();    # 'mx.example.com'
    print $ar->version();        # 1
    my @names = $ar->methods();  # ('spf', 'dkim', ...)
    my @results = $ar->method('dkim'); # list of result hashes

=head1 DESCRIPTION

This class inherits from ParameterHeader to parse Authentication-Results
header fields per RFC 8601.  ParameterHeader handles comment stripping,
semicolon tokenization, quoted strings, and line unfolding.  This class
adds A-R-specific secondary parsing of each method's value string.

=head1 METHODS

=over 4

=item new($value)

Creates a new instance, parsing the given raw header value.

=cut

sub new {
    my ($class, $value) = @_;
    my $self = $class->SUPER::new($value);
    bless $self, $class;
    $self->_parse_authserv();
    $self->_parse_methods();
    return $self;
}

=item authserv_id()

Returns the authserv-id (first token of the header value), lowercased.

=cut

sub authserv_id { $_[0]->{authserv_id} }

=item version()

Returns the version number (default 1).

=cut

sub version { $_[0]->{version} }

=item methods()

Returns a list of method names that have results.

=cut

sub methods { keys %{$_[0]->{methods}} }

=item method($name)

Returns the result(s) for the given method name. Each result is a hash
containing C<result>, C<reason>, and C<properties>.  In list context,
returns all results; in scalar context, returns the first.

=cut

sub method {
    my ($self, $name) = @_;
    my $results = $self->{methods}{lc $name};
    return unless $results;
    return wantarray ? @$results : $results->[0];
}

sub _parse_authserv {
    my ($self) = @_;
    my $val = $self->value();
    $val =~ s/^\s+|\s+$//g;
    # Extract authserv-id: first token, optionally followed by version number
    if ($val =~ /^(\S+)(?:\s+(\d+))?\s*$/) {
        $self->{authserv_id} = lc($1);
        $self->{version} = defined $2 ? $2 + 0 : 1;
    } elsif (length $val) {
        # Take just the first token
        ($self->{authserv_id}) = $val =~ /^(\S+)/;
        $self->{authserv_id} = lc($self->{authserv_id}) if defined $self->{authserv_id};
        $self->{version} = 1;
    } else {
        $self->{authserv_id} = '';
        $self->{version} = 1;
    }
}

sub _parse_methods {
    my ($self) = @_;
    my %methods;

    foreach my $param_name ($self->parameters()) {
        my @values = $self->parameter($param_name);
        foreach my $val (@values) {
            my ($method, $parsed) = $self->_parse_method_value($param_name, $val);
            push @{$methods{$method}}, $parsed if $parsed;
        }
    }

    $self->{methods} = \%methods;
}

sub _parse_method_value {
    my ($self, $name, $val) = @_;

    # Clean up method name: strip version suffix ("dkim / 1" -> "dkim", "dkim/1" -> "dkim")
    my $method = $name;
    $method =~ s{\s*/\s*\d+\s*$}{};
    $method = lc($method);

    $val =~ s/^\s+|\s+$//g;
    return () unless length $val;

    local $_ = $val;

    # Strip optional method version prefix ("/ 1 " at the start of value)
    s{^\s*/\s*\d+\s+}{};

    # Extract result (first word)
    my $result;
    if (s/^(\S+)\s*//) {
        $result = lc($1);
    } else {
        return ();
    }

    my $reason = '';

    # Extract optional reason="quoted" or reason=token
    if (s/^reason\s*=\s*$QUOTED_STRING\s*//i) {
        $reason = $1;
    } elsif (s/^reason\s*=\s*(\S+)\s*//i) {
        $reason = $1;
    }

    # Consume optional action=value
    if (s/^action\s*=\s*$QUOTED_STRING\s*//i) {
        # consumed
    } elsif (s/^action\s*=\s*(\S+)\s*//i) {
        # consumed
    }

    # Extract ptype.property=value pairs
    my $properties = {};
    while (length $_) {
        # ptype.property=value
        if (s/^([\w-]+)\.([\w-]+)\s*=\s*//) {
            my ($ptype, $property) = (lc($1), lc($2));
            my $pval;
            if (s/^$QUOTED_STRING\s*//) {
                $pval = $1;
            } elsif (s/^(\S+)\s*//) {
                $pval = $1;
            } else {
                next;
            }
            $properties->{$ptype}->{$property} = $pval;
        } else {
            # Skip unrecognized token
            last unless s/^\S+\s*//;
        }
    }

    return ($method, {
        result     => $result,
        reason     => $reason,
        properties => $properties,
    });
}

=back

=cut

1;
