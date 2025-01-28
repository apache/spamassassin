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

package Mail::SpamAssassin::Header::ParameterHeader;
use strict;
use warnings FATAL => 'all';
use Encode qw(find_encoding encode);

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Header;

use parent qw(Mail::SpamAssassin::Header);

my $re_charset = qr/[!"#\$%&'+\-0-9A-Z\\\^_`a-z\{\|\}~]+/;
my $re_language = qr/[A-Za-z]{1,8}(?:-[0-9A-Za-z]{1,8})*/;
my $re_exvalue = qr/($re_charset)?'(?:$re_language)?'(.*)/;

=head1 NAME

Mail::SpamAssassin::Header::ParameterHeader - a header with an optional main value and subsequent name=value pairs

=head1 SYNOPSIS

    my $header = Mail::SpamAssassin::Header::ParameterHeader->new('text/plain; charset="utf-8"');
    print $header->value; # text/plain
    print $header->parameter('charset'); # utf-8

=head1 DESCRIPTION

This class is used internally by SpamAssassin to parse headers that contain a main value followed by name=value pairs.

=head1 METHODS

=over 4

=item new($value,[$opts])

Creates a new instance of the class. Accepts the raw header value as a string and an optional hash reference of options.

The following options are available:

=over 4

=item keep_comments (0|1) default: 0

If set to a false value (default), all comments will be removed from the header value.
Otherwise, comments will be preserved.

=back

=cut

sub new {
    my ($class,$value,$opts) = @_;
    my $self = $class->SUPER::new($value);
    $self->{value} = '';
    $self->{parameters} = {};
    bless $self, $class;
    $self->_parse($value,$opts);
    return $self;
}

=item value()

Returns the main value of the header.

=cut

sub value      { $_[0]->{value} }

=item parameters()

Returns a list of parameter names.

=cut

sub parameters { keys %{ $_[0]->{parameters} } }

=item parameter($name)

Returns the value(s) of the parameter with the given name. If there are multiple parameters with the same name,
and the method is called in scalar context, only the first value is returned. If called in list context,
all values are returned.

=cut

sub parameter {
    my ($self,$name) = @_;
    return wantarray ? @{$self->{parameters}->{lc $name}} : $self->{parameters}->{lc $name}->[0];
}

sub _parse {
    my ($self,$raw,$opts) = @_;
    $raw =~ s/^\s+|\s+$//g;
    return unless length $raw;

    _unfold_lines($raw);
    _remove_comments($raw) unless $opts->{keep_comments};

    my @tokens;
    if ( _replace_char($raw,';',"\x{00}") ) {
        # Split on semicolons
        @tokens = split(/\x{00}/,$raw);
    } else {
        # No semicolons found which means one of two things:
        # 1. there are no parameters
        # 2. we're dealing with something non-standard
        # Let's see if there are any equals signs...
        if ( _replace_char($raw,'=',"\x{00}") ) {
            # This is non-standard, but let's try our best to parse it.
            # Split on tokens immediately preceding an equals sign
            my $pos = 0;
            while ( $raw =~ /\S+\s*\x{00}/g ) {
                my $token = substr($raw, $pos, $-[0] - $pos);
                $pos = $-[0];
                next unless length($token);
                push @tokens, $token;
            }
            my $token = substr($raw,$pos);
            push @tokens, $token;
            # Put the equals signs back
            tr/\x{00}/=/ for @tokens;
        } else {
            # No equals signs either. This is just a value.
            $self->{value} = $raw;
            return;
        }
    }

    # Parse tokens into key-value pairs.
    my $params;
    foreach my $token (@tokens) {
        $token =~ s/^\s+|\s+$//g;
        next unless length($token);
        my ($k,$v) = split(/\s*=\s*/,$token,2);
        if ( !defined($v) or !length($k) ) {
            # No equals sign or no key. Treat as value.
            $self->{value} = $token unless length($self->{value});
            next;
        }
        $v =~ s/^"(.*)"$/$1/; # Remove quotes from value
        # Always remove comments from keys (unless they were removed earlier because keep_comments = false)
        _remove_comments($k) unless !$opts->{keep_comments};
        push @{$params->{lc $k}}, $v;
    }

    $self->{parameters} = _process_rfc2231($params);

}

#
# Process RFC 2231 encoded parameters
# - Handle continuations
# - Handle encoded values
#
my $utf8 = find_encoding('utf-8');
sub _process_rfc2231 {
    my ($params) = @_;
    my %cont;
    my %encoded;
    foreach (keys %{$params}) {
        next unless $_ =~ m/^(.*)\*([0-9]+)\*?$/;
        my ($param, $sec) = ($1, $2);
        $cont{$param}->{$sec} = $params->{$_}->[0];
        $encoded{$param} = 1 if $_ =~ m/\*$/;
        delete $params->{$_};
    }
    foreach (keys %cont) {
        my $key = $_;
        $key .= '*' if $encoded{$_};
        $params->{$key} = [ join '', @{$cont{$_}}{sort { $a <=> $b } keys %{$cont{$_}}} ];
    }
    foreach (keys %{$params}) {
        next unless $_ =~ m/^(.*)\*$/;
        my $key = $1;
        next unless defined $params->{$_}->[0] and $params->{$_}->[0] =~ m/^$re_exvalue$/;
        my ($charset, $value) = ($1, $2);
        $value =~ s/%([0-9A-Fa-f]{2})/pack('C', hex($1))/eg;
        if (length $charset && $charset !~ /^(?:us-ascii|utf-8)$/i) {
            my $enc = find_encoding($charset);
            if (defined $enc) {
                # Convert to UTF-8
                $value = $utf8->encode($enc->decode($value));
            } else {
                dbg("ParameterHeader: Unknown charset '$charset' in parameter '$key' value");
            }
        }
        $params->{$key} = [ $value ];
        delete $params->{$_};
    }
    return $params;
}

=back

=cut

1;