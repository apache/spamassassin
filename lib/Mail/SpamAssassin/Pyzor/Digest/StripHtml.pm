package Mail::SpamAssassin::Pyzor::Digest::StripHtml;

# Copyright 2018 cPanel, LLC.
# All rights reserved.
# http://cpanel.net
#
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
#

use strict;
use warnings;

=encoding utf-8

=head1 NAME

Mail::SpamAssassin::Pyzor::Digest::StripHtml - Pyzor HTML-stripping module

=head1 SYNOPSIS

    my $stripped = Mail::SpamAssassin::Pyzor::Digest::StripHtml::strip($html);

=head1 DESCRIPTION

This module attempts to duplicate pyzor's HTML-stripping logic.

=head1 ACCURACY

This library cannot achieve 100%, bug-for-bug parity with pyzor
because to do so would require duplicating Python's own HTML parsing
library. Since that library's output has changed over time, and those
changes in turn affect pyzor, it's literally impossible to arrive at
a single, fully-compatible reimplementation.

That said, all known divergences between pyzor and this library involve
invalid HTML as input.

Please open bug reports for any divergences you identify, particularly
if the input is valid HTML.

=cut

#----------------------------------------------------------------------

use HTML::Parser ();

our $VERSION = '0.03';

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $stripped = strip( $HTML )

Give it some HTML, and it'll give back the stripped text.

In B<general>, the stripping consists of removing tags as well as
C<E<lt>scriptE<gt>> and C<E<lt>styleE<gt>> elements; however, it also
removes HTML entities.

This tries very hard to duplicate pyzor's behavior with invalid HTML.

=cut

sub strip {
    my ($html) = @_;

    $html =~ s<\A\s+><>;
    $html =~ s<\s+\z><>;

    my $p = HTML::Parser->new( api_version => 3 );

    my @pieces;

    my $accumulate = 1;

    $p->handler(
        start => sub {
            my ($tagname) = @_;

            $accumulate = 0 if $tagname eq 'script';
            $accumulate = 0 if $tagname eq 'style';

            return;
        },
        'tagname',
    );

    $p->handler(
        end => sub {
            $accumulate = 1;
            return;
        }
    );

    $p->handler(
        text => sub {
            my ($copy) = @_;

            return if !$accumulate;

            # pyzor's HTML parser discards HTML entities. On top of that,
            # we need to match, as closely as possible, pyzor's handling of
            # invalid HTML entities ... which is a function of Python's
            # standard HTML parsing library. This will probably never be
            # fully compatible with the pyzor, but we can get it close.

            # The original is:
            #
            #   re.compile('&#(?:[0-9]+|[xX][0-9a-fA-F]+)[^0-9a-fA-F]')
            #
            # The parsing loop then "backs up" one byte if the last
            # character isn't a ";". We use a look-ahead assertion to
            # mimic that behavior.
            $copy =~ s<\&\# (?:[0-9]+ | [xX][0-9a-fA-F]+) (?: ; | \z | (?=[^0-9a-fA-F]) )>< >gx;

            # The original is:
            #
            #   re.compile('&([a-zA-Z][-.a-zA-Z0-9]*)[^a-zA-Z0-9]')
            #
            # We again use a look-ahead assertion to mimic Python.
            $copy =~ s<\& [a-zA-Z] [-.a-zA-Z0-9]* (?: ; | \z | (?=[^a-zA-Z0-9]) )>< >gx;

            # Python's HTMLParser aborts its parsing loop when it encounters
            # an invalid numeric reference.
            $copy =~ s<\&\#
                (?:
                    [^0-9xX]        # anything but the expected first char
                    |
                    [0-9]+[a-fA-F]  # hex within decimal
                    |
                    [xX][^0-9a-fA-F]
                )
                (.*)
            ><
                ( -1 == index($1, ';') ) ? q<> : '&#'
            >exs;

            # Python's HTMLParser treats invalid entities as incomplete
            $copy =~ s<(\&\#?)><$1 >gx;

            $copy =~ s<\A\s+><>;
            $copy =~ s<\s+\z><>;

            push @pieces, \$copy if length $copy;
        },
        'text,tagname',
    );

    $p->parse($html);
    $p->eof();

    my $payload = join( q< >, map { $$_ } @pieces );

    # Convert all sequences of whitespace OTHER THAN non-breaking spaces to
    # plain spaces.
    $payload =~ s<[^\S\x{a0}]+>< >g;

    return $payload;
}

1;
