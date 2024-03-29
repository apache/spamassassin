package Mail::SpamAssassin::Pyzor::Digest::Pieces;

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

Mail::SpamAssassin::Pyzor::Digest::Pieces - Pyzor backend logic module

=head1 DESCRIPTION

This module houses backend logic for L<Mail::SpamAssassin::Pyzor::Digest>.

It reimplements logic found in pyzor's F<digest.py> module
(L<https://github.com/SpamExperts/pyzor/blob/master/pyzor/digest.py>).

=cut

#----------------------------------------------------------------------

use Encode                   ();

our $VERSION = '0.03';

# each tuple is [ offset, length ]
use constant _HASH_SPEC => ( [ 20, 3 ], [ 60, 3 ] );

use constant {
    _MIN_LINE_LENGTH => 8,

    _ATOMIC_NUM_LINES => 4,
};

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $strings_ar = digest_payloads( $EMAIL_MIME )

This imitates the corresponding object method in F<digest.py>.
It returns a reference to an array of strings. Each string can be either
a byte string or a character string (e.g., UTF-8 decoded).

NB: RFC 2822 stipulates that message bodies should use CRLF
line breaks, not plain LF (nor plain CR). 
We will thus convert any plain CRs in a quoted-printable message
body into CRLF. Python, though, doesn't do this, so the output of
our implementation of C<digest_payloads()> diverges from that of the Python
original. It doesn't ultimately make a difference since the line-ending
whitespace gets trimmed regardless, but it's necessary to factor in when
comparing the output of our implementation with the Python output.

=cut

sub digest_payloads {
    my ($parsed) = @_;

    my @subparts;

    foreach my $part ($parsed->find_parts(qr/./, 1)) {
      push(@subparts, $part);
    }
    my @payloads;

    foreach my $p (@subparts) {
        my ( $main_type, $subtype, $encoding, $encode_check ) = parse_content_type( $p->{'type'} );

        my $payload;

        if ( $main_type eq 'text' ) {

            if ( $subtype eq 'plain' ) {
              $payload = $p->{'decoded'};
	      $payload =~ s/\\'/\'/gx;
            } else {
              $payload = $p->{'rendered'};
            }

            utf8::upgrade($payload) if defined $payload;

            if ( $subtype eq 'html' ) {
                require Mail::SpamAssassin::Pyzor::Digest::StripHtml;
                $payload = Mail::SpamAssassin::Pyzor::Digest::StripHtml::strip($payload);
            }
        }
        else {
            # This does no decoding, even of, e.g., quoted-printable or base64.
            $payload = $p->{'pristine_body'};
        }
        next if not defined $payload;
        push @payloads, $payload;
    }
    return \@payloads;
}

#----------------------------------------------------------------------

=head2 normalize( $STRING )

This imitates the corresponding object method in F<digest.py>.
It modifies C<$STRING> in-place.

As with the original implementation, if C<$STRING> contains (decoded)
Unicode characters, those characters will be parsed accordingly. So:

    $str = "123\xc2\xa0";   # [ c2 a0 ] == \u00a0, non-breaking space

    normalize($str);

The above will leave C<$str> alone, but this:

    utf8::decode($str);

    normalize($str);

... will trim off the last two bytes from C<$str>.

=cut

sub normalize {    ## no critic qw( Subroutines::RequireArgUnpacking )

    # NULs are bad, mm-kay?
    $_[0] =~ tr<\0><>d;

    # NB: Python's \s without re.UNICODE is the same as Perl's \s
    # with the /a modifier.
    #
    # https://docs.python.org/2/library/re.html
    # https://perldoc.perl.org/perlrecharclass.html#Backslash-sequences

    # Python: re.compile(r'\S{10,}')
    $_[0] =~ s<\S{10,}><>ag;

    # Python: re.compile(r'\S+@\S+')
    $_[0] =~ s<\S+ @ \S+><>agx;

    # Python: re.compile(r'[a-z]+:\S+', re.IGNORECASE)
    $_[0] =~ s<[a-zA-Z]+ : \S+><>agx;

    # (from digest.py ...)
    # Make sure we do the whitespace last because some of the previous
    # patterns rely on whitespace.
    $_[0] =~ tr< \x09-\x0d><>d;

    # This is fun. digest.py's normalize() does a non-UNICODE whitespace
    # strip, then calls strip() on the string, which *will* strip Unicode
    # whitespace from the ends.
    $_[0] =~ s<\A\s+><>;
    $_[0] =~ s<\s+\z><>;

    return;
}

#----------------------------------------------------------------------

=head2 $yn = should_handle_line( $STRING )

This imitates the corresponding object method in F<digest.py>.
It returns a boolean.

=cut

sub should_handle_line {
    return $_[0] && length( $_[0] ) >= _MIN_LINE_LENGTH();
}

#----------------------------------------------------------------------

=head2 $sr = assemble_lines( \@LINES )

This assembles a string buffer out of @LINES. The string is the buffer
of octets that will be hashed to produce the message digest.

Each member of @LINES is expected to be an B<octet string>, not a
character string.

=cut

sub assemble_lines {
    my ($lines_ar) = @_;

    if ( @$lines_ar <= _ATOMIC_NUM_LINES() ) {

        # cf. handle_atomic() in digest.py
        return \join( q<>, @$lines_ar );
    }

    #----------------------------------------------------------------------
    # cf. handle_atomic() in digest.py

    my $str = q<>;

    for my $ofs_len ( _HASH_SPEC() ) {
        my ( $offset, $length ) = @$ofs_len;

        for my $i ( 0 .. ( $length - 1 ) ) {
            my $idx = int( $offset * @$lines_ar / 100 ) + $i;

            next if !defined $lines_ar->[$idx];

            $str .= $lines_ar->[$idx];
        }
    }

    return \$str;
}

#----------------------------------------------------------------------

=head2 ($main, $sub, $encoding, $checkval) = parse_content_type( $CONTENT_TYPE )

=cut

use constant _QUOTED_PRINTABLE_NAMES => (
    "quopri-codec",
    "quopri",
    "quoted-printable",
    "quotedprintable",
);

# Make Encode::decode() ignore anything that doesn't fit the
# given encoding.
use constant _encode_check_ignore => q<>;

sub parse_content_type {
    my ($content_type) = @_;

    # text/plain; charset=us-ascii
    my $ct_parse;
    if($content_type =~ /(\w+)\/(\w+); charset=(.*)/) {
      $ct_parse->{type} = $1;
      $ct_parse->{subtype} = $2;
      $ct_parse->{'attributes'}{'charset'} = $3;
    } elsif($content_type =~ /(\w+)\/(\w+)/) {
      $ct_parse->{type} = $1;
      $ct_parse->{subtype} = $2;
      $ct_parse->{'attributes'}{'charset'} = 'us-ascii';
    } else {
      $ct_parse->{type} = 'text';
      $ct_parse->{subtype} = 'plain';
      $ct_parse->{'attributes'}{'charset'} = 'us-ascii';
    }

    my $main = $ct_parse->{'type'}    || q<>;
    my $sub  = $ct_parse->{'subtype'} || q<>;

    my $encoding = $ct_parse->{'attributes'}{'charset'};

    my $checkval;

    if ($encoding) {

        # Lower-case everything, convert underscore to dash, and remove NUL.
        $encoding =~ tr<A-Z_\0><a-z->d;

        # Apparently pyzor accommodates messages that put the transfer
        # encoding in the Content-Type.
        if ( grep { $_ eq $encoding } _QUOTED_PRINTABLE_NAMES() ) {
            $checkval = Encode::FB_CROAK();
        }
    }
    else {
        $encoding = 'ascii';
    }

    # Match Python .decode()'s 'ignore' behavior
    $checkval ||= \&_encode_check_ignore;

    return ( $main, $sub, $encoding, $checkval );
}

#----------------------------------------------------------------------

=head2 @lines = splitlines( $TEXT )

Imitates C<str.splitlines()>. (cf. C<pydoc str>)

Returns a plain list in list context. Returns the number of
items to be returned in scalar context.

=cut

sub splitlines {
    return split m<\r\n?|\n>, $_[0] if defined $_[0];
}

1;
