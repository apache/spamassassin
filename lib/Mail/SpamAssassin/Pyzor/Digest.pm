package Mail::SpamAssassin::Pyzor::Digest;

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

Mail::SpamAssassin::Pyzor::Digest - Pyzor Digest module

=head1 SYNOPSIS

    my $digest = Mail::SpamAssassin::Pyzor::Digest::get( $mime_text );

=head1 DESCRIPTION

A reimplementation of L<https://github.com/SpamExperts/pyzor/blob/master/pyzor/digest.py>.

=cut

#----------------------------------------------------------------------

use Mail::SpamAssassin::Pyzor::Digest::Pieces ();
use Digest::SHA qw(sha1_hex);

our $VERSION = '0.03';

#----------------------------------------------------------------------

=head1 FUNCTIONS

=head2 $hex = get( $MSG )

This takes an email message in raw MIME text format (i.e., as saved in the
standard mbox format) and returns the message's Pyzor digest in lower-case
hexadecimal.

The output from this function should normally be identical to that of
the C<pyzor> script's C<digest> command. It is suitable for use in
L<Mail::SpamAssassin::Pyzor::Client>'s request methods.

=cut

sub get {
    my ($pms) = @_;
    return Digest::SHA::sha1_hex( ${ _get_predigest( $pms ) } );
}

# NB: This is called from the test.
sub _get_predigest {    ## no critic qw(RequireArgUnpacking)
    my ($pms) = @_;

    my $parsed = $pms->get_message();

    my @lines;

    my $payloads_ar = Mail::SpamAssassin::Pyzor::Digest::Pieces::digest_payloads($parsed);
    for my $payload (@$payloads_ar) {
        my @p_lines = Mail::SpamAssassin::Pyzor::Digest::Pieces::splitlines($payload);
        for my $line (@p_lines) {
            Mail::SpamAssassin::Pyzor::Digest::Pieces::normalize($line);

            next if !Mail::SpamAssassin::Pyzor::Digest::Pieces::should_handle_line($line);

            # Make sure we have an octet string.
            utf8::encode($line) if utf8::is_utf8($line);

            push @lines, $line;
        }
    }

    my $digest_sr = Mail::SpamAssassin::Pyzor::Digest::Pieces::assemble_lines( \@lines );
    return $digest_sr;
}

1;
