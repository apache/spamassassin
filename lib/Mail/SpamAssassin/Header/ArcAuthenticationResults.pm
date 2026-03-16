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

package Mail::SpamAssassin::Header::ArcAuthenticationResults;
use strict;
use warnings FATAL => 'all';

use Mail::SpamAssassin::Header::AuthenticationResults;

use parent qw(Mail::SpamAssassin::Header::AuthenticationResults);

=head1 NAME

Mail::SpamAssassin::Header::ArcAuthenticationResults - parser for ARC-Authentication-Results headers

=head1 SYNOPSIS

    my $aar = Mail::SpamAssassin::Header::ArcAuthenticationResults->new($hdr_value);
    print $aar->arc_index();     # 1
    print $aar->authserv_id();   # 'mx.example.com'
    my @names = $aar->methods(); # ('spf', 'dkim', ...)

=head1 DESCRIPTION

This class inherits from AuthenticationResults to parse
ARC-Authentication-Results header fields per RFC 8617.  The only
difference from a standard Authentication-Results header is the
leading C<i=N;> tag that identifies the ARC instance index.

=head1 METHODS

=over 4

=item new($value)

Creates a new instance, parsing the given raw header value.  The C<i=N;>
prefix is extracted and stored before delegating to the parent parser.

=cut

sub new {
    my ($class, $value) = @_;
    # Extract i=N; prefix before parent parsing
    my $arc_index;
    if ($value =~ s/^\s*i=(\d+)\s*;\s*//) {
        $arc_index = $1;
    }
    my $self = $class->SUPER::new($value);
    $self->{arc_index} = $arc_index;
    return $self;
}

=item arc_index()

Returns the ARC instance index (the C<i=> tag value).

=cut

sub arc_index { $_[0]->{arc_index} }

=back

=cut

1;
