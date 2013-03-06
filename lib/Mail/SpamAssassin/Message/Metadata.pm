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

Mail::SpamAssassin::Message::Metadata - extract metadata from a message

=head1 SYNOPSIS

=head1 DESCRIPTION

This class is tasked with extracting "metadata" from messages for use as
Bayes tokens, fodder for eval tests, or other rules.  Metadata is
supplemental data inferred from the message, like the examples below.

It is held in two forms:

1. as name-value pairs of strings, presented in mail header format.  For
  example, "X-Language" => "en".  This is the general form for simple
  metadata that's useful as Bayes tokens, can be added to marked-up
  messages using "add_header", etc., such as the trusted-relay inference
  and language detection.

2. as more complex data structures on the $msg->{metadata} object.  This
  is the form used for metadata like the HTML parse data, which is stored
  there for access by eval rule code.   Because it's not simple strings,
  it's not added as a Bayes token by default (Bayes needs simple strings).

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::Message::Metadata;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Util qw(reverse_ip_address);
use Mail::SpamAssassin::Message::Metadata::Received;
use Mail::SpamAssassin::Logger;

=item new()

=back

=cut

sub new {
  my ($class, $msg) = @_;
  $class = ref($class) || $class;

  my $self = {
    msg =>		$msg,
    strings =>		{ }
  };

  bless($self,$class);
  $self;
}

sub extract {
  my ($self, $msg, $permsgstatus) = @_;

  # pre-chew Received headers
  $self->parse_received_headers ($permsgstatus, $msg);

  foreach my $tuple (
      [$self->{relays_trusted},   'RELAYSTRUSTEDREVIP'  ],
      [$self->{relays_untrusted}, 'RELAYSUNTRUSTEDREVIP'],
      [$self->{relays_internal},  'RELAYSINTERNALREVIP' ],
      [$self->{relays_external},  'RELAYSEXTERNALREVIP' ])
  { my($rly, $tag) = @$tuple;
    my @revips;
    @revips = map {
      my($ip,$revip);
      $ip = $_->{ip}  if ref $_ && !$_->{ip_private};
      $revip = reverse_ip_address($ip)  if defined $ip && $ip ne '';
      defined $revip && $revip ne '' ? $revip : ();
    } @$rly  if $rly;
    $permsgstatus->set_tag($tag,
                           @revips == 1 ? $revips[0] : \@revips) if @revips;
  }

  $permsgstatus->{main}->call_plugins("extract_metadata",
                       { msg => $msg, permsgstatus => $permsgstatus,
                         conf => $permsgstatus->{main}->{conf} });
}

sub finish {
  my ($self) = @_;
  %{$self} = ();
}

1;
