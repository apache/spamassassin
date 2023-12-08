package Mail::SpamAssassin::Pyzor::Client;

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

Mail::SpamAssassin::Pyzor::Client - Pyzor client logic

=head1 SYNOPSIS

    use Mail::SpamAssassin::Pyzor::Client ();
    use Mail::SpamAssassin::Pyzor::Digest ();

    my $client = Mail::SpamAssassin::Pyzor::Client->new();

    my $digest = Mail::SpamAssassin::Pyzor::Digest::get( $msg );

    my $check_ref = $client->check($digest);
    die $check_ref->{'Diag'} if $check_ref->{'Code'} ne '200';

    my $report_ref = $client->report($digest);
    die $report_ref->{'Diag'} if $report_ref->{'Code'} ne '200';

=head1 DESCRIPTION

A bare-bones L<Pyzor|http://pyzor.org> client that currently only
implements the functionality needed for L<Mail::SpamAssassin>.

=head1 PROTOCOL DETAILS

The Pyzor protocol is not a published standard, and there appears to be
no meaningful public documentation. What follows is enough information,
largely gleaned through forum posts and reverse engineering, to facilitate
effective use of this module:

Pyzor is an RPC-oriented, message-based protocol. Each message
is a simple dictionary of 7-bit ASCII keys and values. Server responses
always include at least the following:

=over

=item * C<Code> - Similar to HTTP status codes; anything besides C<200>
is an error.

=item * C<Diag> - Similar to HTTP status reasons: a text description
of the status.

=back

(NB: There are additional standard response headers that are useful only for
the protocol itself and thus are not part of this module's returns.)

=head2 Reliability

Pyzor uses UDP rather than TCP, so no message is guaranteed to reach its
destination. A transmission failure can happen in either the request or
the response; in either case, a timeout error will result. Such errors
are represented as thrown instances of L<Mail::Pyzor::X::Timeout>.

=cut

#----------------------------------------------------------------------

our $VERSION = '0.04';

our $DEFAULT_SERVER_HOST    = 'public.pyzor.org';
our $DEFAULT_SERVER_PORT    = 24441;
our $DEFAULT_USERNAME       = 'anonymous';
our $DEFAULT_PASSWORD       = '';
our $DEFAULT_OP_SPEC        = '20,3,60,3';
our $PYZOR_PROTOCOL_VERSION = 2.1;
our $DEFAULT_TIMEOUT        = 3.5;
our $READ_SIZE              = 8192;

use IO::Socket::INET ();
use Digest::SHA qw(sha1 sha1_hex);
use Mail::SpamAssassin::Util qw(untaint_var);

my @hash_order = ( 'Op', 'Op-Digest', 'Op-Spec', 'Thread', 'PV', 'User', 'Time', 'Sig' );

#----------------------------------------------------------------------

=head1 CONSTRUCTOR

=head2 new(%OPTS)

Create a new pyzor client.

=over 2

=item Input

%OPTS are (all optional):

=over 3

=item * C<server_host> - The pyzor server host to connect to (default is
C<public.pyzor.org>)

=item * C<server_port> - The pyzor server port to connect to (default is
24441)

=item * C<username> - The username to present to the pyzor server (default
is C<anonymous>)

=item * C<password> - The password to present to the pyzor server (default
is empty)

=item * C<timeout> - The maximum time, in seconds, to wait for a response
from the pyzor server (defeault is 3.5)

=back

=item Output

=over 3

Returns a L<Mail::SpamAssassin::Pyzor::Client> object.

=back

=back

=cut

sub new {
    my ( $class, %OPTS ) = @_;

    $OPTS{'server_host'} = untaint_var($OPTS{'server_host'});
    $OPTS{'server_port'} = untaint_var($OPTS{'server_port'});
    $OPTS{'username'} = untaint_var($OPTS{'username'});
    $OPTS{'password'} = untaint_var($OPTS{'password'});
    $OPTS{'timeout'} = untaint_var($OPTS{'timeout'});

    return bless {
        'server_host' => $OPTS{'server_host'} || $DEFAULT_SERVER_HOST,
        'server_port' => $OPTS{'server_port'} || $DEFAULT_SERVER_PORT,
        'username'    => $OPTS{'username'}    || $DEFAULT_USERNAME,
        'password'    => $OPTS{'password'}    || $DEFAULT_PASSWORD,
        'op_spec'     => $DEFAULT_OP_SPEC,
        'timeout'     => $OPTS{'timeout'} || $DEFAULT_TIMEOUT,
    }, $class;
}

#----------------------------------------------------------------------

=head1 REQUEST METHODS

=head2 report($digest)

Report the digest of a spam message to the pyzor server. This function
will throw if a messaging failure or timeout happens.

=over 2

=item Input

=over 3

=item $digest C<SCALAR>

The message digest to report, as given by
C<Mail::SpamAssassin::Pyzor::Digest::get()>.

=back

=item Output

=over 3

=item C<HASHREF>

Returns a hashref of the standard attributes noted above.

=back

=back

=cut

sub report {
    my ( $self, $digest ) = @_;

    my $msg_ref = $self->_get_base_msg( 'report', $digest );

    $msg_ref->{'Op-Spec'} = $self->{'op_spec'};

    return $self->_send_receive_msg($msg_ref);
}

=head2 check($digest)

Check the digest of a message to see if
the pyzor server has a report for it. This function
will throw if a messaging failure or timeout happens.

=over 2

=item Input

=over 3

=item $digest C<SCALAR>

The message digest to check, as given by
C<Mail::SpamAssassin::Pyzor::Digest::get()>.

=back

=item Output

=over 3

=item C<HASHREF>

Returns a hashref of the standard attributes noted above
as well as the following:

=over

=item * C<Count> - The number of reports the server has received
for the given digest.

=item * C<WL-Count> - The number of whitelist requests the server has received
for the given digest.

=back

=back

=back

=cut

sub check {
    my ( $self, $digest ) = @_;

    return $self->_send_receive_msg( $self->_get_base_msg( 'check', $digest ) );
}

# ----------------------------------------

sub _send_receive_msg {
    my ( $self, $msg_ref ) = @_;

    my $thread_id = $msg_ref->{'Thread'} or warn 'No thread ID?';

    $self->_sign_msg($msg_ref);

    return $self->_do_send_receive(
        $self->_generate_packet_from_message($msg_ref) . "\n\n",
        $thread_id,
    );
}

sub _get_base_msg {
    my ( $self, $op, $digest ) = @_;

    die "Implementor error: op is required" if !$op;
    die "error: digest is required"         if !$digest;

    return {
        'User'      => $self->{'_username'},
        'PV'        => $PYZOR_PROTOCOL_VERSION,
        'Time'      => time(),
        'Op'        => $op,
        'Op-Digest' => $digest,
        'Thread'    => $self->_generate_thread_id()
    };
}

sub _do_send_receive {
    my ( $self, $packet, $thread_id ) = @_;

    my $sock = $self->_get_connection_or_die();

    $self->_send_packet( $sock, $packet );
    my $response = $self->_receive_packet( $sock, $thread_id );

    return 0 if not defined $response;

    my $resp_hr = { map { ( split(m{: }) )[ 0, 1 ] } split( m{\n}, $response ) };

    delete $resp_hr->{'Thread'};

    my $response_pv = delete $resp_hr->{'PV'};

    if ( $PYZOR_PROTOCOL_VERSION ne $response_pv ) {
        warn "Unexpected protocol version ($response_pv) in Pyzor response!";
    }

    return $resp_hr;
}

sub _receive_packet {
    my ( $self, $sock, $thread_id ) = @_;

    my $timeout = $self->{'timeout'} * 1000;

    my $end_time = time + $self->{'timeout'};

    $sock->blocking(0);
    my $response = '';
    my $rout     = '';
    my $rin      = '';
    vec( $rin, fileno($sock), 1 ) = 1;

    while (1) {
        my $time_left = $end_time - time;

        if ( $time_left <= 0 ) {
          warn("Did not receive a response from the pyzor server $self->{'server_host'}:$self->{'server_port'} for $self->{'timeout'} seconds!");
          return;
        }

        my $bytes = sysread( $sock, $response, $READ_SIZE, length $response );
        if ( !defined($bytes) && !$!{'EAGAIN'} && !$!{'EWOULDBLOCK'} ) {
            warn "read from socket: $!";
        }

        if ( index( $response, "\n\n" ) > -1 ) {

            # Reject the response unless its thread ID matches what we sent.
            # This prevents confusion among concurrent Pyzor requests.
            if ( index( $response, "\nThread: $thread_id\n" ) != -1 ) {
                last;
            }
            else {
                $response = '';
            }
        }

        my $found = select( $rout = $rin, undef, undef, $time_left );
        warn "select(): $!" if $found == -1;
    }

    return $response;
}

sub _send_packet {
    my ( $self, $sock, $packet ) = @_;

    $sock->blocking(1);
    syswrite( $sock, $packet ) or warn "write to socket: $!";

    return;
}

sub _get_connection_or_die {
    my ($self) = @_;

    # clear the socket
    undef $self->{'_sock_pid'};
    undef $self->{'_sock'};

    $self->{'_sock_pid'} ||= $$;
    $self->{'_sock'}     ||= IO::Socket::INET->new(
        'PeerHost' => $self->{'server_host'},
        'PeerPort' => $self->{'server_port'},
        'Proto'    => 'udp'
    ) or die "Cannot connect to $self->{'server_host'}:$self->{'server_port'}: $@ $!";
    return $self->{'_sock'};
}

sub _sign_msg {
    my ( $self, $msg_ref ) = @_;

    $msg_ref->{'Sig'} = lc Digest::SHA::sha1_hex(
        Digest::SHA::sha1( $self->_generate_packet_from_message($msg_ref) )
    );

    return 1;
}

sub _generate_packet_from_message {
    my ( $self, $msg_ref ) = @_;

    return join( "\n", map { "$_: $msg_ref->{$_}" } grep { length $msg_ref->{$_} } @hash_order );
}

sub _generate_thread_id {
    my $RAND_MAX = 2**16;
    my $val      = 0;
    $val = int rand($RAND_MAX) while $val < 1024;
    return $val;
}

sub _get_user_pass_hash_key {
    my ($self) = @_;

    return lc Digest::SHA::sha1_hex( $self->{'username'} . ':' . $self->{'password'} );
}

1;
