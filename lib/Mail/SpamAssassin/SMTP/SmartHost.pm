package Mail::SpamAssassin::SMTP::SmartHost;

require 5.001;
use strict;
use bytes;

use vars qw(
  $VERSION @ISA @EXPORT
);

require Exporter;
require AutoLoader;
use Carp;
use Net::DNS;
use Net::SMTP;

@ISA = qw(Exporter AutoLoader);
@EXPORT = qw();

$VERSION = '1.1';

sub _smarthost {
    my $self = shift;
    my $target;

    my $client = new Net::SMTP($self->{SMARTHOST});
    $client->mail($self->{FROM});
    foreach $target (@{$self->{TO}}) {
        $client->to($target)
    }
    $client->data($self->{MSG});
    $client->quit;
}

# New instance.
sub new {
    my($this, $tmpto) = undef;

    $this = $_[0];
    
    my $class = ref($this) || $this;
    my $self = {};

    $self->{FROM} = $_[1];
    $self->{TO} = $_[2];
    $self->{MSG} = $_[3];
    $self->{SMARTHOST} = $_[4];

    bless($self, $class);    
    croak("Bad format.") unless defined($self->{SMARTHOST});
    
    $self->_smarthost;

    return $self;
}

1;
__END__
# POD begins here.

=head1 NAME

Mail::SpamAssassin::SMTP::SmartHost - A simple smarthost module for Net::SMTP::Server.

=head1 SYNOPSIS

  use Carp;
  use Net::SMTP::Server;
  use Net::SMTP::Server::Client;
  use Mail::SpamAssassin::SMTP::SmartHost;

  $smarthost="localhost:10026";

  $server = new Net::SMTP::Server('localhost', 25) ||
    croak("Unable to handle client connection: $!\n");

  while($conn = $server->accept()) {
    # We can perform all sorts of checks here for spammers, ACLs,
    # and other useful stuff to check on a connection.

    # Handle the client's connection and spawn off a new parser.
    # This can/should be a fork() or a new thread,
    # but for simplicity...
    my $client = new Net::SMTP::Server::Client($conn) ||
	croak("Unable to handle client connection: $!\n");

    # Process the client.  This command will block until
    # the connecting client completes the SMTP transaction.
    $client->process || next;
    
    # In this simple server, we're just relaying everything
    # to a server.  If a real server were implemented, you
    # could save email to a file, or perform various other
    # actions on it here.
    my $relay = new Mail::SpamAssassin::SMTP::SmartHost($client->{FROM},
					         $client->{TO},
					         $client->{MSG},
					         $smarthost);
  }

=head1 DESCRIPTION

The Mail::SpamAssassin::SMTP::SmartHost module implements simple SMTP client
connection for use with the Net::SMTP::Server module.  All this module does
is to take a given message and deliver it into another SMTP server, using it
as a "smarthost", making it useful for reinjecting filtered content back
into an SMTP server via an unfiltered port.

This code started life as the Net::SMTP::Server::Relay module which comes
standard with the Net::SMTP::Server package.  After some appropriate
modifications, it is now useful to connect to an arbitrary SMTP server.

The above example illustrates the use of the Mail::SpamAssassin::SMTP::SmartHost
module -- you simply have to instantiate the module, passing along
the sender, recipients, message, and next-hop mailserver.  More formally:

  $relay = new Mail::SpamAssassin::SMTP::SmartHost($from, @to, $msg, $smarthost);

Where $from is the sender, @to is an array containing the list of
recipients, $msg is the message to relay, and $smarthost is the
SMTP server to which you wish to connect including port in host:port format.

=head1 AUTHOR AND COPYRIGHT

Orignial code
Net::SMTP::Server / SMTP::Server is Copyright(C) 1999, 
  MacGyver (aka Habeeb J. Dihu) <macgyver@tos.net>.  ALL RIGHTS RESERVED.

Modifications to Net::SMTP::Server::Relay
  Ian R. Justman <ianj@esper.net>

You may distribute this package under the terms of either the GNU
General Public License or the Artistic License, as specified in the
Perl README file. 

=head1 SEE ALSO

Net::SMTP::Server::Server, Net::SMTP::Server::Client,
Net::SMTP::Server::Relay

=cut
