#!/usr/bin/perl

# This file is based largely on example code bundled with MacGyver's
# Net::SMTP::Server kit, but with some additional stuff to use
# Mail::SpamAsssassin and a modified version of Net::SMTP::Server::Relay so
# then it becomes Net::SMTP::Server::SmartHost.  This way I can direct mail
# to a specific mailserver specified.  ::Relay does MX lookups which isn't
# what we want, but instead, reinject the message back into the system via
# an unfiltered version of SMTP server
#
# This was written with Postfix in mind, but nothing says you cannot use it
# for another MTA.  Be sure to read FILTER_README for a bit more background
# on how to integrate an SMTP-based filter (considered an "advanced" method).
#
# --Ian R. Justman <ianj@esper.net>, 11/21/2001

use Carp;
use Net::SMTP::Server;
use Net::SMTP::Server::Client;
use Net::SMTP::Server::SmartHost;
use Mail::SpamAssassin;
use Net::DNS;

# Some configurable stuff here.  This may get offloaded to a file in the
# future.

$smarthost="localhost:10026";

# Set up the server.  Right now, this is in accordance to Postfix's
# filtering documentation.
#
# Since a vast majority of the SMTP code is based on MacGyver's sample code,
# I'll spare everyone those details here as that info is in his code. 
# Instead,  I'll be concentrating on the message-handling portion. --irj

$server = new Net::SMTP::Server('localhost', 10025) ||
  croak("Unable to handle client connection: $!\n");

while($conn = $server->accept()) {
    my $client = new Net::SMTP::Server::Client($conn) ||
      croak("Unable to handle client connection: $!\n");

    # Process the client.  This command will block until
    # the connecting client completes the SMTP transaction.
    $client->process || next;

    # Mail::Audit wants an array of lines, while the server returns a huge
    # string.  Since I am unsure whether it needs to have the CR/LF pair for
    # each line for use with Razor, after splitting it, using the CR/LF
    # pairs as delimiters, I walk over the message again to re-add them.
    # Once the array is populated and tweaked, it is then handed to a new
    # Mail::Audit object.
    # --irj

    $message = $client->{MSG};
    @msg = split ("\r\n", $message);
    $arraycont = @msg; for(0..$arraycont) { $msg[$_] .= "\r\n"; }
    %args = (data => \@msg);
    $mail = Mail::Audit->new(%args);

    # At some point, I may also put some other code so I can go grab
    # preferences, e.g. via MySQL, e.g. scoring parameters, or even whether to
    # filter at all (hey, with Perl + MySQL, your imagination is the
    # limit).
    #
    # This is where the testing actually happens.  In this example, which I
    # have in an actual production environment (save the address), I have it
    # rewriting the message then forwarding to a collection account for
    # examination.  The addresses have been changed to protect the innocent.
    #
    # If the message is OK, we skip doing anything with the object and
    # instead, pass the original message to the smarthost code below.
    # --irj

    my $spamtest = Mail::SpamAssassin->new();
    my $status = $spamtest->check($mail);
    if ($status->is_spam ()) {
        $status->rewrite_mail ();
        $message = join ("",$mail->header(),@{$mail->body()});
        @recipients = ("====CHANGEME====");
        $recips = \@recipients;
    } else {
        $recips = $client->{TO};
    }

    $status->finish();

    # Here is where we actually connect back into Postfix or wherever.  As
    # has been mentioned before, more detailed information on how to set
    # Postfix up to use an "advanced" filter setup, directly upon this
    # documentation this implementation is based.
    #
    # Here, we need to use a hacked version of Net::SMTP::Server::Relay to
    # make this work, which I will bundle in along with the script.  I made
    # no other modifications to the rest of the distribution (which is
    # required to make this work and is in CPAN).
    # --irj

    my $relay = new Net::SMTP::Server::SmartHost($client->{FROM},
                                                 $recips,
                                                 $message,
                                                 "$smarthost");
}
