filterproxy.pl

This is a prototype for an SMTP filter based on Mail::SpamAssassin
(http://spamassassin.taint.org, http://spamassassin.sourceforge.net).

This was originally written with Postfix's filering in mind, based on the
"advanced" example detailed in the FILTER_README file in the Postfix
distribution, but there's no reason why it couldn't be used with other
servers.

This script is just proof of concept right now; it may more than likely not
be usable in a larger-scale environment where there's high volumes of mail
being transferred.  However, it's currently good enough for a small-scale
environment, like the IRC network for which I serve as postmaster, along
with several other people I service on a small machine.

This script requires Mail::Assassin (see above) and Net::SMTP::Server
(http://www.macgyver.org/software/perl/, plus it is also in CPAN).  You also
need a modified version of one of the modules in order to connect to a
specific SMTP server, which I include in the package.

Right now, this script has a few shortcomings:

1.  It only handles one SMTP transaction at a time.  I am considering
    integrating preforking code in to allow for more concurrency, like the
    code found in MSDW's smtpprox package.

2.  Configurability, configurability!  This is especially true if this will
    filter for multiple people whose needs may be quite different, including
    per-user weighting of the "suspicious stuff", white-lists, etc, and of
    course, whether to tag spam then deliver (if wanted), even whether to
    filter or not.

3.  What do YOU want? Who knows?  With Perl, your imagination's the limit. 

So far, I've managed to zap quite a bit of spam that'd normally go right
through the server.  With Vipul's Razor, this can go up quite a bit.  If
anyone has any ideas about Vipul's Razor and how I populate my arrays,
please let me know.

Credits:

Justin Mason for Mail::SpamAssassin
Habeeb J. "MacGyver" Dihu for his Net::SMTP::Server code

Special thanks go out to the crew at my usual IRC hangout, notably Barry
Hughes, Matti Koskimies, plus a number of others whom I may have not given
appropriate credit, but you still deserve it.  You've been a big help.  :)

--Ian R. Justman <ianj@esper.net>, 11/21/2001
