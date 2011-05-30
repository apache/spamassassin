#!/usr/bin/perl

use strict;
use warnings;
use Mail::SpamAssassin::ArchiveIterator;

my $iterator = Mail::SpamAssassin::ArchiveIterator->new ({wanted_sub => \&wanted, result_sub => sub {}});
my @folders = map {"ham:mbox:$_"} @ARGV;
eval { $iterator->run(@folders); };
if ($@) { die $@ unless ($@ =~ /HITLIMIT/); }

sub wanted {
    my($class, $filename, $recv_date, $msg_array) = @_;

    open MAILOUT, "|/usr/bin/spamc -y -U /tmp/spamd.sock >> /dev/null" or die "Unable to open pipe: $!\n";
    for (@{$msg_array}) {
        print MAILOUT;
    }
    close MAILOUT;

    return 1;
}
