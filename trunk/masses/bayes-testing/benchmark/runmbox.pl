#!/usr/bin/perl

use Mail::Box::Manager;
use File::Basename;

my $foldername = shift;

my $folderbasename = basename($foldername);

my $mgr = Mail::Box::Manager->new;
my $folder = $mgr->open(folder => $foldername,
			access => 'r');
my $nummsg = $folder->messages;

my $count = 0;

while ($count < $nummsg) {
  my $msg = $folder->message($count);

  open MAILOUT, "|/usr/bin/spamc -y -U /tmp/spamd.sock >> /dev/null" or
#  open MAILOUT, "|/usr/bin/spamc -U /tmp/spamd.sock >> $folderbasename.output" or
    die "Unable to open pipe: $!\n";
  $msg->print(\*MAILOUT);
  close MAILOUT;
  $count++;
}
