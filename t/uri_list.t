#!/usr/bin/perl -T

# Tests for Bug #7591, which is actually a bug seen in the EL7 build of Perl.
# The real root cause is obscure, so we test for the bug not the Perl version.

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("uri_list");
use Test::More tests=> 12;
use Mail::SpamAssassin::Util;
use warnings;
use Cwd;

my $twoplus = <<'EOT';
Message-ID: <clean.1010101@x.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@x.com>
MIME-Version: 1.0
To: Recipient <recipient@x.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

 an url: http://host1.example.com
 an url: http://host2.example.com

EOT

my $threeurls = <<'EOT';
Message-ID: <clean.1010101@x.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@x.com>
MIME-Version: 1.0
To: Recipient <recipient@x.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

http://host1.example.com
http://host2.example.com
http://host3.example.com

EOT

my $threeplus = <<'EOT';
Message-ID: <clean.1010101@x.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@x.com>
MIME-Version: 1.0
To: Recipient <recipient@x.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

 an url: http://host1.example.com
 an url: http://host2.example.com
 an url: http://host3.example.com

EOT

my $foururls = <<'EOT';
Message-ID: <clean.1010101@x.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@x.com>
MIME-Version: 1.0
To: Recipient <recipient@x.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

 an url: http://host1.example.com
 an url: http://host2.example.com
 an url: http://host3.example.com
 an url: http://host4.example.com

EOT

my $fiveurls = <<'EOT';
Message-ID: <clean.1010101@x.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@x.com>
MIME-Version: 1.0
To: Recipient <recipient@x.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

 an url: http://host1.example.com
 an url: http://host2.example.com
 an url: http://host3.example.com
 an url: http://host4.example.com
 an url: http://host5.example.com

EOT

my $sixurls = <<'EOT';
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

http://host1.example.com
http://host2.example.com
http://host3.example.com
http://host4.example.com
http://host5.example.com
http://host6.example.com

EOT
my $tmpdir = $workdir;

for my $mail  ($twoplus, $threeurls, $threeplus, $foururls, $fiveurls, $sixurls) {
  my @urls = grep(/\bhttp:/m,$mail);
  my $count = () = $mail =~ /\bhttp:\/\//g;
  #warn "$count urls in message\n";
  # initialize SpamAssassin
  my $sa = create_saobj({dont_copy_prefs => 1});
  $sa->init(0); # parse rules
  my $mailobj = $sa->parse($mail);
  my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mailobj);
  my @urilist = $msg->get_uri_list();
  my $ulcnt = $#urilist + 1 ;
  #warn "$ulcnt urls in parselist\n";
  ok ( $count == $ulcnt );
  $sa->finish();
  # this is ugly, but it actually demos the bug. 
  open (my $mfh, ">", "$tmpdir/msg");
  print $mfh "$mail";
  my $haverules = (  -f "../rules/25_uribl.cf" );
  use vars qw($sarcnt);
  sarun("-D all < $tmpdir/msg 2>&1", \&sarcount);
  # test isn't very useful without this component, but this will at least skip the subtest when it can't be run
  SKIP: {
    skip  "No rules found!\n", 1 if (! $haverules ); 
    if (!ok ( $count == $sarcnt )) {
      warn "Simple grep for http:// found $count URLs, get_uri_list found $ulcnt URLs, spamassassin script found $sarcnt\n";
    }
  }
  sub sarcount {
    $sarcnt = grep(/uridnsbl:.*skip/, <IN>);
  }
}

