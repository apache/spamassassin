#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_protocol_10");
use Test; BEGIN { plan tests => 10 };

use File::Path;
use IO::Socket;
use Mail::SpamAssassin::Conf;

# ---------------------------------------------------------------------------

%patterns = (

q{ SPAMD/1.1 0 EX_OK }, 'response-11',
q{ Spam: True ; }, 'spamheader',	# we use a regexp later for the rest
q{ GTUBE }, 'symbolshit',

);


start_spamd("-L");

my $data = "";
while (<DATA>) {
  s/\r?\n?$/\n/;
  $data .= $_;
}

my $out;

for ($p = 0; $p <= 1; $p++) {
  $out = run_symbols ($data, $p);
  ok (defined ($out));

  if ($out =~ /Spam: True \; ([\d\.]+) \/ 5\.0/) {
    # the exact count could be just over or under 1000. compute!
    ok ($1 >= 980 && $1 < 1020);
  }

  patterns_run_cb ($out);
  ok_all_patterns();
  clear_pattern_counters();
}

stop_spamd();
exit;


sub run_symbols {
  my($data, $proto10) = @_;

  $socket = new IO::Socket::INET(
                  PeerAddr => 'localhost',
                  PeerPort => $spamdport,
                  Proto    => "tcp",
                  Type     => SOCK_STREAM
                ); 
  unless ($socket) {
    warn("FAILED - Couldn't Connect to SpamCheck Host\n");
    return undef;
  }

  if ($proto10) {
    sockwrite ("SYMBOLS SPAMC/1.0\r\n");
  }
  else {
    sockwrite ("SYMBOLS SPAMC/1.2\r\n");
    sockwrite ("Content-Length: " . length($data) . "\r\n");
    sockwrite ("\r\n");
  }
  sockwrite ($data);

  shutdown($socket, 1);

  $data = "";
  while (<$socket>) {
    s/\r?\n?$/\n/;
    print;
    $data .= $_;
  }

  $socket = undef;

  return $data;
}

sub sockwrite {
  my $data = shift;
  # warn "writing: [$data]\n";
  print $socket $data;
}

__DATA__
Received: from root by <snipped> 
To: pookey@pengus.net
Subject: test
Message-Id: <E1914yj-0007JP-00@twiggy.linux-srv.anlx.net>
From: root <root@pengus.net>
Date: Thu, 03 Apr 2003 14:42:05 +0100

testing.  Let's get GTUBE in here:
XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

