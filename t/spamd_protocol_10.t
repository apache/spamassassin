#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_protocol_10");
use Test; BEGIN { plan tests => 10 };

use File::Path;
use Fcntl qw/:seek/;
use IO::Socket::INET;
use Mail::SpamAssassin::Conf;

# ---------------------------------------------------------------------------

%patterns = (

q{ SPAMD/1.1 0 EX_OK }, 'response-11',
q{ Spam: True ; }, 'spamheader',	# we use a regexp later for the rest
q{ GTUBE }, 'symbolshit',

);


start_spamd("-L");

my $startofdata = tell(DATA);
my $out = run_symbols (0);	# use protocol 1.2
ok (defined ($out));

if ($out =~ /Spam: True \; ([\d\.]+) \/ 5\.0/) {
  # the exact count could be just over or under 1000. compute!
  ok ($1 >= 980 && $1 < 1020);
}

patterns_run_cb ($out);
ok_all_patterns();
clear_pattern_counters();

seek (DATA, $startofdata, SEEK_SET);
$out = run_symbols (1);	# use protocol 1.0
ok (defined ($out));

if ($out =~ /Spam: True \; ([\d\.]+) \/ 5\.0/) {
  # the exact count could be just over or under 1000. compute!
  ok ($1 >= 980 && $1 < 1020);
}

patterns_run_cb ($out);
ok_all_patterns();
clear_pattern_counters();

stop_spamd();
exit;


sub run_symbols {
  my $proto10 = shift;

  if (!defined($socket = IO::Socket::INET->new(PeerAddr => 'localhost',
      PeerPort => $spamdport, Proto => "tcp", Type => SOCK_STREAM)))
  {
	  warn("FAILED - Couldn't Connect to SpamCheck Host\n");
	  return undef;

  } else {

  if (!$proto10) {
	  my $data = '';
	  while (<DATA>) { chomp($_); chomp($_); $data .= $_."\n"; }
	  sockwrite ("SYMBOLS SPAMC/1.2\r\n");
	  sockwrite ("Content-Length: ".length($data)."\r\n\r\n");
	  sockwrite ($data);

  } else {
	  sockwrite ("SYMBOLS SPAMC/1.0\r\n");
	  while (<DATA>)
	  {
		  chomp($_);
		  chomp($_);
		  sockwrite ("$_\n");
	  }
  }

	  shutdown($socket, 1);

	  my @Data = ();

	  while (<$socket>) {
		  my ($Data) = (/^(.+)\r?\n?$/);
		  print $Data;
		  print "\n";
		  push(@Data, $Data) if ($Data);
	  }

	  $socket = undef;
	  return join ("\n", @Data);
  }
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

