#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("spamd_protocol_10");
use Test; BEGIN { plan tests => ($SKIP_SPAMD_TESTS ? 0 : 10) };

exit if $SKIP_SPAMD_TESTS;

use File::Path;
use IO::Socket;

# ---------------------------------------------------------------------------

%patterns = (

q{ SPAMD/1.1 0 EX_OK }, 'response-11',
q{ Spam: True ; }, 'spamheader',	# we use a regexp later for the rest
q{ GTUBE }, 'gtube',

);


start_spamd("-L");

my $data = "";
open (GTUBE, "data/spam/gtube.eml") || die $!;
foreach (<GTUBE>) {
  s/\r?\n?$/\n/;
  print "GTUBE: $_";
  $data .= $_;
}
close (GTUBE);

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
  my $use_inet4 =
    !$have_inet6 ||
    ($have_inet4 && $spamdhost =~ /^\d+\.\d+\.\d+\.\d+\z/);
  my %args = ( PeerAddr => $spamdhost,
               PeerPort => $spamdport,
               Proto    => "tcp",
               Type     => SOCK_STREAM
             );
  $socket = $use_inet4 ? IO::Socket::INET->new(%args)
                       : IO::Socket::INET6->new(%args);
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
    print "READ:  $_";
    $data .= $_;
  }

  $socket = undef;

  return $data;
}

sub sockwrite {
  my $data = shift;
  print $socket $data;
  $data =~ s/^/WRITE: /mg;
  print $data;
}

