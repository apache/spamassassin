#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("recursion");
use Test; BEGIN { plan tests => 10 };
use IO::File;

# ---------------------------------------------------------------------------

%patterns = (
  q{X-Spam-Status: }, 'headerfound',
);

# ---------------------------------------------------------------------------

my $msg1 = q{From: foo
Message-Id: <bar>
To: baz
Subject: testing recursion
Content-Type: multipart/report; report-type=delivery-status;
    boundary="__BOUND__"

--__BOUND__

This is the report.

--__BOUND__
Content-Type: message/delivery-status

Reporting-MTA: dns; example.org
Diagnostic-Info: hi!

--__BOUND__
Content-Type: message/rfc822

__MSG__

--__BOUND__--

};

my $msg2 = q{From: foo
Message-Id: <bar>
To: baz
Subject: testing recursion 2
Content-Type: multipart/mixed; boundary="__BOUND__"


--__BOUND__
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

hi!

--__BOUND__
Content-Type: message/rfc822
MIME-Version: 1.0

__MSG__

--__BOUND__--

};

# ---------------------------------------------------------------------------

sub create_test_message {
  my $msg = shift;

  my $boundstr = "AAAAAAAAAAAAAAAAAAA";
  my $bound = $boundstr; $boundstr++;
  my $text = $msg;
  $text =~ s/__BOUND__/${bound}/g;

  for my $i (1 .. 600) {
    my $newmsg = $msg;
    $bound = $boundstr; $boundstr++;
    $newmsg =~ s/__BOUND__/${bound}/g;
    $newmsg =~ s/__MSG__/${text}/g;
    $text = $newmsg;
  }

  open (OUT, ">log/recurse.eml") or die;
  print OUT $text;
  close OUT or die;
}

sub create_test_message_3 {
  my $boundstr = "AAAAAAAAAAAAAAAAAAA";
  my $bound = $boundstr; $boundstr++;
  my $text = q{From: foo
Message-Id: <bar>
To: baz
Subject: testing recursion 3
};

  for my $i (1 .. 600) {
      $text .= qq{Content-Type: multipart/mixed; boundary="$boundstr"

--$boundstr
};
    $boundstr++;
  }

  open (OUT, ">log/recurse.eml") or die;
  print OUT $text;
  close OUT or die;
}

sub try_scan {
  my $fh = IO::File->new_tmpfile();
  ok($fh);
  open(STDERR, ">&=".fileno($fh)) || die "Cannot reopen STDERR";
  sarun("-D -L -t < log/recurse.eml",
        \&patterns_run_cb);
  seek($fh, 0, 0);
  my $error = do {
    local $/;
    <$fh>;
  };

  print "# $error\n";
  if ($error =~ /Deep recursion on subroutine/) { ok(0); }
      else { ok(1); }

  ok_all_patterns();
}

create_test_message($msg1);
try_scan();
create_test_message($msg2);
try_scan();
create_test_message_3();
try_scan();

ok(unlink 'log/recurse.eml');
