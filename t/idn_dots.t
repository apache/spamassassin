#!/usr/bin/perl -w

# test URIs with UTF8 IDNA-equivalent dots between domains instead of ordinary '.'

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_names.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use SATest; sa_t_init("normalize_utf8_dots.t");
use Test;
use Mail::SpamAssassin;
use vars qw(%patterns %anti_patterns);

# settings
plan tests => 6;

# initialize SpamAssassin
my $sa = create_saobj({dont_copy_prefs => 1});
$sa->init(0); # parse rules

# load tests and write mail
%patterns = ();
%anti_patterns = ();
my $message = write_mail();

my $mail = $sa->parse($message);
my $msg = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

my $uris = join("\n", $msg->get_uri_list(), "");

# run patterns and anti-patterns
my $failures = 0;
for my $pattern (keys %patterns) {
  if (!ok($uris =~ /${pattern}/m)) {
    warn "failure: did not find /$pattern/\n";
    $failures++;
  }
}

for my $anti_pattern (keys %anti_patterns) {
  if (!ok($uris !~ /${anti_pattern}/m)) {
    warn "failure: did find /$anti_pattern/\n";
    $failures++;
  }
}

if ($failures) {
  print "URIs found:\n$uris";
}

# function to write test email
sub write_mail {
  my $message = <<'EOF';
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: this is a trivial message
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

EOF

  # Characters that look like a fullstop
  my @delims = split(//, "\x{002E}\x{3002}\x{FF0E}\x{FF61}\x{FE52}\x{2024}");
  my $i = 0;

  foreach my $delim_char (@delims) {
    $i++;
    my $delim = $delim_char; utf8::encode($delim);  # to UTF-8 octets
    my $string = "http://utf$i" . $delim . "example" . $delim . "com";
    my @patterns = ("^http://utf$i\\.example\\.com\$");
    if ($string && @patterns) {
      $message .= "$string\n";
      for my $pattern (@patterns) {
        if ($pattern =~ /^!(.*)/) {
          $anti_patterns{$1} = 1;
        }
        else {
          $patterns{$pattern} = 1;
        }
      }
    }
  }

  return $message;
}
