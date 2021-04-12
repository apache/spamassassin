#!/usr/bin/perl -w -T

# test URIs with UTF8 IDNA-equivalent dots between domains instead of ordinary '.'

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("body_str.t");
use Test::More tests => 12;
use Mail::SpamAssassin;

my $header = <<'EOH';
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: SUBJECT X
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit

EOH

sub write_mail {
  my $body = shift;
  return $header.$body;
}

sub run_sa {
  my $message = write_mail(shift);
  my $scansize = shift;
  my $rawbody_re = shift;
  my $body_re = shift;

  # initialize SpamAssassin
  my $sa = create_saobj({
    dont_copy_prefs => 1,
    config_text => "
      dns_available no
      use_auto_whitelist 0
      use_bayes 0
      util_rb_tld com
      rawbody_part_scan_size $scansize
      body_part_scan_size $scansize
    ",
  });
  $sa->init(0); # parse rules

  my $mail = $sa->parse($message);
  my $pms = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);

  my $rawbody = join("", @{$pms->get_decoded_body_text_array()});
  my $body = join("", @{$pms->get_decoded_stripped_body_text_array()});

  my $body_part_scan_size = $pms->{main}->{conf}->{body_part_scan_size};
  my $rawbody_part_scan_size = $pms->{main}->{conf}->{rawbody_part_scan_size};

  $pms->finish();
  $mail->finish();
  $sa->finish();

  my $rawbody_str = $rawbody;
  my $body_str = $body;
  $rawbody_str =~ s/\n/\\n/s;
  $rawbody_str =~ s/([^ [:graph:]])/sprintf("\\x%s",unpack("H*",$1))/ge;
  $body_str =~ s/\n/\\n/s;
  $body_str =~ s/([^ [:graph:]])/sprintf("\\x%s",unpack("H*",$1))/ge;

  if ($rawbody_part_scan_size != $scansize ||
      $body_part_scan_size != $scansize) {
    print STDERR "FAIL: scan_size mismatch!\n";
    return 0;
  }

  if ($rawbody !~ /$rawbody_re/) {
    print STDERR "FAIL: rawbody mismatch: <BEGIN>$rawbody_str<END>\n";
    return 0;
  }

  if ($body !~ /$body_re/) {
    print STDERR "FAIL: body mismatch: <BEGIN>$body_str<END>\n";
    return 0;
  }

  return 1;
}

ok(run_sa(
  "FIRST LAST",
  0,
  qr/^FIRST LAST\z/,
  qr/^SUBJECT X\nFIRST LAST\z/
  ));

ok(run_sa(
  "<html><body><p>FIRST LAST</p></body></html>",
  0,
  qr!^<html><body><p>FIRST LAST</p></body></html>\z!,
  qr!^SUBJECT X\n<html><body><p>FIRST LAST</p></body></html>\z!
  ));

ok(run_sa(
  "<html><body><p>FIRST X<p><p>LAST</p></body></html>",
  0,
  qr!^<html><body><p>FIRST X<p><p>LAST</p></body></html>\z!,
  qr!^SUBJECT X\n<html><body><p>FIRST X<p><p>LAST</p></body></html>\z!
  ));

ok(run_sa(
  "FIRST LAST",
  9,
  qr/^FIRST LAS\z/,
  qr/^SUBJECT X\nFIRST LAS\z/
  ));

ok(run_sa(
  "FIRST XYZ\nLAST",
  10,
  qr/^FIRST XYZ\n\z/,
  qr/^SUBJECT X\nFIRST XYZ \z/
  ));

ok(run_sa(
  "FIRST LAST",
  11,
  qr/^FIRST LAST\z/,
  qr/^SUBJECT X\nFIRST LAST\z/
  ));

ok(run_sa(
  "<html><body><p>FIRST LAST</p></body></html>",
  11,
  qr/^<html><body>\z/,
  qr/^SUBJECT X\n<html><body><p>FIRST \z/
  ));

ok(run_sa(
  "FIRST XYZ BA R\nLAST",
  11,
  qr/^FIRST XYZ BA R\n\z/,
  qr/^SUBJECT X\nFIRST XYZ BA R \z/
  ));

ok(run_sa(
  "FIRST" . "X" x 1000 . "LAST",
  11,
  qr/^FIRSTXXXXXX\z/,
  qr/^SUBJECT X\nFIRSTXXXXXX\z/
  ));

ok(run_sa(
  "FIRST" . "X" x 3000 . "LAST",
  11,
  qr/^FIRSTXXXXXX\z/,
  qr/^SUBJECT X\nFIRSTXXXXXX\z/
  ));

# Is legal because 1-2k extra is allowed while
# searching for boundary
ok(run_sa(
  "FIRST" . "X" x 1000 . "\nLAST",
  11,
  qr/^FIRSTX{1000}\n\z/,
  qr/^SUBJECT X\nFIRSTX{1000} \z/
  ));

ok(run_sa(
  "FIRST" . "X" x 3000 . "\nLAST",
  11,
  qr/^FIRSTXXXXXX\z/,
  qr/^SUBJECT X\nFIRSTXXXXXX\z/
  ));

