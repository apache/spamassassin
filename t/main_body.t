#!/usr/bin/perl -w -T

# Tests for the main_body rule type (Mail::SpamAssassin::Plugin::MainBody).
#
# A main_body rule works like a body rule, but matches only the single "main"
# body part a mail client would display: attachments are skipped, and for a
# multipart/alternative section the multipart_alternative_preferred_part is
# used (defaulting to text/html, then text/plain).

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("main_body.t");
use Test::More tests => 16;
use Mail::SpamAssassin;

# ---------------------------------------------------------------------------

# run a message through SA with the given extra config and return a hash of
# the names of the rules that fired.
sub hits_for {
  my ($message, $extra_conf) = @_;
  $extra_conf = '' unless defined $extra_conf;

  my $sa = create_saobj({
    dont_copy_prefs => 1,
    post_config_text => "
      dns_available no
      use_auto_whitelist 0
      use_bayes 0

      main_body MB_TOKEN       /UNIQUETOKEN/
      score     MB_TOKEN       1.0
      main_body MB_PLAINONLY   /PLAINONLYTOKEN/
      score     MB_PLAINONLY   1.0
      main_body MB_MIXED1      /MIXEDONETOKEN/
      score     MB_MIXED1      1.0
      main_body MB_MIXED2      /MIXEDTWOTOKEN/
      score     MB_MIXED2      1.0
      main_body MB_HTMLONLY    /HTMLONLYTOKEN/
      score     MB_HTMLONLY    1.0
      main_body MB_SUBJECT     /SUBJECTTOKEN/
      score     MB_SUBJECT     1.0
      main_body MB_SUBJECT_NS  /SUBJECTTOKEN/
      tflags    MB_SUBJECT_NS  nosubject
      score     MB_SUBJECT_NS  1.0
      main_body MB_MULTI       /REPEAT/
      tflags    MB_MULTI       multiple
      score     MB_MULTI       0.1
      main_body MB_MULTI_MAX   /REPEAT/
      tflags    MB_MULTI_MAX   multiple maxhits=2
      score     MB_MULTI_MAX   0.1

      body      B_TOKEN        /UNIQUETOKEN/
      score     B_TOKEN        1.0

      meta      META_ON_MB     (MB_TOKEN)
      score     META_ON_MB     1.0
      $extra_conf
    ",
  });
  $sa->init(0);

  my $mail = $sa->parse($message);
  my $pms = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
  $pms->check();

  my %hits = map { $_ => 1 } split(/,/, $pms->get_names_of_tests_hit());
  # how many times did the multiple-match rules hit?
  my %counts = %{$pms->{tests_already_hit} || {}};

  $pms->finish();
  $mail->finish();
  $sa->finish();

  return (\%hits, \%counts);
}

# ---------------------------------------------------------------------------
# 1. Attachment exclusion: a token that lives only in an attached text/html
#    part must NOT fire a main_body rule, but a plain body rule (with
#    scan_text_attachments) must.

my $msg_attach = <<'EOM';
Message-ID: <a@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="UTF-8"

Hello this is the visible body.
--BOUND
Content-Type: text/html; name="evil.html"
Content-Disposition: attachment; filename="evil.html"

<html><body>UNIQUETOKEN</body></html>
--BOUND--
EOM

{
  my ($hits) = hits_for($msg_attach, "scan_text_attachments 1");
  ok(!$hits->{MB_TOKEN}, "main_body ignores token in attachment");
  ok($hits->{B_TOKEN},   "body rule sees token in attachment (scan_text_attachments)");
}

# ---------------------------------------------------------------------------
# 1b. multipart/mixed with two inline text parts (no filenames): an MUA renders
#     both, so main_body must gather both.

my $msg_mixed = <<'EOM';
Message-ID: <a2@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="UTF-8"

first part with MIXEDONETOKEN inside
--BOUND
Content-Type: text/plain; charset="UTF-8"

second part with MIXEDTWOTOKEN inside
--BOUND--
EOM

{
  my ($hits) = hits_for($msg_mixed);
  ok($hits->{MB_MIXED1}, "main_body sees the first inline text part of a mixed message");
  ok($hits->{MB_MIXED2}, "main_body sees the second inline text part of a mixed message");
}

# ---------------------------------------------------------------------------
# 2. multipart/alternative default: text/html preferred over text/plain.

my $msg_alt = <<'EOM';
Message-ID: <b@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="UTF-8"

PLAINONLYTOKEN here
--BOUND
Content-Type: text/html; charset="UTF-8"

<html><body>HTMLONLYTOKEN here</body></html>
--BOUND--
EOM

{
  my ($hits) = hits_for($msg_alt);
  ok($hits->{MB_HTMLONLY},   "alternative default prefers text/html");
  ok(!$hits->{MB_PLAINONLY}, "alternative default ignores text/plain when html present");
}

# 2b. preference flips to text/plain when configured.
{
  my ($hits) = hits_for($msg_alt,
    "multipart_alternative_preferred_part text/plain");
  ok($hits->{MB_PLAINONLY}, "preferred_part text/plain selects the plain part");
  ok(!$hits->{MB_HTMLONLY}, "preferred_part text/plain ignores the html part");
}

# ---------------------------------------------------------------------------
# 3. text/plain fallback: alternative with only a text/plain part, no html,
#    setting unset -> plain token matches (html->plain fallback).

my $msg_alt_plainonly = <<'EOM';
Message-ID: <c@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="UTF-8"

PLAINONLYTOKEN here
--BOUND--
EOM

{
  my ($hits) = hits_for($msg_alt_plainonly);
  ok($hits->{MB_PLAINONLY}, "falls back to text/plain when no html alternative");
}

# ---------------------------------------------------------------------------
# 4. multiple tflag.

my $msg_multi = <<'EOM';
Message-ID: <d@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

REPEAT REPEAT REPEAT and done
EOM

{
  my ($hits, $counts) = hits_for($msg_multi);
  ok($hits->{MB_MULTI}, "multiple rule fires");
  is($counts->{MB_MULTI}, 3, "multiple rule counts all 3 hits");
  is($counts->{MB_MULTI_MAX}, 2, "maxhits=2 caps the hit count");
}

# ---------------------------------------------------------------------------
# 5. Subject handling: Subject is prepended by default, suppressed by nosubject.

my $msg_subject = <<'EOM';
Message-ID: <e@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: SUBJECTTOKEN in the subject
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

nothing special in the body
EOM

{
  my ($hits) = hits_for($msg_subject);
  ok($hits->{MB_SUBJECT},     "Subject is matched by default (prepended)");
  ok(!$hits->{MB_SUBJECT_NS}, "nosubject tflag suppresses Subject match");
}

# ---------------------------------------------------------------------------
# 6. meta rule depending on a main_body rule resolves.

my $msg_meta = <<'EOM';
Message-ID: <f@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: sender@example.com
To: recipient@example.com
Subject: plain subject
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

body with UNIQUETOKEN in it
EOM

{
  my ($hits) = hits_for($msg_meta);
  ok($hits->{MB_TOKEN},   "main_body rule fires in a simple message");
  ok($hits->{META_ON_MB}, "meta rule depending on a main_body rule resolves");
}
