#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("header_utf8.t");

use constant TEST_ENABLED => ($] > 5.010001);

use Test; BEGIN { plan tests => (TEST_ENABLED ? 44 : 0) };

exit unless (TEST_ENABLED);

# ---------------------------------------------------------------------------

%patterns = (
  q{/ LT_RPATH /}     => 'LT_RPATH',
  q{/ LT_ENVFROM /}   => 'LT_ENVFROM',
  q{/ LT_FROM /}      => 'LT_FROM',
  q{/ LT_FROM_ADDR /} => 'LT_FROM_ADDR',
  q{/ LT_FROM_NAME /} => 'LT_FROM_NAME',
  q{/ LT_FROM_RAW /}  => 'LT_FROM_RAW',
  q{/ LT_TO_ADDR /}   => 'LT_TO_ADDR',
  q{/ LT_TO_NAME /}   => 'LT_TO_NAME',
  q{/ LT_CC_ADDR /}   => 'LT_CC_ADDR',
  q{/ LT_SUBJ /}      => 'LT_SUBJ',
  q{/ LT_SUBJ_RAW /}  => 'LT_SUBJ_RAW',
  q{/ LT_MESSAGEID /} => 'LT_MESSAGEID',
  q{/ LT_MSGID /}     => 'LT_MSGID',
  q{/ LT_CT /}        => 'LT_CT',
  q{/ LT_CT_RAW /}    => 'LT_CT_RAW',
  q{/ LT_AUTH_DOM /}  => 'LT_AUTH_DOM',
  q{/ LT_NOTE /}      => 'LT_NOTE',
  q{/ LT_UTF8SMTP_ANY /}    => 'LT_UTF8SMTP_ANY',
  q{/ LT_SPLIT_UTF8_SUBJ /} => 'LT_SPLIT_UTF8_SUBJ',
  q{/ USER_IN_WHITELIST /}  => 'USER_IN_WHITELIST',
  q{/(?m) LT_ANY_CHARS \s*En-tête contient caractères$/} => 'LT_ANY_CHARS',
);

%anti_patterns = (
  q{/ NO_RELAYS /}  => 'NO_RELAYS',
# q{/ INVALID_MSGID /}  => 'INVALID_MSGID',
);

my $localrules = <<'END';
  add_header all  AuthorDomain _AUTHORDOMAIN_
  whitelist_from  Marilù.Gioffré@esempio-università.it
  header LT_UTF8SMTP_ANY  Received =~ /\bwith\s*UTF8SMTPS?A?\b/mi
  score  LT_UTF8SMTP_ANY  -0.1
  header LT_RPATH   Return-Path:addr =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_RPATH     0.01
  header LT_ENVFROM EnvelopeFrom =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_ENVFROM   0.01
  header LT_FROM      From =~ /^Marilù Gioffré ♥ <Marilù\.Gioffré\@esempio-università\.it>$/
  score  LT_FROM      0.01
  header LT_FROM_ADDR From:addr =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_FROM_ADDR 0.01
  header LT_FROM_NAME From:name =~ /^Marilù Gioffré ♥$/
  score  LT_FROM_NAME 0.01
  header LT_FROM_RAW  From:raw  =~ /^\s*=\?ISO-8859-1\?Q\?Maril=F9\?= Gioffré ♥ <Marilù\.Gioffré\@esempio-università\.it>$/
  score  LT_FROM_RAW  0.01
  header LT_AUTH_DOM  X-AuthorDomain =~ /xn--esempio-universit-4ob\.it/
  score  LT_AUTH_DOM  0.01
  header LT_TO_ADDR   To:addr =~ /Dörte\@Sörensen\.example\.com/
  score  LT_TO_ADDR   0.01
  header LT_TO_NAME   To:name =~ /^Dörte Å\. Sörensen, Jr\./
  score  LT_TO_NAME   0.01
  header LT_CC_ADDR   Cc:addr =~ /^θσερ\@εχαμπλε\.ψομ\z/
  score  LT_CC_ADDR   0.01
  header LT_SUBJ      Subject =~ /^Domače omrežje$/
  score  LT_SUBJ      0.01
  header LT_SUBJ_RAW  Subject:raw  =~ /=\?utf-8\*sl\?Q\?_omre=C5\?=/
  score  LT_SUBJ_RAW  0.01
  header LT_MSGID     Message-ID =~ /^<b497e6c2\@example\.срб>$/
  score  LT_MSGID     0.01
  header LT_MESSAGEID MESSAGEID  =~ /^<b497e6c2\@example\.срб>$/
  score  LT_MESSAGEID 0.01
  header LT_CT        Content-Type =~ /документы для отдела кадров\.pdf/
  score  LT_CT        0.01
  header LT_CT_RAW    Content-Type:raw =~ /=\?utf-8\?B\?tdC70LAg0LrQsNC00YDQvtCyLnBkZg==\?="/
  score  LT_CT_RAW    0.01
  header LT_SPLIT_UTF8_SUBJ Subject:raw =~ m{(=\?UTF-8) (?: \* [^?=<>, \t]* )? (\?Q\?) [^ ?]* =[89A-F][0-9A-F] \?= \s* \1 (?: \* [^ ?=]* )? \2 =[89AB][0-9A-F]}xsmi
  score  LT_SPLIT_UTF8_SUBJ 0.01
  header LT_NOTE      X-Note =~ /^The above.*char =C5 =BE is invalid, .*wild$/m
  score  LT_NOTE      0.01
  header LT_ANY_CHARS From =~ /./
  score  LT_ANY_CHARS 0.01
  describe LT_ANY_CHARS  En-tête contient caractères
END

tstlocalrules ($localrules . '
  normalize_charset 0
');
sarun ("-L -t < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

tstlocalrules ($localrules . '
  normalize_charset 1
');
sarun ("-L -t < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();
