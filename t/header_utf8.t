#!/usr/bin/perl -T

###
### UTF-8 CONTENT, edit with UTF-8 locale/editor
###

use lib '.'; use lib 't';
use SATest; sa_t_init("header_utf8.t");

use constant HAS_EMAIL_ADDRESS_XS => eval { require Email::Address::XS; };
use constant HAS_LIBIDN => eval { require Net::LibIDN; };
use constant HAS_LIBIDN2 => eval { require Net::LibIDN2; };

if (!HAS_EMAIL_ADDRESS_XS) {
  warn "Email::Address::XS is not installed, tests will be lacking\n";
}
if (!HAS_LIBIDN && !HAS_LIBIDN2) {
  warn "Net::LibIDN or Net::LibIDN2 is not installed, tests will be lacking\n";
}

use Test::More;
plan skip_all => "Test requires Perl 5.8" unless $] > 5.008; # TODO: SA already doesn't support anything below 5.8.1

my $tests = 156;
$tests = 305 if (HAS_EMAIL_ADDRESS_XS || (!HAS_EMAIL_ADDRESS_XS && HAS_LIBIDN && HAS_LIBIDN2));
plan tests => $tests;

# ---------------------------------------------------------------------------

%mypatterns = (
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
  q{/ USER_IN_BLOCKLIST /}  => 'USER_IN_BLOCKLIST',
);

%mypatterns_utf8 = (  # as it appears in a report body
  q{/(?m)^ 0\.0 LT_ANY_CHARS \s*En-tête contient caractères$/} => 'LT_ANY_CHARS utf8',
);

%mypatterns_mime_qp = (  # as it appears in a mail header section
  q{/(?m)^\t\*  0\.0 LT_ANY_CHARS =\?UTF-8\?Q\?En-t=C3=AAte_contient_caract=C3=A8res\?=$/} => 'LT_ANY_CHARS mime encoded',
);

%mypatterns_mime_b64 = (  # as it appears in a mail header section
  q{/(?m)^\t\*  0\.0 LT_ANY_CHARS =\?UTF-8\?B\?5a2X56ym6KKr5YyF5ZCr5Zyo5raI5oGv5oql5aS06YOo5YiG\?=$/} => 'LT_ANY_CHARS mime encoded',
);

%mypatterns_mime_b64_bug7307 = (
  q{/ LT_SUBJ2 /}      => 'LT_SUBJ2',
  q{/ LT_SUBJ2_RAW /}  => 'LT_SUBJ2_RAW',
);

%anti_patterns = (
  q{/ NO_RELAYS /}  => 'NO_RELAYS',
# q{/ INVALID_MSGID /}  => 'INVALID_MSGID',
);

my $myrules = <<'END';
  header USER_IN_BLOCKLIST  eval:check_from_in_blocklist()
  tflags USER_IN_BLOCKLIST  userconf nice noautolearn
  score USER_IN_BLOCKLIST   100
  add_header all  AuthorDomain _AUTHORDOMAIN_
  blocklist_from  Marilù.Gioffré@esempio-università.it
  header LT_UTF8SMTP_ANY  Received =~ /\bwith\s*UTF8SMTPS?A?\b/mi
  score  LT_UTF8SMTP_ANY  -0.1
  header LT_RPATH   Return-Path:addr =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_RPATH     0.01
  header LT_ENVFROM EnvelopeFrom =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_ENVFROM   0.01
  header LT_FROM      From =~ /^Marilù Gioffré ♥ <Marilù\.Gioffré\@esempio-università\.it>$/m
  score  LT_FROM      0.01
  header LT_FROM_ADDR From:addr =~ /^Marilù\.Gioffré\@esempio-università\.it\z/
  score  LT_FROM_ADDR 0.01
  header LT_FROM_NAME From:name =~ /^Marilù Gioffré ♥\z/
  score  LT_FROM_NAME 0.01
  header LT_FROM_RAW  From:raw  =~ /^\s*=\?ISO-8859-1\?Q\?Maril=F9\?= Gioffré ♥ <Marilù\.Gioffré\@esempio-università\.it>$/m
  score  LT_FROM_RAW  0.01
  header LT_AUTH_DOM  X-AuthorDomain =~ /^xn--esempio-universit-4ob\.it\z/
  score  LT_AUTH_DOM  0.01
  header LT_TO_ADDR   To:addr =~ /^Dörte\@Sörensen\.example\.com\z/
  score  LT_TO_ADDR   0.01
  header LT_TO_NAME   To:name =~ /^Dörte Å\. Sörensen, Jr\./
  score  LT_TO_NAME   0.01
  header LT_CC_ADDR   Cc:addr =~ /^θσερ\@εχαμπλε\.ψομ\z/
  score  LT_CC_ADDR   0.01
  header LT_SUBJ      Subject =~ /^Domače omrežje$/m
  score  LT_SUBJ      0.01
  header LT_SUBJ_RAW  Subject:raw  =~ /^\s*=\?iso-8859-2\*sl\?Q\?Doma=e8e\?=\s+=\?utf-8\*sl\?Q\?_omre=C5\?=/m
  score  LT_SUBJ_RAW  0.01
  header LT_SUBJ2     Subject =~ /^【重要訊息】台電105年3月電費，委託金融機構扣繳成功電子繳費憑證\(電號07487616730\)$/m
  score  LT_SUBJ2     0.01
  header LT_SUBJ2_RAW Subject:raw  =~ /^\s*=\?UTF-8\?B\?44CQ6YeN6KaB6KiK5oGv44CR5Y\+w6Zu7MTA15bm0\?=\s*=\?UTF-8\?B\?M\+aciOmbu\+iyu\+\+8jOWnlOiol\+mHkeiejeapn\+ani\+aJow==\?=\s*=\?UTF-8\?B\?57mz5oiQ5Yqf6Zu75a2Q57mz6LK75oaR6K2JKOmbu\+iZnw==\?=\s*=\?UTF-8\?B\?MDc0ODc2MTY3MzAp\?=$/m
  score  LT_SUBJ2_RAW 0.01
  header LT_MSGID     Message-ID =~ /^<b497e6c2\@example\.срб>$/m
  score  LT_MSGID     0.01
  header LT_MESSAGEID MESSAGEID  =~ /^<b497e6c2\@example\.срб>$/m
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
  score  LT_ANY_CHARS 0.001
  describe         LT_ANY_CHARS  Header contains characters
  lang fr describe LT_ANY_CHARS  En-tête contient caractères
  # sorry, Google translate:
  lang zh describe LT_ANY_CHARS  字符被包含在消息报头部分
END

if (!HAS_LIBIDN && !HAS_LIBIDN2) {
  # temporary fudge to prevent a test failing
  # until the Net::LibIDN becomes a mandatory module
  $myrules =~ s{^(\s*header LT_AUTH_DOM\s+X-AuthorDomain =~)\s*(/.*/)$}
               {$1 /esempio-università\.it/}m
}



## Test 1 with internal parser, any libidn
$ENV{'SA_HEADER_ADDRESS_PARSER'} = 1;
if (HAS_LIBIDN) {
  $ENV{'SA_LIBIDN'} = 1;
} elsif (HAS_LIBIDN2) {
  $ENV{'SA_LIBIDN'} = 2;
  $libidn2_done++;
}
run_tests();
## Test 2 with Email::Address::XS
if (HAS_EMAIL_ADDRESS_XS) {
  $ENV{'SA_HEADER_ADDRESS_PARSER'} = 2;
  if (HAS_LIBIDN2 && !defined $libidn2_done) {
    $ENV{'SA_LIBIDN'} = 2;
    $libidn2_done++;
  }
  run_tests();
} else {
  ## .. or Test 2 with internal parser, libidn2
  if (HAS_LIBIDN2 && !defined $libidn2_done) {
    $ENV{'SA_LIBIDN'} = 2;
    run_tests();
  }
}


sub run_tests {

$ENV{PERL_BADLANG} = 0;  # suppresses Perl warning about failed locale setting
# see Mail::SpamAssassin::Conf::Parser::parse(), also Bug 6992
$ENV{LANGUAGE} = $ENV{LANG} = 'fr_CH.UTF-8';

#--- normalize_charset 1

tstprefs ($myrules . '
  report_safe 0
  normalize_charset 1
');

%patterns = (%mypatterns, %mypatterns_mime_qp);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

tstprefs ($myrules . '
  report_safe 1
  normalize_charset 1
');
%patterns = (%mypatterns, %mypatterns_utf8);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

tstprefs ($myrules . '
  report_safe 2
  normalize_charset 1
');
%patterns = (%mypatterns, %mypatterns_utf8);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

#--- normalize_charset 0

tstprefs ($myrules . '
  report_safe 0
  normalize_charset 0
');
%patterns = (%mypatterns, %mypatterns_mime_qp);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

tstprefs ($myrules . '
  report_safe 1
  normalize_charset 0
');
%patterns = (%mypatterns, %mypatterns_utf8);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

tstprefs ($myrules . '
  report_safe 2
  normalize_charset 0
');
%patterns = (%mypatterns, %mypatterns_utf8);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

#--- base64 encoded-words

$ENV{PERL_BADLANG} = 0;  # suppresses Perl warning about failed locale setting
# see Mail::SpamAssassin::Conf::Parser::parse(), also Bug 6992
$ENV{LANGUAGE} = $ENV{LANG} = 'zh_CN.UTF-8';

tstprefs ($myrules . '
  report_safe 0
  normalize_charset 1
');
%patterns = (%mypatterns, %mypatterns_mime_b64);
sarun ("-L < data/nice/unicode1", \&patterns_run_cb);
ok_all_patterns();

#--- base64 encoded-words - Bug 7307

$ENV{LANGUAGE} = $ENV{LANG} = 'en_US.UTF-8';

tstprefs ($myrules . '
  report_safe 0
  normalize_charset 1
');
%patterns = (%mypatterns_mime_b64_bug7307);
%anti_patterns = ();
sarun ("-L < data/nice/unicode2", \&patterns_run_cb);
ok_all_patterns();


} ## run_tests

