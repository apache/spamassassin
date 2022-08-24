#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("mimeheader");
use Test::More tests => 18;

# ---------------------------------------------------------------------------

%patterns = (
  q{ 1.0 MIMEHEADER_TEST1 }, '',
  q{ 1.0 MIMEHEADER_TEST2 }, '',
  q{ 1.0 MATCH_NL_NONRAW }, '',
  q{ 1.0 MATCH_NL_RAW }, '',
  q{ 1.0 MIMEHEADER_FOUND1 }, '',
  q{ 1.0 MIMEHEADER_FOUND2 }, '',
  q{ 1.0 MIMEHEADER_CONCAT1 }, '',
  q{ 1.0 MIMEHEADER_RANGE1 }, '',
  q{ 1.0 MIMEHEADER_RANGE2 }, '',
  q{ 1.0 MIMEHEADER_RANGE3 }, '',
  q{ 1.0 MIMEHEADER_RANGE4 }, '',
  q{ 1.0 MIMEHEADER_MULTI1 }, '',
  q{ 1.0 MIMEHEADER_MULTIMETA1 }, '',
  q{ 1.0 MIMEHEADER_MULTI2 }, '',
  q{ 1.0 MIMEHEADER_MULTIMETA2 }, '',
  q{ 1.0 MIMEHEADER_CAPTURE1 }, '',
  qr/tag MIMECAP1 is now ready, value: text\/plain\n/, '',
);

%anti_patterns = (
  'MIMEHEADER_NOTFOUND', '',
);

tstprefs (q{

  mimeheader MIMEHEADER_TEST1 content-type =~ /application\/msword/
  mimeheader MIMEHEADER_TEST2 content-type =~ m!APPLICATION/MSWORD!i

  mimeheader MATCH_NL_NONRAW       Content-Type =~ /msword; name/
  mimeheader MATCH_NL_RAW   Content-Type:raw =~ /msword;\n\tname/

  mimeheader MIMEHEADER_NOTFOUND1 xyzzy =~ /foobar/
  mimeheader MIMEHEADER_FOUND1 xyzzy =~ /foobar/ [if-unset: xyzfoobarxyz]

  mimeheader MIMEHEADER_FOUND2 Content-Type !~ /xyzzy/

  # ALL and concat
  mimeheader MIMEHEADER_CONCAT1 ALL =~ /\nContent-Type: multipart\/mixed;.*?\nContent-Type: multipart\/alternative;.*?\nContent-Type: text\/plain/s
  tflags MIMEHEADER_CONCAT1 concat

  # range
  mimeheader MIMEHEADER_RANGE1 Content-Type =~ /^multipart\/mixed;/
  tflags MIMEHEADER_RANGE1 range=1
  mimeheader MIMEHEADER_RANGE2 Content-Type =~ /^multipart\/alternative.*?text\/plain; charset="iso-8859-2"$/s
  tflags MIMEHEADER_RANGE2 range=2-3 concat
  mimeheader MIMEHEADER_RANGE3 Content-Type =~ /Jurek/
  tflags MIMEHEADER_RANGE3 range=2- concat
  mimeheader MIMEHEADER_RANGE4 Content-Type =~ /Jurek/
  tflags MIMEHEADER_RANGE4 range=-10

  # multiple
  mimeheader MIMEHEADER_MULTI1 Content-Type =~ /-[82]/ # iso-8859-2, two matches
  tflags MIMEHEADER_MULTI1 multiple
  meta MIMEHEADER_MULTIMETA1 MIMEHEADER_MULTI1 == 2
  mimeheader MIMEHEADER_MULTI2 ALL =~ /^X-/m # Count X- starting headers
  tflags MIMEHEADER_MULTI2 multiple
  meta MIMEHEADER_MULTIMETA2 MIMEHEADER_MULTI2 == 4

  # named regex capture
  mimeheader MIMEHEADER_CAPTURE1 Content-Type =~ /(?<MIMECAP1>text\/\w+)/
});

# Check debug needed for tag check
sarun ("-D check -L -t < data/nice/004 2>&1", \&patterns_run_cb);
ok_all_patterns();

