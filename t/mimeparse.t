#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use strict;
use Test;
use Mail::SpamAssassin;
use Digest::SHA1;

my %files = (
	"$prefix/t/data/nice/mime1" => [
	  join("\n", 'multipart/alternative','text/plain',
	             'multipart/mixed,text/plain','application/andrew-inset'),
	],

	"$prefix/t/data/nice/mime2" => [
	  join("\n",'audio/basic'),
	],

	"$prefix/t/data/nice/mime3" => [
	  join("\n", 'multipart/mixed','multipart/mixed,text/plain,audio/x-sun',
	             'multipart/mixed,image/gif,image/gif,application/x-be2,application/atomicmail',
		     'audio/x-sun'),
	],

	"$prefix/t/data/nice/mime4" => [
	  join("\n", 'multipart/mixed','text/plain','image/pgm'),
	],

	"$prefix/t/data/nice/mime5" => [
	  join("\n", 'multipart/mixed','text/plain','image/pbm'),
	  'cfbc6b4dbe0d6fe764dd0e0f10023afb0eb0faa9',
	  '6c41ae723b78e63e3763473cd737b84fae366f80'
	],

	"$prefix/t/data/nice/mime6" => [
	  join("\n",'application/postscript'),
	],

	"$prefix/t/data/nice/mime7" => [
	  join("\n",'multipart/mixed','audio/basic','audio/basic'),
	],

	"$prefix/t/data/nice/mime8" => [
	  join("\n",'multipart/mixed','application/postscript','binary','message/rfc822,multipart/mixed,text/plain,multipart/parallel,image/gif,audio/basic,application/atomicmail,message/rfc822,audio/x-sun'),
	  '07fdde1c24f216b05813f6a1ae0c7c1c0f84c42b',
	  '03e5acb518e8aca0b3a7b18f2d94b5efe73495b2'
	],

	"$prefix/t/data/nice/base64.txt" => [
	  join("\n",'multipart/mixed','text/plain','text/plain'),
	  '0147e619903eb01721d04c4f05ab9c9d497be193',
	  'a0f062b1992b25de8607df1b829d29ede5687126'
	],

	"$prefix/t/data/spam/badmime.txt" => [
	  join("\n",'multipart/alternative','text/plain','text/html'),
	  'fe56ab5c4b0199cd2811871adc89cf2a9a3d9748',
	  '2e7fea381fe9f0b34f947ddb7a38b81ece68605d'
	],

	"$prefix/t/data/spam/badmime2.txt" => [
	  join("\n",'multipart/alternative','text/plain','text/html'),
	  '05c9e1f1f3638a5191542b0c278debe38ac98a83',
	  'e6e71e824aec0e204367bfdc9a9e227039f42815'
	],

	"$prefix/t/data/nice/mime9" => [
	  join("\n",'multipart/mixed','text/plain','message/rfc822,message/rfc822,multipart/mixed,multipart/alternative,text/plain,text/html,image/jpeg'),
	  '5cdcabdb89c5fbb3a5e0c0473599668927045d9c',
	  'f80584aff917e03d54663422918b58e4689cf993',
	  '0228600472b0820b3b326d9d7842eef3af811cb2',
	  '0b9fb462ad496d926ef65db0da8da451d7815ab6',
	],
);

# initialize SpamAssassin
my $sa = Mail::SpamAssassin->new({
    rules_filename => "$prefix/t/log/test_rules_copy",
    site_rules_filename => "$prefix/t/log/test_default.cf",
    userprefs_filename  => "$prefix/masses/spamassassin/user_prefs",
    local_tests_only    => 1,
    debug             => 0,
    dont_copy_prefs   => 1,
});

my $numtests = 5;
while ( my($k,$v) = each %files ) {
  $numtests += @{$v};
}

plan tests => $numtests;

foreach my $k ( sort keys %files ) {
  open(INP, $k) || die "Can't find $k:$!";
  my $mail = $sa->parse(\*INP, 1);
  close(INP);

  my $res = join("\n",$mail->content_summary());
  my $want = shift @{$files{$k}};
#  print "---$k---\n---\nGOT: $res\n---\nEXPECTED: $want\n---\n";
  ok( $res eq $want );
  if ( @{$files{$k}} ) {
    my @parts = $mail->find_parts(qr/./,1);

#    my $i = 0;
#    foreach (@parts) { print "> $i ",$parts[$i]->{type},"\n"; $i++; }

    foreach ( @{$files{$k}} ) {
      $res = 1;
      if ( $_ ne '' ) {
	if ( !defined $parts[0] ) {
	  $res = '';
	}
	else {
	  $res = Digest::SHA1::sha1_hex($parts[0]->decode());
	}
#	print ">> ",$parts[0]->{'type'}," = $res\n";
#	print ">> ",$parts[0]->{'type'}," expected $_\n";
        $res = $res eq $_;
      }
      ok ( $res );
      shift @parts;
    }
  }
  $mail->finish();
}

my @msg;
my $subject;
my $mail;

@msg = ("Subject: =?ISO-8859-1?Q?a?=\n", "\n");
$mail = $sa->parse(\@msg);
$subject = $mail->get_header("Subject");
$mail->finish();
ok($subject eq "a\n");

@msg = ("Subject: =?ISO-8859-1?Q?a?= b\n", "\n");
$mail = $sa->parse(\@msg);
$subject = $mail->get_header("Subject");
$mail->finish();
ok($subject eq "a b\n");

@msg = ("Subject: =?ISO-8859-1?Q?a?=   \t =?ISO-8859-1?Q?b?=\n", "\n");
$mail = $sa->parse(\@msg);
$subject = $mail->get_header("Subject");
$mail->finish();
ok($subject eq "ab\n");

@msg = ("Subject: =?ISO-8859-1?Q?a?=\n", " =?ISO-8859-1?Q?_b?=\n", "\n");
$mail = $sa->parse(\@msg);
$subject = $mail->get_header("Subject");
$mail->finish();
ok($subject eq "a b\n");

@msg = ("Subject: =?ISO-8859-1?Q?a?=\n", " =?ISO-8859-1?Q?_b?= mem_brain =?  invalid ?=\n", "\n");
$mail = $sa->parse(\@msg);
$subject = $mail->get_header("Subject");
$mail->finish();
ok($subject eq "a b mem_brain =?  invalid ?=\n");
