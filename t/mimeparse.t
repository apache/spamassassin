#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
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
use Test;
use Mail::SpamAssassin;
use Mail::SpamAssassin::SHA1;

my %files = (
	"$prefix/t/data/nice/mime1" => [
	  join("\n", 'multipart/alternative','text/plain',
	             'multipart/mixed,text/richtext','application/andrew-inset'),
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
	  join("\n",'multipart/mixed','application/postscript','binary','message/rfc822'),
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
);

my $numtests = 0;
while ( my($k,$v) = each %files ) {
  $numtests += @{$v};
}

plan tests => $numtests;

foreach my $k ( sort keys %files ) {
  open(INP, $k) || die "Can't find $k:$!";
  my $mail = Mail::SpamAssassin->parse(\*INP);
  close(INP);

  # We know it's not parsed, so deal with it!
  $mail->_do_parse();

  my $res = join("\n",$mail->content_summary());
  #print "---\n$res\n---\n";
  ok( $res eq shift @{$files{$k}} );
  if ( @{$files{$k}} ) {
    my @parts = $mail->find_parts(qr/./,1);
    foreach ( @{$files{$k}} ) {
      $res = 1;
      if ( $_ ne '' ) {
	if ( !defined $parts[0] ) {
	  $res = '';
	}
	else {
	  $res = Mail::SpamAssassin::SHA1::SHA1($parts[0]->decode());
	}
	#print ">> $res\n";
        $res = $res eq $_;
      }
      ok ( $res );
      shift @parts;
    }
  }
}
