#!/usr/bin/perl -w -T

###
### UTF-8 CONTENT, edit with UTF-8 locale/editor
###

use strict;

use lib '.'; use lib 't';
use SATest; sa_t_init("get_headers");
use Test::More;

use Mail::SpamAssassin;

use constant HAS_EMAIL_ADDRESS_XS => eval { require Email::Address::XS; };

my $tests = 52;
$tests *= 2 if (HAS_EMAIL_ADDRESS_XS);
plan tests => $tests;

##############################################

# initialize SpamAssassin
my ($sa,$mail,$pms);
sub new_saobj {
  $pms->finish() if $pms;
  $mail->finish() if $mail;
  $sa->finish() if $sa;
  undef $sa; undef $mail; undef $pms;
  $sa = create_saobj({'dont_copy_prefs' => 1});
  $sa->init(0);
  $mail = $sa->parse( get_raw_headers()."\n\nBlah\n" );
  $pms = Mail::SpamAssassin::PerMsgStatus->new($sa, $mail);
}

sub try {
  my ($try, $expect) = @_;

  my $result;
  my @results = $pms->get($try);
  if (!@results) {
    $result = undef;
  } else {
    $result = join("\\n", @results);
  }

  my $parser = $Mail::SpamAssassin::Util::header_address_parser == 1 ?
    'internal' : 'Email::Address::XS';

  # Whitelist some differences
  if ($parser eq 'Email::Address::XS') {
    # try: Email::Address::XS: 'From5:addr' failed! expect: 'noreply@foobar.com\ninfo=foobar.com@mlsend.com' got: 'noreply@foobar.com'
    return 1 if $try eq 'From5:addr' && $result eq 'noreply@foobar.com';
    # try: Email::Address::XS: 'From5:name' failed! expect: undef got: '=?UTF-8?Q? Foobar _'
    return 1 if $try eq 'From5:name' && $result eq '=?UTF-8?Q? Foobar _';
    # try: Email::Address::XS: 'From9:name' failed! expect: 'Mr\nSpam' got: 'Mr, Spam <spam@blah.com>\nSpam'
    return 1 if $try eq 'From9:name' && $result eq 'Mr, Spam <spam@blah.com>\nSpam';
  }

  if (!defined $expect) {
    if (defined $result) {
      my $lr=$result;$lr=~s/\t/\\t/gs;$lr =~s/\n/\\n/gs;
      warn "try: $parser: '$try' failed! expect: undef got: '$lr'\n";
      return 0;
    } else {
      return 1;
    }
  }
  elsif (!defined $result) {
    if (defined $expect) {
      my $le=$expect;$le=~s/\t/\\t/gs;$le =~s/\n/\\n/gs;
      warn "try: $parser: '$try' failed! expect: '$le' got: undef\n";
      return 0;
    } else {
      return 1;
    }
  }

  if ($expect eq $result) {
    return 1;
  } else {
    my $le=$expect;$le=~s/\t/\\t/gs;$le =~s/\n/\\n/gs;
    my $lr=$result;$lr=~s/\t/\\t/gs;$lr =~s/\n/\\n/gs;
    warn "try: $parser: '$try' failed! expect: '$le' got: '$lr'\n";
    return 0;
  }
}

##############################################

sub get_raw_headers {
  return q{To1: <jm@foo>
To2: jm@foo
To3: jm@foo (Foo Blah)
To4: jm@foo, jm@bar
To5: display: jm@foo (Foo Blah), jm@bar ;
To6: Foo Blah <jm@foo>
To7: "Foo Blah" <jm@foo>
To8: "'Foo Blah'" <jm@foo>
To9: "_$B!z8=6b$=$N>l$GEv$?$j!*!zEv_(B_$B$?$k!*!)$/$8!z7|>^%\%s%P!<!z_(B" <jm@foo>
To10: "Some User" <"Another User"@foo>
To11: "Some User"@foo
To12: "Some User <jm@bar>" <jm@foo>
To13: "Some User <\"Some User\"@bar>" <jm@foo>
Hdr1:    foo  
  bar
	baz 
  
To_bug5201_a: =?ISO-2022-JP?B?GyRCQjw+ZRsoQiAbJEI1V0JlGyhC?= <jm@foo>
To_bug5201_b: =?ISO-2022-JP?B?GyRCNiVHTyM3JSQlcyU1JSQlQCE8PnBKcxsoQg==?= <jm@foo>
To_bug5201_c: "joe+foobar@example.com"
From1: Foo Blah
From2: <jm@foo>, "'Foo Blah'" <jm@bar>, =?utf-8?Q?'Baz Bl=C3=A4h'?= <baz@blaeh>
From3: =?utf-8?Q?"B=C3=A4z=C3=A4=C3=A4_=28baz=40blah.?= =?utf-8?Q?com=29"?= <jm@foo>
From4: "Mr., Spam"<spam@(comment)blah.com(comment)>(comment)
From5: =?UTF-8?Q?"Foobar"_<noreply@foobar.com>?=, =?utf-8?Q?"Foobar"?=<info=foobar.com@mlsend.com>
X-Note: From6 is really \\\" - escaped perl backslashes..
From6: "Mr. <Spam> (foo@bar)\\\\\\"" <spam@blah.com> (comment)
From7: "Mr. <Spam> \(foo\@bar)\\\\\\\\\\"" <spam@blah.com> (comment)
From8: "Foo Blah \(via Foobar\)" <no-reply@foobar.com>, "Foo Blah (via Foobar)" <no-reply@foobar.com>
From9: Mr, Spam <spam@blah.com>
};
}

##############################################


for (1 .. 2) { ## parser loop

if ($_ == 2 && !HAS_EMAIL_ADDRESS_XS) {
  warn "Not running Email::Address::XS tests, module missing\n";
  next;
}

$Mail::SpamAssassin::Util::header_address_parser = $_;
new_saobj();

ok(try('To1:addr', 'jm@foo'));
ok(try('To1:name', undef));
ok(try('To2:addr', 'jm@foo'));
ok(try('To2:name', undef));
ok(try('To3:addr', 'jm@foo'));
ok(try('To3:name', 'Foo Blah'));
ok(try('To4:addr', 'jm@foo\njm@bar'));
ok(try('To4:name', undef));
ok(try('To5:addr', 'jm@foo\njm@bar'));
ok(try('To5:name', 'Foo Blah'));
ok(try('To6:addr', 'jm@foo'));
ok(try('To6:name', 'Foo Blah'));
ok(try('To7:addr', 'jm@foo'));
ok(try('To7:name', 'Foo Blah'));
ok(try('To8:addr', 'jm@foo'));
ok(try('To8:name', 'Foo Blah'));
ok(try('To9:addr', 'jm@foo'));
ok(try('To9:name', '_$B!z8=6b$=$N>l$GEv$?$j!*!zEv_(B_$B$?$k!*!)$/$8!z7|>^%%s%P!<!z_(B'));
ok(try('To10:addr', '"Another User"@foo'));
ok(try('To10:name', 'Some User'));
ok(try('To11:addr', '"Some User"@foo'));
ok(try('To11:name', undef));
ok(try('To12:addr', 'jm@foo'));
ok(try('To12:name', 'Some User <jm@bar>'));
ok(try('To13:addr', 'jm@foo'));
ok(try('To13:name', 'Some User <"Some User"@bar>'));
ok(try('Hdr1', "foo   bar baz\n"));
ok(try('Hdr1:raw', "    foo  \n  bar\n\tbaz \n  \n"));
ok(try('To_bug5201_a:addr', 'jm@foo'));
ok(try('To_bug5201_a:name', '村上 久代'));
ok(try('To_bug5201_b:addr', 'jm@foo'));
ok(try('To_bug5201_b:name', '競馬７インサイダー情報'));
ok(try('To_bug5201_c:addr', 'joe+foobar@example.com'));
ok(try('To_bug5201_c:name', undef));
ok(try('From1:addr', undef));
ok(try('From1:name', 'Foo Blah'));
ok(try('From2:addr', 'jm@foo\njm@bar\nbaz@blaeh'));
ok(try('From2:name', 'Foo Blah\nBaz Bläh'));
ok(try('From3:addr', 'jm@foo'));
ok(try('From3:name', 'Bäzää (baz@blah.com)'));
ok(try('From4:addr', 'spam@blah.com'));
ok(try('From4:name', 'Mr., Spam'));
ok(try('From5:addr', 'noreply@foobar.com\ninfo=foobar.com@mlsend.com'));
ok(try('From5:name', undef));
ok(try('From6:addr', 'spam@blah.com'));
ok(try('From6:name', 'Mr. <Spam> (foo@bar)"'));
ok(try('From7:addr', 'spam@blah.com'));
ok(try('From7:name', 'Mr. <Spam> (foo@bar)"'));
ok(try('From8:addr', 'no-reply@foobar.com\nno-reply@foobar.com'));
ok(try('From8:name', 'Foo Blah (via Foobar)\nFoo Blah (via Foobar)'));
ok(try('From9:addr', 'spam@blah.com'));
ok(try('From9:name', 'Mr\nSpam'));

} ## end parser loop

$pms->finish() if $pms;
$mail->finish() if $mail;
$sa->finish() if $sa;

