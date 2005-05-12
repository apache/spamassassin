#!/usr/bin/perl -w

# test URI redirecton patterns

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
use SATest; sa_t_init("uri_html");
use Test;
use Mail::SpamAssassin;
use vars qw(%patterns %anti_patterns);

# settings
plan tests => 2;

# initialize SpamAssassin
my $sa = create_saobj({'dont_copy_prefs' => 1});

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
  if ($uris !~ /${pattern}/m) {
    print "did not find $pattern\n";
    $failures++;
  }
}
ok(!$failures);
$failures = 0;

for my $anti_pattern (keys %anti_patterns) {
  if ($uris =~ /${anti_pattern}/m) {
    print "did find $anti_pattern\n";
    $failures++;
  }
}
ok(!$failures);

# function to write test email
sub write_mail {
    my $msg = <<'EOF';
Message-ID: <clean.1010101@example.com>
Date: Mon, 07 Oct 2002 09:00:00 +0000
From: Sender <sender@example.com>
MIME-Version: 1.0
To: Recipient <recipient@example.com>
Subject: this is a trivial message
Content-Type: multipart/related;
	boundary="--IDYGGVGT_LIYGR"

----IDYGGVGT_LIYGR
Content-Type: text/plain
Content-Transfer-Encoding: 7bit

This text part is ignored
http://www.dontputthisinthetestdata.com

----IDYGGVGT_LIYGR
Content-Type: text/html; charset=us-ascii
Content-Transfer-Encoding: 8bit

<html>
<head>
<meta http-equiv="Content-Type" content="text; charset=iso-8859-1">
</head>
<body>
EOF

  while (<DATA>) {
    chomp;
    next if /^#/;
    if (/^(.*?)\t+(.*?)\s*$/) {
      my $string = $1;
      my @patterns = split(' ', $2);
      if ($string && @patterns) {
	$msg .= qq@<a href="$string">click here</a>\n@;
	for my $pattern (@patterns) {
	  if ($pattern =~ /^\!(.*)/) {
	    $anti_patterns{$1} = 1;
	  }
	  else {
	    $patterns{$pattern} = 1;
	  }
	}
      }
    }
  }
  $msg .= "</body>\n</html>\n\n----IDYGGVGT_LIYGR--\n";

  return $msg;
}

# <line>    : <string><tabs><matches>
# <string>  : string in the body
# <tabs>    : one or more tabs
# <matches> : patterns expected to be found in URI output, if preceded by ! if
#             it is an antipattern, each pattern is separated by whitespace
__DATA__
www5.poh6feib.com	poh6feib
vau6yaer.com		vau6yaer
www5.poh6feib.info	poh6feib
Haegh3de.co.uk		Haegh3de

ftp.yeinaix3.co.uk	ftp://ftp.yeinaix3.co.uk !http://ftp.yeinaix3.co.uk
ftp5.riexai5r.co.uk	http://ftp5.riexai5r.co.uk !ftp://ftp5.riexai5r.co.uk

http://10.1.3.1/	10.1.3.1

=www.deiJ1pha.com	www.deiJ1pha.com
@www.Te0xohxu.com	www.Te0xohxu.com
.www.kuiH5sai.com	www.kuiH5sai.com

a=www.zaiNgoo7.com	www.zaiNgoo7.com
c.www.moSaoga8.com	www.moSaoga8.com

http://www.example.com/about/wahfah7d.html	wahfah7d
http://www.example.com?xa1kaLuo			\?xa1kaLuo
http://www.lap7thob.com/			^http://www.lap7thob.com/$

www.phoh1Koh.com/			^www.phoh1Koh.com/$
www.Tar4caeg.com:80			http://www.Tar4caeg.com:80
www.Coo4mowe.com:80/foo/foo.html	^www.Coo4mowe.com:80/foo/foo.html
www.Nee2quae.com:80/			^www.Nee2quae.com:80/$

HAETEI3D.com	HAETEI3D
CUK3VEIZ.us	CUK3VEIZ
CHAI7SAI.biz	CHAI7SAI
VU4YAPHU.info	VU4YAPHU
NAUVE1PH.net	NAUVE1PH
LEIX6QUU.org	LEIX6QUU
LOT1GOHV.ws	LOT1GOHV
LI4JAIZI.name	LI4JAIZI
BA1LOOXU.tv	BA1LOOXU
yiez7too.CC	yiez7too
huwaroo1.DE	huwaroo1
chohza7t.JP	chohza7t
the7zuum.BE	the7zuum
sai6bahg.AT	sai6bahg
leow3del.UK	leow3del
ba5keinu.NZ	ba5keinu
chae2shi.CN	chae2shi
roo7kiey.TW	roo7kiey

www.Chiew0ch.COM	www.Chiew0ch.COM
www.thohY2qu.US		www.thohY2qu.US
www.teiP7gei.BIZ	www.teiP7gei.BIZ
www.xohThai8.INFO	www.xohThai8.INFO
www.haik7Ram.NET	www.haik7Ram.NET
www.Quaes3se.ORG	www.Quaes3se.ORG
www.Chai6tah.WS		www.Chai6tah.WS
www.Thuoth1y.NAME	www.Thuoth1y.NAME
www.Chieb8ge.TV		www.Chieb8ge.TV
WWW.quus4Rok.cc		WWW.quus4Rok.cc
WWW.maic6Hei.de		WWW.maic6Hei.de
WWW.he4Hiize.jp		WWW.he4Hiize.jp
WWW.Soh1toob.be		WWW.Soh1toob.be
WWW.chahMee5.at		WWW.chahMee5.at
WWW.peepooN0.uk		WWW.peepooN0.uk
WWW.Kiox3phi.nz		WWW.Kiox3phi.nz
WWW.jong3Xou.cn		WWW.jong3Xou.cn
WWW.waeShoe0.tw		WWW.waeShoe0.tw

invalid_ltd.foo		!invalid_tld
invalid_ltd.bar		!invalid_tld
invalid_ltd.xyzzy	!invalid_tld
invalid_ltd.co.zz	!invalid_tld

www.invalid_ltd.foo	!invalid_tld
www.invalid_ltd.bar	!invalid_tld
www.invalid_ltd.xyzzy	!invalid_tld
www.invalid_ltd.co.zz	!invalid_tld

command.com		command.com

# IPs for www.yahoo.com
http://66.94.230.33	http://66.94.230.33
http://1113515555	http://66.94.230.35

http://www.luzoop5k.com		http://www.luzoop5k.com
https://www.luzoop5k.com	https://www.luzoop5k.com
ftp://www.luzoop5k.com		ftp://www.luzoop5k.com
mailto:www.luzoop5k.com		mailto:www.luzoop5k.com
file://www.luzoop5k.com		file://www.luzoop5k.com

# //<user>:<password>@<host>:<port>/<url-path>
http://user:pass@jiefeet4.com:80/x/y	http://user:pass@jiefeet4.com:80/x/y

puahi8si.com:80			puahi8si.com:80
chop8tan.com:443		chop8tan.com:443

ftp://name@su5queib.ca//etc/motd	ftp://name@su5queib.ca//etc/motd
ftp://name@faikaj4t.dom/%2Fetc/motd	ftp://name@faikaj4t.dom//etc/motd

#keyword:sportscar		!sportscar

# test redirector pattern
http://www.NATE.com/r/DM03/n%65verp4%79re%74%61%69%6c%2eco%6d/%62%61m/?m%61%6e=%6Di%634%39	http://neverp4yretail.com/bam/[?]man=mic49

# test ignoring text portion of multipart with an html part
http://www.nowhereinthetestdata.com		!http://www.dontputhisinthetestdata.com

# questionable tests

mailto://cah3neun@thaihe4d.com		mailto://cah3neun@thaihe4d.com
mailto://jicu8vah@another@jicu8vah	jicu8vah@another@jicu8vah
