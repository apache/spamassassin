#!/usr/bin/perl -w -T

# test URIs as grabbed from text/plain messages

use strict;
use lib '.'; use lib 't';
use SATest; sa_t_init("uri_text");
use Test::More tests => 168;
use Mail::SpamAssassin;
use vars qw(%patterns %anti_patterns);

# initialize SpamAssassin
my $sa = create_saobj({
    require_rules => 0,
    site_rules_filename => $siterules,
    rules_filename => $localrules,
    local_tests_only => 1,
    dont_copy_prefs => 1,
});
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
Content-Type: text/plain
Content-Transfer-Encoding: 7bit

EOF

  while (<DATA>) {
    chomp;
    next if /^#/;
    next if /^\s*$/;
    if (/^(.*?)\t+(.*?)\s*$/) {
      my $string = $1;
      my @patterns = split(' ', $2);
      if ($string && @patterns) {
        $string =~ s/{ESC}/\x1b/gs;     # magic, to avoid ^[ chars in source
        $message .= "$string\n";
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
    else {
      warn "unparseable line: $_";
    }
  }

  return $message;
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

ftp.yeinaix3.co.uk	ftp://ftp\.yeinaix3\.co\.uk !http://ftp\.yeinaix3\.co\.uk
ftp5.riexai5r.co.uk	http://ftp5\.riexai5r\.co\.uk !ftp://ftp5\.riexai5r\.co\.uk

10.1.1.1		!10\.1\.1\.1
10.1.2.1/		!10\.1\.2\.1
http://10.1.3.1/	10\.1\.3\.1

quau0wig.quau0wig	!quau0wig
foo.Cahl1goo.php	!Cahl1goo
www5.mi1coozu.php	!mi1coozu
www.mezeel0P.php	!mezeel0P
bar.neih6fee.com.php	!neih6fee
www.zai6Vuwi.com.invalid	!zai6Vuwi

=www.deiJ1pha.com	www\.deiJ1pha\.com
@www.Te0xohxu.com	www\.Te0xohxu\.com
.www.kuiH5sai.com	www\.kuiH5sai\.com

a=www.zaiNgoo7.com	www\.zaiNgoo7\.com
b@www.vohWais0.com	mailto:b\@www\.vohWais0\.com	!http://www\.vohWais0\.com
c.www.moSaoga8.com	www\.moSaoga8\.com

xyz..geifoza0.com	!geifoza0
xyz.geifoza1.com/..xyz	xyz\.geifoza1\.com/\.\.xyz
xyz.geifoza2.CoM	xyz\.geifoza2\.CoM
http://xyz..geifoza3.com	!geifoza3
http://xyz.geifoza4.com/..xyz	xyz\.geifoza4\.com/\.\.xyz
http://xyz.geifoza5.CoM	xyz\.geifoza5\.CoM

joe@koja3fui.koja3fui	!koja3fui

<xuq@dsj.x.thriyi.com>	mailto:xuq\@dsj\.x\.thriyi\.com	!http\S*thriyi

http://www.example.com/about/wahfah7d.html	wahfah7d
http://www.example.com?xa1kaLuo			\?xa1kaLuo
http://www.example.com#xa1kaLup			\#xa1kaLup
http://www.lap7thob.com/			^http://www\.lap7thob\.com/$

www.phoh1Koh.com/			^http://www\.phoh1Koh\.com/$
www.Tar4caeg.com:80			^http://www\.Tar4caeg\.com:80
www.Coo4mowe.com:80/foo/foo.html	^http://www\.Coo4mowe\.com:80/foo/foo\.html
www.Nee2quae.com:80/			^http://www\.Nee2quae\.com:80/$
www.foo@Qii3mafs.com:80			^http://www\.foo\@Qii3mafs\.com:80$
www.foo:bar@Qii3maft.com:80		^http://www\.foo:bar\@Qii3maft\.com:80$

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

www.Chiew0ch.COM	^http://www\.Chiew0ch\.COM
www.thohY2qu.US		^http://www\.thohY2qu\.US
www.teiP7gei.BIZ	^http://www\.teiP7gei\.BIZ
www.xohThai8.INFO	^http://www\.xohThai8\.INFO
www.haik7Ram.NET	^http://www\.haik7Ram\.NET
www.Quaes3se.ORG	^http://www\.Quaes3se\.ORG
www.Chai6tah.WS		^http://www\.Chai6tah\.WS
www.Thuoth1y.NAME	^http://www\.Thuoth1y\.NAME
www.Chieb8ge.TV		^http://www\.Chieb8ge\.TV
WWW.quus4Rok.cc		^http://WWW\.quus4Rok\.cc
WWW.maic6Hei.de		^http://WWW\.maic6Hei\.de
WWW.he4Hiize.jp		^http://WWW\.he4Hiize\.jp
WWW.Soh1toob.be		^http://WWW\.Soh1toob\.be
WWW.chahMee5.at		^http://WWW\.chahMee5\.at
WWW.peepooN0.uk		^http://WWW\.peepooN0\.uk
WWW.Kiox3phi.nz		^http://WWW\.Kiox3phi\.nz
WWW.jong3Xou.cn		^http://WWW\.jong3Xou\.cn
WWW.waeShoe0.tw		^http://WWW\.waeShoe0\.tw

invalid_ltd.notword	!invalid_tld
invalid_ltd.invalid	!invalid_tld
invalid_ltd.xyzzy	!invalid_tld
invalid_ltd.co.zz	!invalid_tld

www.invalid_ltd.notword	!invalid_tld
www.invalid_ltd.invalid	!invalid_tld
www.invalid_ltd.xyzzy	!invalid_tld
www.invalid_ltd.co.zz	!invalid_tld

# underscores allowed, but not at 1st-2nd level
uctest.zyb2n2ef.c_om	!zyb2n2ef
uctest.zyb2_n2ef.com	!zyb2_n2ef
uc_test.u8uwe8qu.com	^http://uc_test\.u8uwe8qu\.com

# invalid hostnames with -
http://-sdfisiz2e.com	!sdfisiz2e
ESRYnSeM7s-.com		!ESRYnSeM7s
foo-.CgPcASgHNa.com	!CgPcASgHNa

# valid hostnames with -
www.eZxdy-TWA4z.com	^http://www\.eZxdy-TWA4z\.com
www-3.WV7jujA10G.com	^http://www-3\.WV7jujA10G\.com

command.com		command\.com
cmd.exe			!cmd\.exe

commander		!commander
aaacomaaa		!aaacomaaa
com.foo.web		!com\.foo\.web

# IPs for www.yahoo.com
66.94.230.32		!66\.94\.230\.32
http://66.94.230.33	^http://66\.94\.230\.33
http://1113515555	^http://66\.94\.230\.35

gooboo4k@xieyohy0.com		^mailto:gooboo4k\@xieyohy0\.com
mailto:baeb1fai@quo6puyo.com	^mailto:baeb1fai\@quo6puyo\.com

http://www.luzoop5k.com		^http://www\.luzoop5k\.com
https://www.luzoop5k.com	^https://www\.luzoop5k\.com
ftp://www.luzoop5k.com		^ftp://www\.luzoop5k\.com

Mailto:aaeb1fai@quo6puyo.com	^Mailto:aaeb1fai\@quo6puyo\.com
Http://www.auzoop5k.com		^Http://www\.auzoop5k\.com
Https://www.auzoop5k.com	^Https://www\.auzoop5k\.com
Ftp://www.auzoop5k.com		^Ftp://www\.auzoop5k\.com

mailto:www.luzoop5k.com		!^mailto:www\.luzoop5k\.com
# no longer accept file: scheme
file://www.luzoop5k.com		!^file://www\.luzoop5k\.com

# //<user>:<password>@<host>:<port>/<url-path>
http://user:pass@jiefeet4.com:80/x/y	^http://user:pass\@jiefeet4\.com:80/x/y

www.liy8quei:80				www\.liy8quei\.com
www.veibi6cu:443			!veibi6cu
www.puahi9si.com:80			puahi9si\.com:80
www.puahi9si2.com:80			puahi9si2\.com$
www.chop9tan.com:443			chop9tan\.com:443

ftp://name@su5queib.ca//etc/motd	^ftp://name\@su5queib\.ca//etc/motd
ftp://name@faikaj4t.dom/%2Fetc/motd	!^ftp://name\@faikaj4t\.dom//etc/motd
ftp://name@faikaj4t.com/%2Fetc/motd	^ftp://name\@faikaj4t\.com//etc/motd

keyword:sportscar			!sportscar

# questionable tests
mailto://cah3neun@thaihe4d.com		^mailto://cah3neun\@thaihe4d\.com

mailto://jicu8vah@another@jicu8vah	!jicu8vah\@another\@jicu8vah
baeb1fai@@example.com			!baeb1fai\@\@example\.com
mailto://yie6xuna			!yie6xuna
mailto://yie6xuna@nottld		!yie6xuna\@nottld

<sentto-4934-foo=addr.com@verper.com>	!^http://.*addr\.com\@verper\.com
<sentto-4934-foo=addr.com@verper.com>	^mailto:sentto-4934-foo=addr\.com\@verper\.com

http://foo23498.com/{ESC}(B	^http://foo23498\.com/$
{ESC}(Bhttp://foo23499.com/	^http://foo23499\.com/$
http://foo23500.com{ESC}(B/	^http://foo23500\.com(?:/?)$

M0"-AE/9Y.KN:_0D2F:95^H*:I,8	!9Y\.KN
>delimtest1.com	^http://delimtest1\.com
<delimtest2.com	^http://delimtest2\.com
"delimtest3.com	^http://delimtest3\.com
\delimtest4.com	^http://delimtest4\.com
'delimtest5.com	^http://delimtest5\.com
`delimtest6.com	^http://delimtest6\.com
,delimtest7.com	^http://delimtest7\.com
{delimtest8.com	^http://delimtest8\.com
[delimtest9.com	^http://delimtest9\.com
(delimtest10.com	^http://delimtest10\.com
|delimtest11.com	^http://delimtest11\.com
 delimtest12.com	^http://delimtest12\.com
ignorethishttp://delimtest13.org	^http://delimtest13\.org
donotignorethiswww.delimtest14.com	donotignorethiswww\.delimtest14\.com
<www.delimtest15.com/foo-~!@#^&*()_+=:;'?,.xyz-~!@#^&*()_+=:;'?,.>	^http://www\.delimtest15\.com/foo-~!\@#\^&\*\(\)_\+=:;'\?,\.xyz$
.....www.delimtest16.com..........	^http://www\.delimtest16\.com$
-----www.delimtest17.com----------	^http://www\.delimtest17\.com$
.....http://www.delimtest18.com..........	^http://www\.delimtest18\.com$
-----http://www.delimtest19.com----------	^http://www\.delimtest19\.com$

# emails with a comma at the end
test@delimtest20.com,stuff stuff		delimtest20\.com

# check some TLDs, no point testing all here
# the inactive TLDs have negative checks

# first confirm that it will not match on not a TLD
example.invalid	!^http://example\.invalid$
example.zzf	!^http://example\.zzf$

example.ac	^http://example\.ac$
example.eu	^http://example\.eu$
example.fi	^http://example\.fi$
example.tp	!^http://example\.tp$
example.travel	^http://example\.travel$
example.um	!^http://example\.um$
example.us	^http://example\.us$

# with www. prefix tests a different table of TLDs

www.example.foo	^http://www\.example\.foo$
www.example.zzf	!^http://www\.example\.zzf$

www.example.ac	^http://www\.example\.ac$
www.example.an	!^http://www\.example\.an$
www.example.ao	^http://www\.example\.ao$
www.example.arpa	^http://www\.example\.arpa$
www.example.ci	^http://www\.example\.ci$
www.example.edu	^http://www\.example\.edu$
www.example.tp	!^http://www\.example\.tp$
www.example.ws	^http://www\.example\.ws$
www.example.yu	!^http://www\.example\.yu$
www.example.za	^http://www\.example\.za$
