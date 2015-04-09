#!/usr/bin/perl -w

# test URIs as grabbed from text/plain messages

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
use SATest; sa_t_init("uri_text");
use Test;
use Mail::SpamAssassin;
use vars qw(%patterns %anti_patterns);

# settings
plan tests => 683;

# initialize SpamAssassin
my $sa = create_saobj({dont_copy_prefs => 1});

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
xyz.geifoza1.com/..xyz	xyz\.geifoza1\.com	!xyz\.geifoza1\.com/\.\.xyz
xyz.geifoza2.CoM	xyz\.geifoza2\.CoM
http://xyz..geifoza3.com	!geifoza3
http://xyz.geifoza4.com/..xyz	xyz\.geifoza4\.com/\.\.xyz
http://xyz.geifoza5.CoM	xyz\.geifoza5\.CoM

joe@koja3fui.koja3fui	!koja3fui

<xuq@dsj.x.thriyi.com>	mailto:xuq\@dsj\.x\.thriyi\.com	!http\S*thriyi

http://www.example.com/about/wahfah7d.html	wahfah7d
http://www.example.com?xa1kaLuo			\?xa1kaLuo
http://www.lap7thob.com/			^http://www\.lap7thob\.com/$

www.phoh1Koh.com/			^www\.phoh1Koh\.com/$
www.Tar4caeg.com:80			http://www\.Tar4caeg\.com:80
www.Coo4mowe.com:80/foo/foo.html	^www\.Coo4mowe\.com:80/foo/foo\.html
www.Nee2quae.com:80/			^www\.Nee2quae\.com:80/$

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

www.Chiew0ch.COM	www\.Chiew0ch\.COM
www.thohY2qu.US		www\.thohY2qu\.US
www.teiP7gei.BIZ	www\.teiP7gei\.BIZ
www.xohThai8.INFO	www\.xohThai8\.INFO
www.haik7Ram.NET	www\.haik7Ram\.NET
www.Quaes3se.ORG	www\.Quaes3se\.ORG
www.Chai6tah.WS		www\.Chai6tah\.WS
www.Thuoth1y.NAME	www\.Thuoth1y\.NAME
www.Chieb8ge.TV		www\.Chieb8ge\.TV
WWW.quus4Rok.cc		WWW\.quus4Rok\.cc
WWW.maic6Hei.de		WWW\.maic6Hei\.de
WWW.he4Hiize.jp		WWW\.he4Hiize\.jp
WWW.Soh1toob.be		WWW\.Soh1toob\.be
WWW.chahMee5.at		WWW\.chahMee5\.at
WWW.peepooN0.uk		WWW\.peepooN0\.uk
WWW.Kiox3phi.nz		WWW\.Kiox3phi\.nz
WWW.jong3Xou.cn		WWW\.jong3Xou\.cn
WWW.waeShoe0.tw		WWW\.waeShoe0\.tw

invalid_ltd.notword	!invalid_tld
invalid_ltd.invalid	!invalid_tld
invalid_ltd.xyzzy	!invalid_tld
invalid_ltd.co.zz	!invalid_tld

www.invalid_ltd.notword	!invalid_tld
www.invalid_ltd.invalid	!invalid_tld
www.invalid_ltd.xyzzy	!invalid_tld
www.invalid_ltd.co.zz	!invalid_tld

command.com		command\.com
cmd.exe			!cmd\.exe

commander		!commander
aaacomaaa		!aaacomaaa
aaa.com.aaa		!aaa\.com\.aaa
com.foo.web		!com\.foo\.web

# IPs for www.yahoo.com
66.94.230.32		!66\.94\.230\.32
http://66.94.230.33	http://66\.94\.230\.33
http://1113515555	http://66\.94\.230\.35

gooboo4k@xieyohy0.com		mailto:gooboo4k\@xieyohy0\.com
mailto:baeb1fai@quo6puyo.com	mailto:baeb1fai\@quo6puyo\.com

http://www.luzoop5k.com		http://www\.luzoop5k\.com
https://www.luzoop5k.com	https://www\.luzoop5k\.com
ftp://www.luzoop5k.com		ftp://www\.luzoop5k\.com

Mailto:aaeb1fai@quo6puyo.com	Mailto:aaeb1fai\@quo6puyo\.com
Http://www.auzoop5k.com		Http://www\.auzoop5k\.com
Https://www.auzoop5k.com	Https://www\.auzoop5k\.com
Ftp://www.auzoop5k.com		Ftp://www\.auzoop5k\.com

mailto:www.luzoop5k.com		!mailto:www\.luzoop5k\.com
# no longer accept file: scheme
file://www.luzoop5k.com		!file://www\.luzoop5k\.com

# //<user>:<password>@<host>:<port>/<url-path>
http://user:pass@jiefeet4.com:80/x/y	http://user:pass\@jiefeet4\.com:80/x/y

www.liy8quei:80				!liy8quei
www.veibi6cu:443			!veibi6cu
puahi8si.com:80				!puahi8si\.com:80
chop8tan.com:443			!chop8tan\.com:443
www.puahi9si.com:80		puahi9si\.com:80
www.chop9tan.com:443	chop9tan\.com:443

ftp://name@su5queib.ca//etc/motd	ftp://name\@su5queib\.ca//etc/motd
ftp://name@faikaj4t.dom/%2Fetc/motd	!ftp://name\@faikaj4t\.dom//etc/motd
ftp://name@faikaj4t.com/%2Fetc/motd	ftp://name\@faikaj4t\.com//etc/motd

keyword:sportscar		!sportscar

# questionable tests
mailto://cah3neun@thaihe4d.com		mailto://cah3neun\@thaihe4d\.com

mailto://jicu8vah@another@jicu8vah	!jicu8vah\@another\@jicu8vah
baeb1fai@@example.com			!baeb1fai\@\@example\.com
mailto://yie6xuna		!yie6xuna
mailto://yie6xuna@nottld		!yie6xuna\@nottld

<sentto-4934-foo=addr.com@verper.com>	!^http://.*addr\.com\@verper\.com
<sentto-4934-foo=addr.com@verper.com>	mailto:sentto-4934-foo=addr\.com\@verper\.com

http://foo23498.com/{ESC}(B	^http://foo23498\.com/$
{ESC}(Bhttp://foo23499.com/	^http://foo23499\.com/$
http://foo23500.com{ESC}(B/	^http://foo23500\.com(?:/?)$

M0"-AE/9Y.KN:_0D2F:95^H*:I,8	!9Y\.KN
>delimtest1.com	http://delimtest1\.com
<delimtest2.com	http://delimtest2\.com
"delimtest3.com	http://delimtest3\.com
\delimtest4.com	http://delimtest4\.com
'delimtest5.com	http://delimtest5\.com
`delimtest6.com	http://delimtest6\.com
,delimtest7.com	http://delimtest7\.com
{delimtest8.com	http://delimtest8\.com
[delimtest9.com	http://delimtest9\.com
(delimtest10.com	http://delimtest10\.com
|delimtest11.com	http://delimtest11\.com
 delimtest12.com	http://delimtest12\.com
ignorethishttp://delimtest13.org	http://delimtest13\.org
donotignorethiswww.delimtest14.com	donotignorethiswww\.delimtest14\.com
<www.delimtest15.com/foo-~!@#^&*()_+=:;'?,.xyz-~!@#^&*()_+=:;'?,.>	^http://www\.delimtest15\.com/foo-~!\@#\^&\*\(\)_\+=:;'\?,\.xyz$
.....www.delimtest16.com..........	^http://www\.delimtest16\.com$
-----www.delimtest17.com----------	^http://www\.delimtest17\.com$
.....http://www.delimtest18.com..........	^http://www\.delimtest18\.com$
-----http://www.delimtest19.com----------	^http://www\.delimtest19\.com$

# emails with a comma at the end
test@delimtest20.com,stuff stuff		delimtest20\.com

# check all the TLDs (might as well be thorough)
# the inactive TLDs have negative checks

# first confirm that it will not match on not a TLD
example.invalid	!^http://example\.invalid$
example.zzf	!^http://example\.zzf$

example.ac	^http://example\.ac$
example.ad	^http://example\.ad$
example.ae	^http://example\.ae$
example.aero	^http://example\.aero$
example.af	^http://example\.af$
example.ag	^http://example\.ag$
example.ai	^http://example\.ai$
example.al	^http://example\.al$
example.am	^http://example\.am$
example.an	^http://example\.an$
example.ao	^http://example\.ao$
example.aq	^http://example\.aq$
example.ar	^http://example\.ar$
example.arpa	^http://example\.arpa$
example.as	^http://example\.as$
example.asia	^http://example\.asia$
example.at	^http://example\.at$
example.au	^http://example\.au$
example.aw	^http://example\.aw$
example.ax	^http://example\.ax$
example.az	^http://example\.az$
example.ba	^http://example\.ba$
example.bb	^http://example\.bb$
example.bd	^http://example\.bd$
example.be	^http://example\.be$
example.bf	^http://example\.bf$
example.bg	^http://example\.bg$
example.bh	^http://example\.bh$
example.bi	^http://example\.bi$
example.biz	^http://example\.biz$
example.bj	^http://example\.bj$
example.bm	^http://example\.bm$
example.bn	^http://example\.bn$
example.bo	^http://example\.bo$
example.br	^http://example\.br$
example.bs	^http://example\.bs$
example.bt	^http://example\.bt$
example.bv	^http://example\.bv$
example.bw	^http://example\.bw$
example.by	^http://example\.by$
example.bz	^http://example\.bz$
example.ca	^http://example\.ca$
example.cat	^http://example\.cat$
example.cc	^http://example\.cc$
example.cd	^http://example\.cd$
example.cf	^http://example\.cf$
example.cg	^http://example\.cg$
example.ch	^http://example\.ch$
example.ci	^http://example\.ci$
example.ck	^http://example\.ck$
example.cl	^http://example\.cl$
example.cm	^http://example\.cm$
example.cn	^http://example\.cn$
example.co	^http://example\.co$
example.com	^http://example\.com$
example.coop	^http://example\.coop$
example.cr	^http://example\.cr$
example.cu	^http://example\.cu$
example.cv	^http://example\.cv$
example.cx	^http://example\.cx$
example.cy	^http://example\.cy$
example.cz	^http://example\.cz$
example.de	^http://example\.de$
example.dj	^http://example\.dj$
example.dk	^http://example\.dk$
example.dm	^http://example\.dm$
example.do	^http://example\.do$
example.dz	^http://example\.dz$
example.ec	^http://example\.ec$
example.edu	^http://example\.edu$
example.ee	^http://example\.ee$
example.eg	^http://example\.eg$
example.er	^http://example\.er$
example.es	^http://example\.es$
example.et	^http://example\.et$
example.eu	^http://example\.eu$
example.fi	^http://example\.fi$
example.fj	^http://example\.fj$
example.fk	^http://example\.fk$
example.fm	^http://example\.fm$
example.fo	^http://example\.fo$
example.fr	^http://example\.fr$
example.ga	^http://example\.ga$
example.gb	^http://example\.gb$
example.gd	^http://example\.gd$
example.ge	^http://example\.ge$
example.gf	^http://example\.gf$
example.gg	^http://example\.gg$
example.gh	^http://example\.gh$
example.gi	^http://example\.gi$
example.gl	^http://example\.gl$
example.gm	^http://example\.gm$
example.gn	^http://example\.gn$
example.gov	^http://example\.gov$
example.gp	^http://example\.gp$
example.gq	^http://example\.gq$
example.gr	^http://example\.gr$
example.gs	^http://example\.gs$
example.gt	^http://example\.gt$
example.gu	^http://example\.gu$
example.gw	^http://example\.gw$
example.gy	^http://example\.gy$
example.hk	^http://example\.hk$
example.hm	^http://example\.hm$
example.hn	^http://example\.hn$
example.hr	^http://example\.hr$
example.ht	^http://example\.ht$
example.hu	^http://example\.hu$
example.id	^http://example\.id$
example.ie	^http://example\.ie$
example.il	^http://example\.il$
example.im	^http://example\.im$
example.in	^http://example\.in$
example.info	^http://example\.info$
example.int	^http://example\.int$
example.io	^http://example\.io$
example.iq	^http://example\.iq$
example.ir	^http://example\.ir$
example.is	^http://example\.is$
example.it	^http://example\.it$
example.je	^http://example\.je$
example.jm	^http://example\.jm$
example.jo	^http://example\.jo$
example.jobs	^http://example\.jobs$
example.jp	^http://example\.jp$
example.ke	^http://example\.ke$
example.kg	^http://example\.kg$
example.kh	^http://example\.kh$
example.ki	^http://example\.ki$
example.km	^http://example\.km$
example.kn	^http://example\.kn$
example.kp	^http://example\.kp$
example.kr	^http://example\.kr$
example.kw	^http://example\.kw$
example.ky	^http://example\.ky$
example.kz	^http://example\.kz$
example.la	^http://example\.la$
example.lb	^http://example\.lb$
example.lc	^http://example\.lc$
example.li	^http://example\.li$
example.lk	^http://example\.lk$
example.lr	^http://example\.lr$
example.ls	^http://example\.ls$
example.lt	^http://example\.lt$
example.lu	^http://example\.lu$
example.lv	^http://example\.lv$
example.ly	^http://example\.ly$
example.ma	^http://example\.ma$
example.mc	^http://example\.mc$
example.md	^http://example\.md$
example.me	^http://example\.me$
example.mg	^http://example\.mg$
example.mh	^http://example\.mh$
example.mil	^http://example\.mil$
example.mk	^http://example\.mk$
example.ml	^http://example\.ml$
example.mm	^http://example\.mm$
example.mn	^http://example\.mn$
example.mo	^http://example\.mo$
example.mobi	^http://example\.mobi$
example.mp	^http://example\.mp$
example.mq	^http://example\.mq$
example.mr	^http://example\.mr$
example.ms	^http://example\.ms$
example.mt	^http://example\.mt$
example.mu	^http://example\.mu$
example.museum	^http://example\.museum$
example.mv	^http://example\.mv$
example.mw	^http://example\.mw$
example.mx	^http://example\.mx$
example.my	^http://example\.my$
example.mz	^http://example\.mz$
example.na	^http://example\.na$
example.name	^http://example\.name$
example.nc	^http://example\.nc$
example.ne	^http://example\.ne$
example.net	^http://example\.net$
example.nf	^http://example\.nf$
example.ng	^http://example\.ng$
example.ni	^http://example\.ni$
example.nl	^http://example\.nl$
example.no	^http://example\.no$
example.np	^http://example\.np$
example.nr	^http://example\.nr$
example.nu	^http://example\.nu$
example.nz	^http://example\.nz$
example.om	^http://example\.om$
example.org	^http://example\.org$
example.pa	^http://example\.pa$
example.pe	^http://example\.pe$
example.pf	^http://example\.pf$
example.pg	^http://example\.pg$
example.ph	^http://example\.ph$
example.pk	^http://example\.pk$
example.pl	^http://example\.pl$
example.pm	^http://example\.pm$
example.pn	^http://example\.pn$
example.pr	^http://example\.pr$
example.pro	^http://example\.pro$
example.ps	^http://example\.ps$
example.pt	^http://example\.pt$
example.pw	^http://example\.pw$
example.py	^http://example\.py$
example.qa	^http://example\.qa$
example.re	^http://example\.re$
example.ro	^http://example\.ro$
example.rs	^http://example\.rs$
example.ru	^http://example\.ru$
example.rw	^http://example\.rw$
example.sa	^http://example\.sa$
example.sb	^http://example\.sb$
example.sc	^http://example\.sc$
example.sd	^http://example\.sd$
example.se	^http://example\.se$
example.sg	^http://example\.sg$
example.sh	^http://example\.sh$
example.si	^http://example\.si$
example.sj	^http://example\.sj$
example.sk	^http://example\.sk$
example.sl	^http://example\.sl$
example.sm	^http://example\.sm$
example.sn	^http://example\.sn$
example.so	^http://example\.so$
example.sr	^http://example\.sr$
example.st	^http://example\.st$
example.su	^http://example\.su$
example.sv	^http://example\.sv$
example.sy	^http://example\.sy$
example.sz	^http://example\.sz$
example.tc	^http://example\.tc$
example.td	^http://example\.td$
example.tel	^http://example\.tel$
example.tf	^http://example\.tf$
example.tg	^http://example\.tg$
example.th	^http://example\.th$
example.tj	^http://example\.tj$
example.tk	^http://example\.tk$
example.tl	^http://example\.tl$
example.tm	^http://example\.tm$
example.tn	^http://example\.tn$
example.to	^http://example\.to$
example.tp	!^http://example\.tp$
example.tr	^http://example\.tr$
example.travel	^http://example\.travel$
example.tt	^http://example\.tt$
example.tv	^http://example\.tv$
example.tw	^http://example\.tw$
example.tz	^http://example\.tz$
example.ua	^http://example\.ua$
example.ug	^http://example\.ug$
example.uk	^http://example\.uk$
example.um	!^http://example\.um$
example.us	^http://example\.us$
example.uy	^http://example\.uy$
example.uz	^http://example\.uz$
example.va	^http://example\.va$
example.vc	^http://example\.vc$
example.ve	^http://example\.ve$
example.vg	^http://example\.vg$
example.vi	^http://example\.vi$
example.vn	^http://example\.vn$
example.vu	^http://example\.vu$
example.wf	^http://example\.wf$
example.ws	^http://example\.ws$
example.ye	^http://example\.ye$
example.yt	^http://example\.yt$
example.yu	!^http://example\.yu$
example.za	^http://example\.za$
example.zm	^http://example\.zm$
example.zw	^http://example\.zw$

# with www. prefix tests a different table of TLDs

www.example.foo	^http://www\.example\.foo$
www.example.zzf	!^http://www\.example\.zzf$

www.example.ac	^http://www\.example\.ac$
www.example.ad	^http://www\.example\.ad$
www.example.ae	^http://www\.example\.ae$
www.example.aero	^http://www\.example\.aero$
www.example.af	^http://www\.example\.af$
www.example.ag	^http://www\.example\.ag$
www.example.ai	^http://www\.example\.ai$
www.example.al	^http://www\.example\.al$
www.example.am	^http://www\.example\.am$
www.example.an	^http://www\.example\.an$
www.example.ao	^http://www\.example\.ao$
www.example.aq	^http://www\.example\.aq$
www.example.ar	^http://www\.example\.ar$
www.example.arpa	^http://www\.example\.arpa$
www.example.as	^http://www\.example\.as$
www.example.asia	^http://www\.example\.asia$
www.example.at	^http://www\.example\.at$
www.example.au	^http://www\.example\.au$
www.example.aw	^http://www\.example\.aw$
www.example.ax	^http://www\.example\.ax$
www.example.az	^http://www\.example\.az$
www.example.ba	^http://www\.example\.ba$
www.example.bb	^http://www\.example\.bb$
www.example.bd	^http://www\.example\.bd$
www.example.be	^http://www\.example\.be$
www.example.bf	^http://www\.example\.bf$
www.example.bg	^http://www\.example\.bg$
www.example.bh	^http://www\.example\.bh$
www.example.bi	^http://www\.example\.bi$
www.example.biz	^http://www\.example\.biz$
www.example.bj	^http://www\.example\.bj$
www.example.bm	^http://www\.example\.bm$
www.example.bn	^http://www\.example\.bn$
www.example.bo	^http://www\.example\.bo$
www.example.br	^http://www\.example\.br$
www.example.bs	^http://www\.example\.bs$
www.example.bt	^http://www\.example\.bt$
www.example.bv	^http://www\.example\.bv$
www.example.bw	^http://www\.example\.bw$
www.example.by	^http://www\.example\.by$
www.example.bz	^http://www\.example\.bz$
www.example.ca	^http://www\.example\.ca$
www.example.cat	^http://www\.example\.cat$
www.example.cc	^http://www\.example\.cc$
www.example.cd	^http://www\.example\.cd$
www.example.cf	^http://www\.example\.cf$
www.example.cg	^http://www\.example\.cg$
www.example.ch	^http://www\.example\.ch$
www.example.ci	^http://www\.example\.ci$
www.example.ck	^http://www\.example\.ck$
www.example.cl	^http://www\.example\.cl$
www.example.cm	^http://www\.example\.cm$
www.example.cn	^http://www\.example\.cn$
www.example.co	^http://www\.example\.co$
www.example.com	^http://www\.example\.com$
www.example.coop	^http://www\.example\.coop$
www.example.cr	^http://www\.example\.cr$
www.example.cu	^http://www\.example\.cu$
www.example.cv	^http://www\.example\.cv$
www.example.cx	^http://www\.example\.cx$
www.example.cy	^http://www\.example\.cy$
www.example.cz	^http://www\.example\.cz$
www.example.de	^http://www\.example\.de$
www.example.dj	^http://www\.example\.dj$
www.example.dk	^http://www\.example\.dk$
www.example.dm	^http://www\.example\.dm$
www.example.do	^http://www\.example\.do$
www.example.dz	^http://www\.example\.dz$
www.example.ec	^http://www\.example\.ec$
www.example.edu	^http://www\.example\.edu$
www.example.ee	^http://www\.example\.ee$
www.example.eg	^http://www\.example\.eg$
www.example.er	^http://www\.example\.er$
www.example.es	^http://www\.example\.es$
www.example.et	^http://www\.example\.et$
www.example.eu	^http://www\.example\.eu$
www.example.fi	^http://www\.example\.fi$
www.example.fj	^http://www\.example\.fj$
www.example.fk	^http://www\.example\.fk$
www.example.fm	^http://www\.example\.fm$
www.example.fo	^http://www\.example\.fo$
www.example.fr	^http://www\.example\.fr$
www.example.ga	^http://www\.example\.ga$
www.example.gb	^http://www\.example\.gb$
www.example.gd	^http://www\.example\.gd$
www.example.ge	^http://www\.example\.ge$
www.example.gf	^http://www\.example\.gf$
www.example.gg	^http://www\.example\.gg$
www.example.gh	^http://www\.example\.gh$
www.example.gi	^http://www\.example\.gi$
www.example.gl	^http://www\.example\.gl$
www.example.gm	^http://www\.example\.gm$
www.example.gn	^http://www\.example\.gn$
www.example.gov	^http://www\.example\.gov$
www.example.gp	^http://www\.example\.gp$
www.example.gq	^http://www\.example\.gq$
www.example.gr	^http://www\.example\.gr$
www.example.gs	^http://www\.example\.gs$
www.example.gt	^http://www\.example\.gt$
www.example.gu	^http://www\.example\.gu$
www.example.gw	^http://www\.example\.gw$
www.example.gy	^http://www\.example\.gy$
www.example.hk	^http://www\.example\.hk$
www.example.hm	^http://www\.example\.hm$
www.example.hn	^http://www\.example\.hn$
www.example.hr	^http://www\.example\.hr$
www.example.ht	^http://www\.example\.ht$
www.example.hu	^http://www\.example\.hu$
www.example.id	^http://www\.example\.id$
www.example.ie	^http://www\.example\.ie$
www.example.il	^http://www\.example\.il$
www.example.im	^http://www\.example\.im$
www.example.in	^http://www\.example\.in$
www.example.info	^http://www\.example\.info$
www.example.int	^http://www\.example\.int$
www.example.io	^http://www\.example\.io$
www.example.iq	^http://www\.example\.iq$
www.example.ir	^http://www\.example\.ir$
www.example.is	^http://www\.example\.is$
www.example.it	^http://www\.example\.it$
www.example.je	^http://www\.example\.je$
www.example.jm	^http://www\.example\.jm$
www.example.jo	^http://www\.example\.jo$
www.example.jobs	^http://www\.example\.jobs$
www.example.jp	^http://www\.example\.jp$
www.example.ke	^http://www\.example\.ke$
www.example.kg	^http://www\.example\.kg$
www.example.kh	^http://www\.example\.kh$
www.example.ki	^http://www\.example\.ki$
www.example.km	^http://www\.example\.km$
www.example.kn	^http://www\.example\.kn$
www.example.kp	^http://www\.example\.kp$
www.example.kr	^http://www\.example\.kr$
www.example.kw	^http://www\.example\.kw$
www.example.ky	^http://www\.example\.ky$
www.example.kz	^http://www\.example\.kz$
www.example.la	^http://www\.example\.la$
www.example.lb	^http://www\.example\.lb$
www.example.lc	^http://www\.example\.lc$
www.example.li	^http://www\.example\.li$
www.example.lk	^http://www\.example\.lk$
www.example.lr	^http://www\.example\.lr$
www.example.ls	^http://www\.example\.ls$
www.example.lt	^http://www\.example\.lt$
www.example.lu	^http://www\.example\.lu$
www.example.lv	^http://www\.example\.lv$
www.example.ly	^http://www\.example\.ly$
www.example.ma	^http://www\.example\.ma$
www.example.mc	^http://www\.example\.mc$
www.example.md	^http://www\.example\.md$
www.example.me	^http://www\.example\.me$
www.example.mg	^http://www\.example\.mg$
www.example.mh	^http://www\.example\.mh$
www.example.mil	^http://www\.example\.mil$
www.example.mk	^http://www\.example\.mk$
www.example.ml	^http://www\.example\.ml$
www.example.mm	^http://www\.example\.mm$
www.example.mn	^http://www\.example\.mn$
www.example.mo	^http://www\.example\.mo$
www.example.mobi	^http://www\.example\.mobi$
www.example.mp	^http://www\.example\.mp$
www.example.mq	^http://www\.example\.mq$
www.example.mr	^http://www\.example\.mr$
www.example.ms	^http://www\.example\.ms$
www.example.mt	^http://www\.example\.mt$
www.example.mu	^http://www\.example\.mu$
www.example.museum	^http://www\.example\.museum$
www.example.mv	^http://www\.example\.mv$
www.example.mw	^http://www\.example\.mw$
www.example.mx	^http://www\.example\.mx$
www.example.my	^http://www\.example\.my$
www.example.mz	^http://www\.example\.mz$
www.example.na	^http://www\.example\.na$
www.example.name	^http://www\.example\.name$
www.example.nc	^http://www\.example\.nc$
www.example.ne	^http://www\.example\.ne$
www.example.net	^http://www\.example\.net$
www.example.nf	^http://www\.example\.nf$
www.example.ng	^http://www\.example\.ng$
www.example.ni	^http://www\.example\.ni$
www.example.nl	^http://www\.example\.nl$
www.example.no	^http://www\.example\.no$
www.example.np	^http://www\.example\.np$
www.example.nr	^http://www\.example\.nr$
www.example.nu	^http://www\.example\.nu$
www.example.nz	^http://www\.example\.nz$
www.example.om	^http://www\.example\.om$
www.example.org	^http://www\.example\.org$
www.example.pa	^http://www\.example\.pa$
www.example.pe	^http://www\.example\.pe$
www.example.pf	^http://www\.example\.pf$
www.example.pg	^http://www\.example\.pg$
www.example.ph	^http://www\.example\.ph$
www.example.pk	^http://www\.example\.pk$
www.example.pl	^http://www\.example\.pl$
www.example.pm	^http://www\.example\.pm$
www.example.pn	^http://www\.example\.pn$
www.example.pr	^http://www\.example\.pr$
www.example.pro	^http://www\.example\.pro$
www.example.ps	^http://www\.example\.ps$
www.example.pt	^http://www\.example\.pt$
www.example.pw	^http://www\.example\.pw$
www.example.py	^http://www\.example\.py$
www.example.qa	^http://www\.example\.qa$
www.example.re	^http://www\.example\.re$
www.example.ro	^http://www\.example\.ro$
www.example.rs	^http://www\.example\.rs$
www.example.ru	^http://www\.example\.ru$
www.example.rw	^http://www\.example\.rw$
www.example.sa	^http://www\.example\.sa$
www.example.sb	^http://www\.example\.sb$
www.example.sc	^http://www\.example\.sc$
www.example.sd	^http://www\.example\.sd$
www.example.se	^http://www\.example\.se$
www.example.sg	^http://www\.example\.sg$
www.example.sh	^http://www\.example\.sh$
www.example.si	^http://www\.example\.si$
www.example.sj	^http://www\.example\.sj$
www.example.sk	^http://www\.example\.sk$
www.example.sl	^http://www\.example\.sl$
www.example.sm	^http://www\.example\.sm$
www.example.sn	^http://www\.example\.sn$
www.example.so	^http://www\.example\.so$
www.example.sr	^http://www\.example\.sr$
www.example.st	^http://www\.example\.st$
www.example.su	^http://www\.example\.su$
www.example.sv	^http://www\.example\.sv$
www.example.sy	^http://www\.example\.sy$
www.example.sz	^http://www\.example\.sz$
www.example.tc	^http://www\.example\.tc$
www.example.td	^http://www\.example\.td$
www.example.tel	^http://www\.example\.tel$
www.example.tf	^http://www\.example\.tf$
www.example.tg	^http://www\.example\.tg$
www.example.th	^http://www\.example\.th$
www.example.tj	^http://www\.example\.tj$
www.example.tk	^http://www\.example\.tk$
www.example.tl	^http://www\.example\.tl$
www.example.tm	^http://www\.example\.tm$
www.example.tn	^http://www\.example\.tn$
www.example.to	^http://www\.example\.to$
www.example.tp	!^http://www\.example\.tp$
www.example.tr	^http://www\.example\.tr$
www.example.travel	^http://www\.example\.travel$
www.example.tt	^http://www\.example\.tt$
www.example.tv	^http://www\.example\.tv$
www.example.tw	^http://www\.example\.tw$
www.example.tz	^http://www\.example\.tz$
www.example.ua	^http://www\.example\.ua$
www.example.ug	^http://www\.example\.ug$
www.example.uk	^http://www\.example\.uk$
www.example.um	!^http://www\.example\.um$
www.example.us	^http://www\.example\.us$
www.example.uy	^http://www\.example\.uy$
www.example.uz	^http://www\.example\.uz$
www.example.va	^http://www\.example\.va$
www.example.vc	^http://www\.example\.vc$
www.example.ve	^http://www\.example\.ve$
www.example.vg	^http://www\.example\.vg$
www.example.vi	^http://www\.example\.vi$
www.example.vn	^http://www\.example\.vn$
www.example.vu	^http://www\.example\.vu$
www.example.wf	^http://www\.example\.wf$
www.example.ws	^http://www\.example\.ws$
www.example.ye	^http://www\.example\.ye$
www.example.yt	^http://www\.example\.yt$
www.example.yu	!^http://www\.example\.yu$
www.example.za	^http://www\.example\.za$
www.example.zm	^http://www\.example\.zm$
www.example.zw	^http://www\.example\.zw$
