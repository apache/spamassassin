# The (extremely complex) rules for domain delegation.
# Note that really, this should be called "RegistryBoundaries"; see bug 4605

# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Util::RegistrarBoundaries;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw (
  @ISA %TWO_LEVEL_DOMAINS %THREE_LEVEL_DOMAINS %US_STATES %VALID_TLDS
);

# The list of currently-valid TLDs for the DNS system.
#
# http://data.iana.org/TLD/tlds-alpha-by-domain.txt
# Version 2008020601, Last Updated Thu Feb  7 09:07:00 2008 UTC
# The following have been removed from the list because they are
# inactive, as can be seen in the Wikipedia articles about them
# as of 2008-02-08, e.g. http://en.wikipedia.org/wiki/.so_%28domain_name%29
#     bv gb pm sj so um yt

foreach (qw/
  ac ad ae aero af ag ai al am an ao aq ar arpa as asia at au aw ax az
  ba bb bd be bf bg bh bi biz bj bm bn bo br bs bt bw by bz ca cat cc
  cd cf cg ch ci ck cl cm cn co com coop cr cu cv cx cy cz de dj dk dm
  do dz ec edu ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh
  gi gl gm gn gov gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im
  in info int io iq ir is it je jm jo jobs jp ke kg kh ki km kn kp kr kw
  ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mil mk ml mm
  mn mo mobi mp mq mr ms mt mu museum mv mw mx my mz na name nc ne net
  nf ng ni nl no np nr nu nz om org pa pe pf pg ph pk pl pn pr pro ps
  pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn
  sr st su sv sy sz tc td tel tf tg th tj tk tl tm tn to tp tr travel tt
  tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yu za
  zm zw
  /) { 
  $VALID_TLDS{$_} = 1;
}

# to resort this, pump the whole list through:
#  perl -e '$/=undef; $_=<>; foreach(split) { ($a,$b) = split(/\./, $_, 2); $t{$b}->{$_}=1; } foreach (sort keys %t) { print "  ",join(" ", sort keys %{$t{$_}}),"\n" }'
#
# http://www.neustar.us/policies/docs/rfc_1480.txt
# data originally from http://spamcheck.freeapp.net/two-level-tlds
# The freeapp.net site now says that information on the site is obsolete
# See discussion and sources in comments of bug 5677
# updated as per bug 5815
foreach(qw/

  com.ac edu.ac gov.ac mil.ac net.ac org.ac
  nom.ad
  ac.ae co.ae com.ae gov.ae mil.ae name.ae net.ae org.ae pro.ae sch.ae
  com.af edu.af gov.af net.af
  co.ag com.ag net.ag nom.ag org.ag
  com.ai edu.ai gov.ai net.ai off.ai org.ai
  com.al edu.al gov.al net.al org.al
  com.an edu.an net.an org.an
  co.ao ed.ao gv.ao it.ao og.ao pb.ao
  com.ar edu.ar gov.ar int.ar mil.ar net.ar org.ar
  e164.arpa in-addr.arpa ip6.arpa iris.arpa uri.arpa urn.arpa
  ac.at co.at gv.at or.at priv.at
  act.au asn.au com.au conf.au csiro.au edu.au gov.au id.au info.au net.au nsw.au nt.au org.au otc.au oz.au qld.au sa.au tas.au telememo.au vic.au wa.au
  com.aw
  biz.az com.az edu.az gov.az info.az int.az mil.az name.az net.az org.az pp.az
  co.ba com.ba edu.ba gov.ba mil.ba net.ba org.ba rs.ba unbi.ba unsa.ba
  com.bb edu.bb gov.bb net.bb org.bb
  ac.bd com.bd edu.bd gov.bd mil.bd net.bd org.bd
  ac.be belgie.be dns.be fgov.be
  gov.bf
  biz.bh cc.bh com.bh edu.bh gov.bh info.bh net.bh org.bh
  com.bm edu.bm gov.bm net.bm org.bm
  com.bn edu.bn net.bn org.bn
  com.bo edu.bo gob.bo gov.bo int.bo mil.bo net.bo org.bo tv.bo
  adm.br adv.br agr.br am.br arq.br art.br ato.br bio.br bmd.br cim.br cng.br cnt.br com.br coop.br dpn.br ecn.br edu.br eng.br esp.br etc.br eti.br far.br fm.br fnd.br fot.br fst.br g12.br ggf.br gov.br imb.br ind.br inf.br jor.br lel.br mat.br med.br mil.br mus.br net.br nom.br not.br ntr.br odo.br org.br ppg.br pro.br psc.br psi.br qsl.br rec.br slg.br srv.br tmp.br trd.br tur.br tv.br vet.br zlg.br
  com.bs net.bs org.bs
  com.bt edu.bt gov.bt net.bt org.bt
  co.bw org.bw
  gov.by mil.by
  com.bz net.bz org.bz
  ab.ca bc.ca gc.ca mb.ca nb.ca nf.ca nl.ca ns.ca nt.ca nu.ca on.ca pe.ca qc.ca sk.ca yk.ca
  co.ck edu.ck gov.ck net.ck org.ck
  ac.cn ah.cn bj.cn com.cn cq.cn edu.cn fj.cn gd.cn gov.cn gs.cn gx.cn gz.cn ha.cn hb.cn he.cn hi.cn hk.cn hl.cn hn.cn jl.cn js.cn jx.cn ln.cn mo.cn net.cn nm.cn nx.cn org.cn qh.cn sc.cn sd.cn sh.cn sn.cn sx.cn tj.cn tw.cn xj.cn xz.cn yn.cn zj.cn
  arts.co com.co edu.co firm.co gov.co info.co int.co mil.co net.co nom.co org.co rec.co store.co web.co
  lkd.co.im ltd.co.im plc.co.im
  au.com br.com cn.com de.com eu.com gb.com hu.com no.com qc.com ru.com sa.com se.com uk.com us.com uy.com za.com
  ac.cr co.cr ed.cr fi.cr go.cr or.cr sa.cr
  com.cu edu.cu gov.cu inf.cu net.cu org.cu
  gov.cx
  ac.cy biz.cy com.cy ekloges.cy gov.cy ltd.cy name.cy net.cy org.cy parliament.cy press.cy pro.cy tm.cy
  co.dk
  com.dm edu.dm gov.dm net.dm org.dm
  art.do com.do edu.do gob.do gov.do mil.do net.do org.do sld.do web.do
  art.dz asso.dz com.dz edu.dz gov.dz net.dz org.dz pol.dz
  com.ec edu.ec fin.ec gov.ec info.ec k12.ec med.ec mil.ec net.ec org.ec pro.ec
  co.ee com.ee edu.ee fie.ee med.ee org.ee pri.ee
  com.eg edu.eg eun.eg gov.eg mil.eg net.eg org.eg sci.eg
  com.er edu.er gov.er ind.er mil.er net.er org.er
  com.es edu.es gob.es nom.es org.es
  biz.et com.et edu.et gov.et info.et name.et net.et org.et
  aland.fi
  ac.fj biz.fj com.fj gov.fj id.fj info.fj mil.fj name.fj net.fj org.fj pro.fj school.fj
  ac.fk co.fk com.fk gov.fk net.fk nom.fk org.fk
  aeroport.fr assedic.fr asso.fr avocat.fr avoues.fr barreau.fr cci.fr chambagri.fr chirurgiens-dentistes.fr com.fr experts-comptables.fr geometre-expert.fr gouv.fr greta.fr huissier-justice.fr medecin.fr nom.fr notaires.fr pharmacien.fr port.fr prd.fr presse.fr tm.fr veterinaire.fr
  com.ge edu.ge gov.ge mil.ge net.ge org.ge pvt.ge
  ac.gg alderney.gg co.gg gov.gg guernsey.gg ind.gg ltd.gg net.gg org.gg sark.gg sch.gg
  com.gh edu.gh gov.gh mil.gh org.gh
  com.gi edu.gi gov.gi ltd.gi mod.gi org.gi
  ac.gn com.gn gov.gn net.gn org.gn
  asso.gp com.gp edu.gp net.gp org.gp
  com.gr edu.gr gov.gr net.gr org.gr
  com.gt edu.gt gob.gt ind.gt mil.gt net.gt org.gt
  com.gu edu.gu gov.gu mil.gu net.gu org.gu
  com.hk edu.hk gov.hk idv.hk net.hk org.hk
  com.hn edu.hn gob.hn mil.hn net.hn org.hn
  com.hr from.hr iz.hr name.hr
  adult.ht art.ht asso.ht com.ht coop.ht edu.ht firm.ht gouv.ht info.ht med.ht net.ht org.ht perso.ht pol.ht pro.ht rel.ht shop.ht
  2000.hu ac.hu agrar.hu bolt.hu casino.hu city.hu co.hu edu.hu erotica.hu erotika.hu film.hu forum.hu games.hu gov.hu hotel.hu info.hu ingatlan.hu jogasz.hu konyvelo.hu lakas.hu media.hu news.hu org.hu priv.hu reklam.hu sex.hu shop.hu sport.hu suli.hu szex.hu tm.hu tozsde.hu utazas.hu video.hu
  ac.id co.id go.id mil.id net.id or.id sch.id web.id
  gov.ie
  ac.il co.il gov.il idf.il k12.il muni.il net.il org.il
  ac.im co.im gov.im net.im nic.im org.im
  ac.in co.in edu.in ernet.in firm.in gen.in gov.in ind.in mil.in net.in nic.in org.in res.in
  com.io gov.io mil.io net.io org.io
  ac.ir co.ir gov.ir id.ir net.ir org.ir sch.ir
  edu.it gov.it
  ac.je co.je gov.je ind.je jersey.je ltd.je net.je org.je sch.je
  com.jm edu.jm gov.jm net.jm org.jm
  com.jo edu.jo gov.jo mil.jo net.jo org.jo
  ac.jp ad.jp aichi.jp akita.jp aomori.jp chiba.jp co.jp ed.jp ehime.jp fukui.jp fukuoka.jp fukushima.jp gifu.jp go.jp gov.jp gr.jp gunma.jp hiroshima.jp hokkaido.jp hyogo.jp ibaraki.jp ishikawa.jp iwate.jp kagawa.jp kagoshima.jp kanagawa.jp kanazawa.jp kawasaki.jp kitakyushu.jp kobe.jp kochi.jp kumamoto.jp kyoto.jp lg.jp matsuyama.jp mie.jp miyagi.jp miyazaki.jp nagano.jp nagasaki.jp nagoya.jp nara.jp ne.jp net.jp niigata.jp oita.jp okayama.jp okinawa.jp or.jp org.jp osaka.jp saga.jp saitama.jp sapporo.jp sendai.jp shiga.jp shimane.jp shizuoka.jp takamatsu.jp tochigi.jp tokushima.jp tokyo.jp tottori.jp toyama.jp utsunomiya.jp wakayama.jp yamagata.jp yamaguchi.jp yamanashi.jp yokohama.jp
  ac.ke co.ke go.ke ne.ke new.ke or.ke sc.ke
  com.kg edu.kg gov.kg mil.kg net.kg org.kg
  com.kh edu.kh gov.kh mil.kh net.kh org.kh per.kh
  ac.kr busan.kr chungbuk.kr chungnam.kr co.kr daegu.kr daejeon.kr es.kr gangwon.kr go.kr gwangju.kr gyeongbuk.kr gyeonggi.kr gyeongnam.kr hs.kr incheon.kr jeju.kr jeonbuk.kr jeonnam.kr kg.kr kyonggi.kr mil.kr ms.kr ne.kr or.kr pe.kr re.kr sc.kr seoul.kr ulsan.kr
  com.kw edu.kw gov.kw mil.kw net.kw org.kw
  com.ky edu.ky gov.ky net.ky org.ky
  com.kz edu.kz gov.kz mil.kz net.kz org.kz
  com.la net.la org.la
  com.lb edu.lb gov.lb mil.lb net.lb org.lb
  com.lc edu.lc gov.lc net.lc org.lc
  assn.lk com.lk edu.lk gov.lk grp.lk hotel.lk int.lk ltd.lk net.lk ngo.lk org.lk sch.lk soc.lk web.lk
  com.lr edu.lr gov.lr net.lr org.lr
  co.ls org.ls
  gov.lt mil.lt
  asn.lv com.lv conf.lv edu.lv gov.lv id.lv mil.lv net.lv org.lv
  biz.ly com.ly edu.ly gov.ly id.ly med.ly net.ly org.ly plc.ly sch.ly
  ac.ma co.ma gov.ma net.ma org.ma press.ma
  asso.mc tm.mc
  com.mg edu.mg gov.mg mil.mg nom.mg org.mg prd.mg tm.mg
  army.mil navy.mil
  com.mk org.mk
  com.mm edu.mm gov.mm net.mm org.mm
  edu.mn gov.mn org.mn
  com.mo edu.mo gov.mo net.mo org.mo
  music.mobi weather.mobi
  com.mt edu.mt gov.mt net.mt org.mt tm.mt uu.mt
  co.mu com.mu
  aero.mv biz.mv com.mv coop.mv edu.mv gov.mv info.mv int.mv mil.mv museum.mv name.mv net.mv org.mv pro.mv
  ac.mw co.mw com.mw coop.mw edu.mw gov.mw int.mw museum.mw net.mw org.mw
  com.mx edu.mx gob.mx net.mx org.mx
  com.my edu.my gov.my mil.my name.my net.my org.my
  alt.na com.na cul.na edu.na net.na org.na telecom.na unam.na
  com.nc net.nc org.nc
  de.net gb.net uk.net
  ac.ng com.ng edu.ng gov.ng net.ng org.ng sch.ng
  com.ni edu.ni gob.ni net.ni nom.ni org.ni
  fhs.no folkebibl.no fylkesbibl.no herad.no idrett.no kommune.no mil.no museum.no priv.no stat.no tel.no vgs.no
  com.np edu.np gov.np mil.np net.np org.np
  biz.nr co.nr com.nr edu.nr fax.nr gov.nr info.nr mob.nr mobil.nr mobile.nr net.nr org.nr tel.nr tlf.nr
  ac.nz co.nz cri.nz geek.nz gen.nz govt.nz iwi.nz maori.nz mil.nz net.nz org.nz school.nz
  ac.om biz.om co.om com.om edu.om gov.om med.om mil.om mod.om museum.om net.om org.om pro.om sch.om
  dk.org eu.org
  abo.pa ac.pa com.pa edu.pa gob.pa ing.pa med.pa net.pa nom.pa org.pa sld.pa
  com.pe edu.pe gob.pe mil.pe net.pe nom.pe org.pe
  com.pf edu.pf org.pf
  ac.pg com.pg net.pg
  com.ph edu.ph gov.ph mil.ph net.ph ngo.ph org.ph
  biz.pk com.pk edu.pk fam.pk gob.pk gok.pk gon.pk gop.pk gos.pk gov.pk net.pk org.pk web.pk
  agro.pl aid.pl art.pl atm.pl auto.pl bialystok.pl biz.pl com.pl edu.pl gda.pl gdansk.pl gmina.pl gov.pl gsm.pl info.pl katowice.pl krakow.pl lodz.pl lublin.pl mail.pl media.pl miasta.pl mil.pl net.pl ngo.pl nieruchomosci.pl nom.pl olsztyn.pl opole.pl org.pl pc.pl powiat.pl poznan.pl priv.pl realestate.pl rel.pl sex.pl shop.pl sklep.pl slupsk.pl sos.pl szczecin.pl szkola.pl targi.pl tm.pl torun.pl tourism.pl travel.pl turystyka.pl warszawa.pl waw.pl wroc.pl wroclaw.pl za.pl zgora.pl
  biz.pr com.pr edu.pr gov.pr info.pr isla.pr name.pr net.pr org.pr pro.pr
  cpa.pro law.pro med.pro
  com.ps edu.ps gov.ps net.ps org.ps plo.ps sec.ps
  com.pt edu.pt gov.pt int.pt net.pt nome.pt org.pt publ.pt
  com.py edu.py gov.py net.py org.py
  com.qa edu.qa gov.qa net.qa org.qa
  asso.re com.re nom.re
  arts.ro com.ro firm.ro info.ro nom.ro nt.ro org.ro rec.ro store.ro tm.ro www.ro
  ac.rs co.rs edu.rs gov.rs in.rs org.rs
  ac.ru adygeya.ru altai.ru amur.ru amursk.ru arkhangelsk.ru astrakhan.ru baikal.ru bashkiria.ru belgorod.ru bir.ru bryansk.ru buryatia.ru cbg.ru chel.ru chelyabinsk.ru chita.ru chukotka.ru chuvashia.ru cmw.ru com.ru dagestan.ru dudinka.ru e-burg.ru edu.ru fareast.ru gov.ru grozny.ru int.ru irkutsk.ru ivanovo.ru izhevsk.ru jamal.ru jar.ru joshkar-ola.ru k-uralsk.ru kalmykia.ru kaluga.ru kamchatka.ru karelia.ru kazan.ru kchr.ru kemerovo.ru khabarovsk.ru khakassia.ru khv.ru kirov.ru kms.ru koenig.ru komi.ru kostroma.ru krasnoyarsk.ru kuban.ru kurgan.ru kursk.ru kustanai.ru kuzbass.ru lipetsk.ru magadan.ru magnitka.ru mari-el.ru mari.ru marine.ru mil.ru mordovia.ru mosreg.ru msk.ru murmansk.ru mytis.ru nakhodka.ru nalchik.ru net.ru nkz.ru nnov.ru norilsk.ru nov.ru novosibirsk.ru nsk.ru omsk.ru orenburg.ru org.ru oryol.ru oskol.ru palana.ru penza.ru perm.ru pp.ru pskov.ru ptz.ru pyatigorsk.ru rnd.ru rubtsovsk.ru ryazan.ru sakhalin.ru samara.ru saratov.ru simbirsk.ru smolensk.ru snz.ru spb.ru stavropol.ru stv.ru surgut.ru syzran.ru tambov.ru tatarstan.ru test.ru tom.ru tomsk.ru tsaritsyn.ru tsk.ru tula.ru tuva.ru tver.ru tyumen.ru udm.ru udmurtia.ru ulan-ude.ru vdonsk.ru vladikavkaz.ru vladimir.ru vladivostok.ru volgograd.ru vologda.ru voronezh.ru vrn.ru vyatka.ru yakutia.ru yamal.ru yaroslavl.ru yekaterinburg.ru yuzhno-sakhalinsk.ru zgrad.ru
  ac.rw co.rw com.rw edu.rw gouv.rw gov.rw int.rw mil.rw net.rw
  com.sa edu.sa gov.sa med.sa net.sa org.sa pub.sa sch.sa
  com.sb edu.sb gov.sb net.sb org.sb
  com.sc edu.sc gov.sc net.sc org.sc
  com.sd edu.sd gov.sd info.sd med.sd net.sd org.sd sch.sd tv.sd
  ab.se ac.se bd.se brand.se c.se d.se e.se f.se fh.se fhsk.se fhv.se g.se h.se i.se k.se komforb.se kommunalforbund.se komvux.se lanarb.se lanbib.se m.se mil.se n.se naturbruksgymn.se o.se org.se parti.se pp.se press.se s.se sshn.se t.se tm.se u.se w.se x.se y.se z.se
  com.sg edu.sg gov.sg idn.sg net.sg org.sg per.sg
  com.sh edu.sh gov.sh mil.sh net.sh org.sh
  edu.sk gov.sk mil.sk
  co.st com.st consulado.st edu.st embaixada.st gov.st mil.st net.st org.st principe.st saotome.st store.st
  com.sv edu.sv gob.sv org.sv red.sv
  com.sy gov.sy net.sy org.sy
  at.tf bg.tf ca.tf ch.tf cz.tf de.tf edu.tf eu.tf int.tf net.tf pl.tf ru.tf sg.tf us.tf
  ac.th co.th go.th in.th mi.th net.th or.th
  ac.tj biz.tj co.tj com.tj edu.tj go.tj gov.tj int.tj mil.tj name.tj net.tj org.tj web.tj
  com.tn edunet.tn ens.tn fin.tn gov.tn ind.tn info.tn intl.tn nat.tn net.tn org.tn rnrt.tn rns.tn rnu.tn tourism.tn
  gov.to
  gov.tp
  av.tr bbs.tr bel.tr biz.tr com.tr dr.tr edu.tr gen.tr gov.tr info.tr k12.tr mil.tr name.tr net.tr org.tr pol.tr tel.tr web.tr
  aero.tt at.tt au.tt be.tt biz.tt ca.tt co.tt com.tt coop.tt de.tt dk.tt edu.tt es.tt eu.tt fr.tt gov.tt info.tt int.tt it.tt jobs.tt mobi.tt museum.tt name.tt net.tt nic.tt org.tt pro.tt se.tt travel.tt uk.tt us.tt
  co.tv gov.tv
  club.tw com.tw ebiz.tw edu.tw game.tw gov.tw idv.tw mil.tw net.tw org.tw
  ac.tz co.tz go.tz ne.tz or.tz
  cherkassy.ua chernigov.ua chernovtsy.ua ck.ua cn.ua co.ua com.ua crimea.ua cv.ua dn.ua dnepropetrovsk.ua donetsk.ua dp.ua edu.ua gov.ua if.ua in.ua ivano-frankivsk.ua kh.ua kharkov.ua kherson.ua khmelnitskiy.ua kiev.ua kirovograd.ua km.ua kr.ua ks.ua kv.ua lg.ua lugansk.ua lutsk.ua lviv.ua mk.ua net.ua nikolaev.ua od.ua odessa.ua org.ua pl.ua poltava.ua rovno.ua rv.ua sebastopol.ua sumy.ua te.ua ternopil.ua uzhgorod.ua vinnica.ua vn.ua zaporizhzhe.ua zhitomir.ua zp.ua zt.ua
  ac.ug co.ug go.ug ne.ug or.ug sc.ug
  ac.uk bl.uk british-library.uk co.uk edu.uk gov.uk icnet.uk jet.uk ltd.uk me.uk mod.uk national-library-scotland.uk net.uk nhs.uk nic.uk nls.uk org.uk parliament.uk plc.uk police.uk sch.uk
  ak.us al.us ar.us az.us ca.us co.us ct.us dc.us de.us dni.us fed.us fl.us ga.us hi.us ia.us id.us il.us in.us isa.us kids.us ks.us ky.us la.us ma.us md.us me.us mi.us mn.us mo.us ms.us mt.us nc.us nd.us ne.us nh.us nj.us nm.us nsn.us nv.us ny.us oh.us ok.us or.us pa.us ri.us sc.us sd.us tn.us tx.us ut.us va.us vt.us wa.us wi.us wv.us wy.us
  com.uy edu.uy gub.uy mil.uy net.uy org.uy
  vatican.va
  arts.ve bib.ve co.ve com.ve edu.ve firm.ve gov.ve info.ve int.ve mil.ve net.ve nom.ve org.ve rec.ve store.ve tec.ve web.ve
  co.vi com.vi edu.vi gov.vi net.vi org.vi
  ac.vn biz.vn com.vn edu.vn gov.vn health.vn info.vn int.vn name.vn net.vn org.vn pro.vn
  ch.vu com.vu de.vu edu.vu fr.vu net.vu org.vu
  com.ws edu.ws gov.ws net.ws org.ws
  com.ye edu.ye gov.ye mil.ye net.ye org.ye
  ac.yu co.yu edu.yu org.yu
  ac.za alt.za bourse.za city.za co.za edu.za gov.za law.za mil.za net.za ngo.za nom.za org.za school.za tm.za web.za
  ac.zm co.zm gov.zm org.zm sch.zm
  ac.zw co.zw gov.zw org.zw

 /) {
  $TWO_LEVEL_DOMAINS{$_} = 1;
}

# This is required because the .us domain is nuts. See $THREE_LEVEL_DOMAINS
# below.
#
foreach (qw/
  ak al ar az ca co ct dc de fl ga gu hi ia id il in ks ky la ma md me mi 
  mn mo ms mt nc nd ne nh nj nm nv ny oh ok or pa pr ri sc sd tn tx ut va vi 
  vt wa wi wv wy
  /) {
  $US_STATES{$_} = 1;
}

foreach (qw/
  demon.co.uk esc.edu.ar lkd.co.im plc.co.im
 /) {
  $THREE_LEVEL_DOMAINS{$_} = 1;
}

###########################################################################

=over 4

=item ($hostname, $domain) = split_domain ($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, splitting at the DNS registry boundary.

Examples:

    "www.foo.com" => ( "www", "foo.com" )
    "www.foo.co.uk" => ( "www", "foo.co.uk" )

=cut

sub split_domain {
  my $domain = lc shift;
  my $hostname = '';

  if ($domain) {
    # www..spamassassin.org -> www.spamassassin.org
    $domain =~ tr/././s;

    # leading/trailing dots
    $domain =~ s/^\.+//;
    $domain =~ s/\.+$//;

    # Split scalar domain into components
    my @domparts = split(/\./, $domain);
    my @hostname;

    while (@domparts > 1) { # go until we find the TLD
      if (@domparts == 4) {
	if ($domparts[3] eq 'us' &&
	    (($domparts[0] eq 'pvt' && $domparts[1] eq 'k12') ||
	     ($domparts[0] =~ /^c[io]$/)))
	{
          # http://www.neustar.us/policies/docs/rfc_1480.txt
          # "Fire-Dept.CI.Los-Angeles.CA.US"
          # "<school-name>.PVT.K12.<state>.US"
          last if ($US_STATES{$domparts[2]});
	}
      }
      elsif (@domparts == 3) {
        # http://www.neustar.us/policies/docs/rfc_1480.txt
	# demon.co.uk
	# esc.edu.ar
	# [^\.]+\.${US_STATES}\.us
	if ($domparts[2] eq 'us') {
          last if ($US_STATES{$domparts[1]});
	}
        else {
          my $temp = join(".", @domparts);
          last if ($THREE_LEVEL_DOMAINS{$temp});
        }
      }
      elsif (@domparts == 2) {
	# co.uk, etc.
	my $temp = join(".", @domparts);
        last if ($TWO_LEVEL_DOMAINS{$temp});
      }
      push(@hostname, shift @domparts);
    }

    # Look for a sub-delegated TLD
    # use @domparts to skip trying to match on TLDs that can't possibly
    # match, but keep in mind that the hostname can be blank, so 4TLD needs 4,
    # 3TLD needs 3, 2TLD needs 2 ...
    #
    unshift @domparts, pop @hostname if @hostname;
    $domain = join(".", @domparts);
    $hostname = join(".", @hostname);
  }

  ($hostname, $domain);
}

###########################################################################

=item $domain = trim_domain($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, returning just the domain.

Examples:

    "www.foo.com" => "foo.com" 
    "www.foo.co.uk" => "foo.co.uk" 

=cut

sub trim_domain {
  my ($domain) = @_;
  my ($host, $dom) = split_domain($domain);
  return $dom;
}

###########################################################################

=item $ok = is_domain_valid($dom)

Return C<1> if the domain is valid, C<undef> otherwise.  A valid domain
(a) does not contain whitespace, (b) contains at least one dot, and (c)
uses a valid TLD or ccTLD.

=back

=cut

sub is_domain_valid {
  my ($dom) = @_;

  # domains don't have whitespace
  return 0 if ($dom =~ /\s/);

  # ensure it ends in a known-valid TLD, and has at least 1 dot
  return 0 unless ($dom =~ /\.([^.]+)$/);
  return 0 unless ($VALID_TLDS{$1});

  return 1;     # nah, it's ok.
}

1;
