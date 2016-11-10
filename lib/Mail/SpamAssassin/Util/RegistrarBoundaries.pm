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

=head1 NAME

Mail::SpamAssassin::Util::RegistrarBoundaries - domain delegation rules

This module is DEPRECATED AND REPLACED WITH
Mail::SpamAssassin::RegistryBoundaries !!

DO NOT USE. This is left as transition fallback for third party plugins.

It will be removed in the future but all functionality has been
transitioned to Mail::SpamAssassin::RegistryBoundaries and the TLD
updates via 20_aux_tlds.cf delivered via sa-update with version 3.4.1.

=cut

package Mail::SpamAssassin::Util::RegistrarBoundaries;

use strict;
use warnings;
# use bytes;
use re 'taint';

use vars qw (
  @ISA %TWO_LEVEL_DOMAINS %THREE_LEVEL_DOMAINS %US_STATES %VALID_TLDS $VALID_TLDS_RE
);

# %VALID_TLDS
# The list of currently-valid TLDs for the DNS system.
#
# This list is deprecated and unmaintained. It will become increasingly
# out of date and will be removed in a future release.
#
# As of 3.4.1, updates will be done in rules/20_aux_tlds.cf
foreach (qw/aaa aarp abarth abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco active actor ad adac ads adult ae aeg aero aetna af afamilycompany afl ag agakhan agency ai aig aigo airbus airforce airtel akdn al alfaromeo alibaba alipay allfinanz allstate ally alsace alstom am americanexpress americanfamily amex amfam amica amsterdam analytics android anquan anz ao aol apartments app apple aq aquarelle ar aramco archi army arpa art arte as asda asia associates at athleta attorney au auction audi audible audio auspost author auto autos avianca aw aws ax axa az azure ba baby baidu banamex bananarepublic band bank bar barcelona barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb bbc bbt bbva bcg bcn bd be beats beauty beer bentley berlin best bestbuy bet bf bg bh bharti bi bible bid bike bing bingo bio biz bj black blackfriday blanco blockbuster blog bloomberg blue bm bms bmw bn bnl bnpparibas bo boats boehringer bofa bom bond boo book booking boots bosch bostik bot boutique br bradesco bridgestone broadway broker brother brussels bs bt budapest bugatti build builders business buy buzz bv bw by bz bzh ca cab cafe cal call calvinklein cam camera camp cancerresearch canon capetown capital capitalone car caravan cards care career careers cars cartier casa case caseih cash casino cat catering cba cbn cbre cbs cc cd ceb center ceo cern cf cfa cfd cg ch chanel channel chase chat cheap chintai chloe christmas chrome chrysler church ci cipriani circle cisco citadel citi citic city cityeats ck cl claims cleaning click clinic clinique clothing cloud club clubmed cm cn co coach codes coffee college cologne com comcast commbank community company compare computer comsec condos construction consulting contact contractors cooking cookingchannel cool coop corsica country coupon coupons courses cr credit creditcard creditunion cricket crown crs cruises csc cu cuisinella cv cw cx cy cymru cyou cz dabur dad dance date dating datsun day dclk dds de deal dealer deals degree delivery dell deloitte delta democrat dental dentist desi design dev dhl diamonds diet digital direct directory discount discover dish diy dj dk dm dnp do docs doctor dodge dog doha domains dot download drive dtv dubai duck dunlop duns dupont durban dvag dvr dz earth eat ec eco edeka edu education ee eg email emerck energy engineer engineering enterprises epost epson equipment er ericsson erni es esq estate esurance et eu eurovision eus events everbank exchange expert exposed express extraspace fage fail fairwinds faith family fan fans farm farmers fashion fast fedex feedback ferrari ferrero fi fiat fidelity fido film final finance financial fire firestone firmdale fish fishing fit fitness fj fk flickr flights flir florist flowers fly fm fo foo foodnetwork football ford forex forsale forum foundation fox fr free fresenius frl frogans frontdoor frontier ftr fujitsu fujixerox fund furniture futbol fyi ga gal gallery gallo gallup game games gap garden gb gbiz gd gdn ge gea gent genting george gf gg ggee gh gi gift gifts gives giving gl glade glass gle global globo gm gmail gmbh gmo gmx gn godaddy gold goldpoint golf goo goodhands goodyear goog google gop got gov gp gq gr grainger graphics gratis green gripe group gs gt gu guardian gucci guge guide guitars guru gw gy hamburg hangout haus hbo hdfc hdfcbank health healthcare help helsinki here hermes hgtv hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday homedepot homegoods homes homesense honda honeywell horse host hosting hot hoteles hotmail house how hr hsbc ht htc hu hughes hyatt hyundai ibm icbc ice icu id ie ieee ifm iinet ikano il im imamat imdb immo immobilien in industries infiniti info ing ink institute insurance insure int intel international intuit investments io ipiranga iq ir irish is iselect ismaili ist istanbul it itau itv iveco iwc jaguar java jcb jcp je jeep jetzt jewelry jlc jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos juniper kaufen kddi ke kerryhotels kerrylogistics kerryproperties kfh kg kh ki kia kim kinder kindle kitchen kiwi km kn koeln komatsu kosher kp kpmg kpn kr krd kred kuokgroup kw ky kyoto kz la lacaixa ladbrokes lamborghini lamer lancaster lancia lancome land landrover lanxess lasalle lat latino latrobe law lawyer lb lc lds lease leclerc lefrak legal lego lexus lgbt li liaison lidl life lifeinsurance lifestyle lighting like lilly limited limo lincoln linde link lipsy live living lixil lk loan loans locker locus loft lol london lotte lotto love lpl lplfinancial lr ls lt ltd ltda lu lundbeck lupin luxe luxury lv ly ma macys madrid maif maison makeup man management mango market marketing markets marriott marshalls maserati mattel mba mc mcd mcdonalds mckinsey md me med media meet melbourne meme memorial men menu meo metlife mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma mn mo mobi mobily moda moe moi mom monash money monster montblanc mopar mormon mortgage moscow motorcycles mov movie movistar mp mq mr ms msd mt mtn mtpc mtr mu museum mutual mutuelle mv mw mx my mz na nab nadex nagoya name nationwide natura navy nba nc ne nec net netbank netflix network neustar new newholland news next nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja nissan nissay nl no nokia northwesternmutual norton now nowruz nowtv np nr nra nrw ntt nu nyc nz obi observer off office okinawa olayan olayangroup oldnavy ollo om omega one ong onl online onyourside ooo open oracle orange org organic orientexpress origins osaka otsuka ott ovh pa page pamperedchef panasonic panerai paris pars partners parts party passagens pay pccw pe pet pf pfizer pg ph pharmacy philips photo photography photos physio piaget pics pictet pictures pid pin ping pink pioneer pizza pk pl place play playstation plumbing plus pm pn pnc pohl poker politie porn post pr pramerica praxi press prime pro prod productions prof progressive promo properties property protection pru prudential ps pt pub pw pwc py qa qpon quebec quest qvc racing radio raid re read realestate realtor realty recipes red redstone redumbrella rehab reise reisen reit ren rent rentals repair report republican rest restaurant review reviews rexroth rich richardli ricoh rightathome rio rip ro rocher rocks rodeo rogers room rs rsvp ru ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon samsclub samsung sandvik sandvikcoromant sanofi sap sapo sarl sas save saxo sb sbi sbs sc sca scb schaeffler schmidt scholarships school schule schwarz science scjohnson scor scot sd se seat secure security seek select sener services ses seven sew sex sexy sfr sg sh shangrila sharp shaw shell shia shiksha shoes shop shopping shouji show showtime shriram si silk sina singles site sj sk ski skin sky skype sl sling sm smart smile sn sncf so soccer social softbank software sohu solar solutions song sony soy space spiegel spot spreadbetting sr srl srt st stada staples star starhub statebank statefarm statoil stc stcgroup stockholm storage store stream studio study style su sucks supplies supply support surf surgery suzuki sv swatch swiftcover swiss sx sy sydney symantec systems sz tab taipei talk taobao target tatamotors tatar tattoo tax taxi tc tci td tdk team tech technology tel telecity telefonica temasek tennis teva tf tg th thd theater theatre tiaa tickets tienda tiffany tips tires tirol tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray toshiba total tours town toyota toys tr trade trading training travel travelchannel travelers travelersinsurance trust trv tt tube tui tunes tushu tv tvs tw tz ua ubank ubs uconnect ug uk unicom university uno uol ups us uy uz va vacations vana vanguard vc ve vegas ventures verisign versicherung vet vg vi viajes video vig viking villas vin vip virgin visa vision vista vistaprint viva vivo vlaanderen vn vodka volkswagen volvo vote voting voto voyage vu vuelos wales walmart walter wang wanggou warman watch watches weather weatherchannel webcam weber website wed wedding weibo weir wf whoswho wien wiki williamhill win windows wine winners wme wolterskluwer woodside work works world wow ws wtc wtf xbox xerox xfinity xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a xn--30rr7y xn--3bst00m xn--3ds443g xn--3e0b707e xn--3oq18vl8pn36a xn--3pxu8k xn--42c2d9a xn--45brj9c xn--45q11c xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g xn--6frz82g xn--6qq986b3xl xn--80adxhks xn--80ao21a xn--80asehdb xn--80aswg xn--8y0a063a xn--90a3ac xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b xn--cg4bki xn--clchc0ea0b2g2a9gcd xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf xn--e1a4c xn--eckvdtc9d xn--efvy88h xn--estv75g xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--fiqz9s xn--fjq720a xn--flw351e xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gecrj9c xn--gk3at1e xn--h2brj9c xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i xn--j1aef xn--j1amh xn--j6w193g xn--jlq61u9w7b xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d xn--kpu716f xn--kput3i xn--l1acc xn--lgbbat1ad8j xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a xn--mgbaam7a8h xn--mgbab2bd xn--mgbayh7gpa xn--mgbb9fbpob xn--mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo xn--mgberp4a5d4ar xn--mgbpl2fh xn--mgbt3dhd xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--node xn--nqv7f xn--nqv7fs00ema xn--nyqy26a xn--o3cw4h xn--ogbpf8fl xn--p1acf xn--p1ai xn--pbt977c xn--pgbs0dh xn--pssy2u xn--q9jyb4c xn--qcka1pmc xn--qxam xn--rhqv96g xn--rovu88b xn--s9brj9c xn--ses554g xn--t60b56a xn--tckwe xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a xn--xhq521b xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xperia xxx xyz yachts yahoo yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zippo zm zone zuerich zw/) {
  $VALID_TLDS{$_} = 1;
}

# $VALID_TLDS_RE
# %VALID_TLDS as Regexp::List optimized regexp, for use in Plugins etc
#
# This regex is deprecated and unmaintained. It will become increasingly
# out of date and will be removed in a future release.
#
# As of 3.4.1, this regex is generated automatically in Conf.pm
$VALID_TLDS_RE = qr/(?:X(?:N--(?:M(?:GB(?:A(?:(?:3A4F16|YH7GP)A|AM7A8H|B2BD)|ERP4A5D4AR|C0A9AZCG|BH1A71E|X4CD0AB|9AWBF)|XTQ1M)|F(?:IQ(?:(?:228C5H|S8|Z9)S|64B)|PCRJ9C3D|ZC2C9E2C|LW351E)|C(?:ZR(?:694B|S0T|U2D)|LCHC0EA0B2G2A9GCD|G4BKI|1AVG)|V(?:(?:ERMGENSBERAT(?:UNG-PW|ER-CT)|UQ861)B|HQUV)|X(?:KC2(?:DL3A5EE0H|AL3HYE2A)|HQ521B)|3(?:E0B707E|BST00M|DS443G|0RR7Y)|N(?:QV7F(?:S00EMA)?|GBC5AZD|ODE)|80A(?:S(?:EHDB|WG)|DXHKS|O21A)|(?:Q(?:CKA1PM|9JYB4)|GECRJ9)C|4(?:5(?:BRJ9|Q11)C|GBRIM)|KP(?:R(?:W13|Y57)D|UT3I)|9(?:0A(?:3AC|IS)|ET52U)|P(?:1A(?:CF|I)|GBS0DH)|Y(?:FRO4I67O|GBI2AMMX)|6(?:QQ986B3XL|FRZ82G)|I(?:1B6B1A6A2E|O0A7I)|L(?:GBBAT1AD8J|1ACC)|H(?:2BRJ9C|XT814E)|O(?:GBPF8FL|3CW4H)|S(?:9BRJ9C|ES554G)|J(?:6W193G|1AMH)|55Q(?:W42G|X5D)|D1A(?:CJ3B|LF)|WGB(?:H1C|L6A)|B4W605FERD|1QQW23A|RHQV96G|ZFR164B|UNUP4Y)|IN|XX|YZ)|C(?:[CDGKMVWXZ]|O(?:N(?:S(?:TRUCTION|ULTING)|(?:TRACTOR|DO)S)|M(?:P(?:UTER|ANY)|MUNITY)?|(?:L(?:LEG|OGN)|FFE)E|O(?:[LP]|KING)|U(?:NTRY|RSES)|ACH|DES)?|A(?:[BL]|R(?:E(?:ERS?)?|AVAN|TIER|DS)|N(?:CERRESEARCH|ON)|P(?:ETOWN|ITAL)|S(?:[AH]|INO)|T(?:ERING)?|M(?:ERA|P))?|H(?:R(?:ISTMAS|OME)|A(?:NNEL|T)|URCH|EAP|LOE)?|L(?:(?:EAN|OTH)ING|I(?:NIC|CK)|AIMS|UB)?|R(?:EDIT(?:CARD)?|(?:UISE)?S|ICKET)?|I(?:T(?:IC|Y))?|E(?:NTER|RN|O)|U(?:ISINELLA)?|Y(?:MRU)?|B?N|FD?)|S(?:[BDGJLMNRVXZ]|U(?:PP(?:L(?:IES|Y)|ORT)|R(?:GERY|F)|ZUKI|CKS)?|C(?:[AB]|H(?:MIDT|WARZ|OOL|ULE)|IENCE|OT)?|O(?:L(?:UTIONS|AR)|FTWARE|CIAL|HU|Y)?|A(?:ARLAND|MSUNG|LE|RL|XO|P)?|P(?:READBETTING|IEGEL|ACE)|H(?:IKSHA|RIRAM|OES)?|E(?:RVICES|XY|W)?|Y(?:STEMS|DNEY)?|I(?:NGLES|TE)?|T(?:UDY|YLE)?|KY?)|A(?:[OWZ]|C(?:T(?:IVE|OR)|COUNTANTS?|ADEMY)?|U(?:CTION|DIO|TOS)?|L(?:LFINANZ|SACE)?|S(?:SOCIATES|IA)?|B(?:OGADO|BOTT)|R(?:CHI|MY|PA)?|(?:MSTERDA)?M|Q(?:UARELLE)?|I(?:RFORCE)?|T(?:TORNEY)?|D(?:ULT|S)?|N(?:DROID)?|G(?:ENCY)?|PARTMENTS|E(?:RO)?|FL?|XA?)|M(?:[CDGHKLNPQRSVWXYZ]|O(?:R(?:TGAGE|MON)|N(?:ASH|EY)|TORCYCLES|V(?:IE)?|SCOW|BI|DA|E)?|A(?:R(?:KET(?:ING|S)?|RIOTT)|N(?:AGEMENT|GO)|I(?:SON|F)|DRID)?|E(?:M(?:ORIAL|E)|LBOURNE|DIA|ET|NU)?|I(?:(?:AM|N)I|L)|T(?:PC|N)?|U(?:SEUM)?|MA?)|B(?:[DFGHJSTVWY]|A(?:R(?:CLAY(?:CARD|S)|GAINS)?|N[DK]|YERN)?|U(?:ILD(?:ERS)?|DAPEST|SINESS|ZZ)|L(?:ACK(?:FRIDAY)?|OOMBERG|UE)|I(?:[DZ]|(?:NG)?O|KE)?|O(?:UTIQUE|ATS|ND|O)?|E(?:RLIN|ER|ST)?|N(?:PPARIBAS)?|R(?:USSELS)?|BC?|MW?|ZH?)|P(?:[EFGKMNSTWY]|R(?:O(?:D(?:UCTIONS)?|PERT(?:IES|Y)|F)?|AXI|ESS)?|A(?:R(?:T(?:(?:NER)?S|Y)|IS)|NERAI|GE)?|I(?:C(?:T(?:URES|ET)|S)|AGET|ZZA|NK)|H(?:OTO(?:GRAPHY|S)?|ARMACY|YSIO)?|L(?:U(?:MBING|S)|ACE)?|O(?:KER|HL|RN|ST)|UB)|G(?:[FHNPQSTWY]|O(?:[PV]|L(?:D(?:POINT)?|F)|O(?:G(?:LE)?)?)|R(?:A(?:PHIC|TI)S|EEN|IPE)?|U(?:I(?:TARS|DE)|GE|RU)?|L(?:OB(?:AL|O)|ASS|E)?|A(?:L(?:LERY)?|RDEN)?|I(?:FTS?|VES)?|M(?:[OX]|AIL)?|B(?:IZ)?|E(?:NT)?|G(?:EE)?|DN?)|F(?:[JM]|I(?:NANC(?:IAL|E)|SH(?:ING)?|T(?:NESS)?|RMDALE|LM)?|O(?:R(?:SALE|EX)|O(?:TBALL)?|UNDATION)?|L(?:O(?:RIST|WERS)|SMIDTH|IGHTS|Y)|A(?:I(?:TH|L)|SHION|NS?|RM)|U(?:RNITURE|TBOL|ND)|R(?:OGANS|L)?|(?:EEDBAC)?K)|D(?:[JMZ]|E(?:NT(?:IST|AL)|SI(?:GN)?|LIVERY|MOCRAT|GREE|ALS|V)?|I(?:(?:SCOUN|E)T|RECT(?:ORY)?|AMONDS|GITAL)|A(?:[DY]|T(?:ING|SUN|E)|BUR|NCE)|O(?:(?:MAIN|C)S|WNLOAD|OSAN|HA)?|(?:CL)?K|URBAN|VAG|NP)|T(?:[CDFGHJKLMNTVWZ]|O(?:(?:OL|UR|Y)S|SHIBA|DAY|KYO|WN|P)?|R(?:A(?:D(?:ING|E)|INING|VEL)|UST)?|I(?:(?:CKET|P)S|R(?:ES|OL)|ENDA)|E(?:CH(?:NOLOGY)?|MASEK|NNIS|L)|A(?:T(?:TOO|AR)|IPEI|X)|UI)|E(?:[CEG]|N(?:GINEER(?:ING)?|TERPRISES|ERGY)|X(?:P(?:OSED|ERT)|CHANGE)|U(?:ROVISION|S)?|(?:QUIPMEN|A)?T|VE(?:RBANK|NTS)|DU(?:CATION)?|M(?:ERCK|AIL)|S(?:TATE|Q)?|R(?:NI)?|PSON)|R(?:E(?:P(?:UBLICAN|AIR|ORT)|S(?:TAURAN)?T|D(?:STONE)?|I(?:SEN?|T)|N(?:TALS)?|VIEWS?|ALTOR|CIPES|HAB)?|O(?:CKS|DEO)?|I(?:[OP]|CH)|S(?:VP)?|U(?:HR)?|YUKYU|W)|L(?:[BCKRVY]|I(?:M(?:ITED|O)|GHTING|DL|FE|NK)?|A(?:T(?:ROBE)?|CAIXA|WYER|ND)?|O(?:TT[EO]|ANS?|NDON)|E(?:CLERC|ASE|GAL)|U(?:X(?:URY|E))?|T(?:DA)?|D?S|GBT)|I(?:[DELOQST]|N(?:[GK]|(?:VESTMENT|DUSTRIE)S|T(?:ERNATIONAL)?|S(?:TITUT|UR)E|F(?:INITI|O))?|M(?:MO(?:BILIEN)?)?|R(?:ISH)?|[BF]M|WC)|V(?:[CGU]|E(?:(?:NTURE|GA)S|RSICHERUNG|T)?|I(?:(?:AJE|LLA)S|SION|DEO)?|O(?:T(?:[EO]|ING)|YAGE|DKA)|(?:LAANDERE)?N|A(?:CATIONS)?)|H(?:[KMNRTU]|O(?:L(?:DINGS|IDAY)|ST(?:ING)?|[RU]SE|MES|W)|E(?:R(?:MES|E)|ALTHCARE|LP)|A(?:MBURG|NGOUT|US)|I(?:PHOP|V))|W(?:[FS]|E(?:B(?:SITE|CAM)|D(?:DING)?)|I(?:LLIAMHILL|E?N|KI)|A(?:LES|TCH|NG)|OR(?:KS?|LD)|HOSWHO|T[CF]|ME)|N(?:[FLOPUZ]|E(?:T(?:WORK)?|USTAR|WS?|XUS)?|I(?:SSAN|NJA|CO)?|A(?:GOYA|ME|VY)?|R[AW]?|GO?|Y?C|HK|TT)|K(?:[EGHMPWZ]|I(?:TCHEN|WI|M)?|O(?:MATSU|ELN)|(?:AUFE)?N|R(?:E?D)?|Y(?:OTO)?|DDI)|O(?:(?:(?:TSU|SA)K|KINAW)A|R(?:G(?:ANIC)?|ACLE)|N(?:[EG]|L(?:INE)?)|OO|VH|M)|Y(?:[ET]|O(?:(?:KOHAM|G)A|DOBASHI|UTUBE)|A(?:CHTS|NDEX))|J(?:[MP]|O(?:B(?:URG|S))?|E(?:TZT)?|UEGOS|AVA|CB)|U(?:[AGKSYZ]|N(?:IVERSITY|O)|OL)|Z(?:[AMW]|UERICH|ONE|IP)|Q(?:UEBEC|PON|A))/ix;

# Two-Level TLDs
#
# to resort this, pump the whole list through:
#  perl -e '$/=undef; $_=<>; foreach(split) { ($a,$b) = split(/\./, $_, 2); $t{$b}->{$_}=1; } foreach (sort keys %t) { print "  ",join(" ", sort keys %{$t{$_}}),"\n" }'
#
# http://www.neustar.us/policies/docs/rfc_1480.txt
# data originally from http://spamcheck.freeapp.net/two-level-tlds
# The freeapp.net site now says that information on the site is obsolete
# See discussion and sources in comments of bug 5677
# updated as per bug 5815
# cleanup in progress per bug 6795 (axb)
# Unsorted sources:
# .ua : http://hostmaster.ua
# .hu : http://www.domain.hu/domain/English/szabalyzat/sld.html
#
# This list is deprecated and unmaintained. It will become increasingly
# out of date and will be removed in a future release.
#
# As of 3.4.1, updates will be done in rules/20_aux_tlds.cf
#
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
  adm.br adv.br agr.br am.br arq.br art.br ato.br bio.br bmd.br cim.br cng.br cnt.br com.br coop.br dpn.br eco.br ecn.br edu.br eng.br esp.br etc.br eti.br far.br fm.br fnd.br fot.br fst.br g12.br ggf.br gov.br imb.br ind.br inf.br jor.br lel.br mat.br med.br mil.br mus.br net.br nom.br not.br ntr.br odo.br org.br ppg.br pro.br psc.br psi.br qsl.br rec.br slg.br srv.br tmp.br trd.br tur.br tv.br vet.br zlg.br
  com.bs net.bs org.bs
  com.bt edu.bt gov.bt net.bt org.bt
  co.bw org.bw
  gov.by mil.by
  com.bz net.bz org.bz
  ab.ca bc.ca gc.ca mb.ca nb.ca nf.ca nl.ca ns.ca nt.ca nu.ca on.ca pe.ca qc.ca sk.ca yk.ca
  co.ck edu.ck gov.ck net.ck org.ck
  ac.cn ah.cn bj.cn com.cn cq.cn edu.cn fj.cn gd.cn gov.cn gs.cn gx.cn gz.cn ha.cn hb.cn he.cn hi.cn hk.cn hl.cn hn.cn jl.cn js.cn jx.cn ln.cn mo.cn net.cn nm.cn nx.cn org.cn qh.cn sc.cn sd.cn sh.cn sn.cn sx.cn tj.cn tw.cn xj.cn xz.cn yn.cn zj.cn
  arts.co com.co edu.co firm.co gov.co info.co int.co mil.co net.co nom.co org.co rec.co web.co
  lkd.co.im ltd.co.im plc.co.im
  co.cm com.cm net.cm
  au.com br.com cn.com de.com eu.com gb.com hu.com no.com qc.com ru.com sa.com se.com uk.com us.com uy.com za.com
  ac.cr co.cr ed.cr fi.cr go.cr or.cr sa.cr
  com.cu edu.cu gov.cu inf.cu net.cu org.cu
  gov.cx
  ac.cy biz.cy com.cy ekloges.cy gov.cy ltd.cy name.cy net.cy org.cy parliament.cy press.cy pro.cy tm.cy
  co.dk
  com.dm edu.dm gov.dm net.dm org.dm
  art.do com.do edu.do gob.do gov.do mil.do net.do org.do sld.do web.do
  art.dz asso.dz com.dz edu.dz gov.dz net.dz org.dz pol.dz
  com.ec edu.ec fin.ec gov.ec info.ec k12.ec med.ec mil.ec net.ec org.ec pro.ec gob.ec
  co.ee com.ee edu.ee fie.ee med.ee org.ee pri.ee
  com.eg edu.eg eun.eg gov.eg mil.eg net.eg org.eg sci.eg
  com.er edu.er gov.er ind.er mil.er net.er org.er
  com.es edu.es gob.es nom.es org.es
  biz.et com.et edu.et gov.et info.et name.et net.et org.et
  aland.fi
  ac.fj biz.fj com.fj gov.fj id.fj info.fj mil.fj name.fj net.fj org.fj pro.fj school.fj
  ac.fk co.fk com.fk gov.fk net.fk nom.fk org.fk
  tm.fr asso.fr nom.fr prd.fr presse.fr com.fr gouv.fr
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
  2000.hu agrar.hu bolt.hu casino.hu city.hu co.hu erotica.hu erotika.hu film.hu forum.hu games.hu hotel.hu info.hu ingatlan.hu jogasz.hu konyvelo.hu lakas.hu media.hu news.hu org.hu priv.hu reklam.hu sex.hu shop.hu sport.hu suli.hu szex.hu tm.hu tozsde.hu utazas.hu video.hu
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
  ac.me co.me edu.me gov.me its.me net.me org.me priv.me
  com.mg edu.mg gov.mg mil.mg nom.mg org.mg prd.mg tm.mg
  army.mil navy.mil
  com.mk org.mk
  com.mm edu.mm gov.mm net.mm org.mm
  edu.mn gov.mn org.mn
  com.mo edu.mo gov.mo net.mo org.mo
  music.mobi weather.mobi
  co.mp edu.mp gov.mp net.mp org.mp
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
  ac.ni biz.ni com.ni edu.ni gob.ni in.ni info.ni int.ni mil.ni net.ni nom.ni org.ni web.ni
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
  art.pl biz.pl com.pl edu.pl gov.pl info.pl mil.pl net.pl ngo.pl org.pl
  biz.pr com.pr edu.pr gov.pr info.pr isla.pr name.pr net.pr org.pr pro.pr
  cpa.pro law.pro med.pro
  com.ps edu.ps gov.ps net.ps org.ps plo.ps sec.ps
  com.pt edu.pt gov.pt int.pt net.pt nome.pt org.pt publ.pt
  com.py edu.py gov.py net.py org.py
  com.qa edu.qa gov.qa net.qa org.qa
  asso.re com.re nom.re
  arts.ro com.ro firm.ro info.ro nom.ro nt.ro org.ro rec.ro store.ro tm.ro www.ro
  ac.rs co.rs edu.rs gov.rs in.rs org.rs
  ac.ru com.ru edu.ru gov.ru int.ru mil.ru net.ru org.ru pp.ru
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
  ac.za alt.za bourse.za city.za co.za edu.za gov.za law.za mil.za net.za ngo.za nom.za org.za school.za tm.za web.za
  ac.zm co.zm  com.zm edu.zm gov.zm org.zm sch.zm
  ac.zw co.zw gov.zw org.zw

 /) {
  $TWO_LEVEL_DOMAINS{$_} = 1;
}

# This is required because the .us domain is nuts. See $THREE_LEVEL_DOMAINS
# below.
#
# This list is moved to transitioned to Mail::SpamAssassin::RegistryBoundaries

foreach (qw/
  ak al ar az ca co ct dc de fl ga gu hi ia id il in ks ky la ma md me mi
  mn mo ms mt nc nd ne nh nj nm nv ny oh ok or pa pr ri sc sd tn tx ut va vi
  vt wa wi wv wy
  /) {
  $US_STATES{$_} = 1;
}

##
## DO NOT UPDATE THIS DEPRECATED LIST
## Everything is now maintained in sa-update 20_aux_tlds.cf
##
foreach (qw/
  demon.co.uk esc.edu.ar lkd.co.im plc.co.im
 /) {
  $THREE_LEVEL_DOMAINS{$_} = 1;
}

###########################################################################

=head1 METHODS

=over 4

=item ($hostname, $domain) = split_domain ($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, splitting at the DNS registry boundary.

Examples:

    "www.foo.com" => ( "www", "foo.com" )
    "www.foo.co.uk" => ( "www", "foo.co.uk" )

This function has been moved !!! See Mail::SpamAssassin::RegistryBoundaries !!!

This is left as transition fallback for third party plugins.

It will be removed in the future.

=cut

sub split_domain {
  my $domain = lc shift;
  my $hostname = '';

  warn "DEPRECATED: MS::Util::RegistrarBoundaries::split_domain, Bug 7170";

  if (defined $domain && $domain ne '') {
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

This function has been moved !!! See Mail::SpamAssassin::RegistryBoundaries !!!

This is left as transition fallback for third party plugins.

It will be removed in the future.

=cut

sub trim_domain {
  my ($domain) = @_;
  warn "DEPRECATED: MS::Util::RegistrarBoundaries::trim_domain, Bug 7170";
  my ($host, $dom) = split_domain($domain);
  return $dom;
}

###########################################################################

=item $ok = is_domain_valid($dom)

Return C<1> if the domain is valid, C<undef> otherwise.  A valid domain
(a) does not contain whitespace, (b) contains at least one dot, and (c)
uses a valid TLD or ccTLD.

This function has been moved !!! See Mail::SpamAssassin::RegistryBoundaries !!!

This is left as transition fallback for third party plugins.

It will be removed in the future.

=back

=cut

sub is_domain_valid {
  my ($dom) = @_;
  warn "DEPRECATED: MS::Util::RegistrarBoundaries::is_domain_valid, Bug 7170";

  # domains don't have whitespace
  return 0 if ($dom =~ /\s/);

  # ensure it ends in a known-valid TLD, and has at least 1 dot
  return 0 unless ($dom =~ /\.([^.]+)$/);
  return 0 unless ($VALID_TLDS{$1});

  return 1;     # nah, it's ok.
}

1;
