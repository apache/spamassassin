# The (extremely complex) rules for domain delegation.

# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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
use bytes;

use vars qw (
  @ISA $TWO_LEVEL_DOMAINS $THREE_LEVEL_DOMAINS $US_STATES $FOUR_LEVEL_DOMAINS
  $VALID_TLDS
);

# The list of currently-valid TLDs for the DNS system.
#
$VALID_TLDS = qr{ (?:
  # http://www.iana.org/cctld/cctld-whois.htm
  ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|az|ax|ba|bb|bd|be|bf|bg|bh|bi|
  bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|
  cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|fi|fj|fk|fm|fo|fr|ga|gb|gd|
  ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|
  in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|
  lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|
  mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|
  pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|
  tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|
  ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw|

  # http://www.iana.org/gtld/gtld.htm
  aero| biz| com| coop| info| museum| name| net| org| pro| gov| edu| mil| int|
  
  # http://www.iana.org/arpa-dom/
  arpa

  # just in case... futureproofing 
  eu
  
  )
}ix;

# This is required because the .us domain is nuts. See $THREE_LEVEL_DOMAINS
# and $FOUR_LEVEL_DOMAINS below.
#
$US_STATES = qr{ (?:
  ak|al|ar|az|ca|co|ct|dc|de|fl|ga|gu|hi|ia|id|il|in|ks|ky|la|ma|md|me|mi|
  mn|mo|ms|mt|nc|nd|ne|nh|nj|nm|nv|ny|oh|ok|or|pa|pr|ri|sc|sd|tn|tx|ut|va|vi|
  vt|wa|wi|wv|wy )
}ix;

# updated: 2004-04-30: first rev
#
$THREE_LEVEL_DOMAINS = qr( (?:
  demon\.co\.uk |

  # http://www.neustar.us/policies/docs/rfc_1480.txt
  [^\.]+\.${US_STATES}\.us )
)ix;

$FOUR_LEVEL_DOMAINS = qr( (?:
  # http://www.neustar.us/policies/docs/rfc_1480.txt
  # "Fire-Dept.CI.Los-Angeles.CA.US"
  # "<school-name>.PVT.K12.<state>.US"

  pvt\.k12\.${US_STATES}\.us
  c[io]\.[^\.]+\.${US_STATES}\.us
)
)ix;

# updated: 2004-04-30: first rev
$TWO_LEVEL_DOMAINS = qr{ (?:

  # http://www.neustar.us/policies/docs/rfc_1480.txt

  fed\.us |
  dni\.us |

  # data from http://spamcheck.freeapp.net/two-level-tlds , in turn from
  # http://www.bestregistrar.com/help/ccTLD.htm

  com\.ac |
  edu\.ac |
  gov\.ac |
  net\.ac |
  mil\.ac |
  org\.ac |
  com\.ae |
  net\.ae |
  org\.ae |
  com\.ar |
  net\.ar |
  org\.ar |
  co\.at |
  ac\.at |
  com\.au |
  org\.au |
  gov\.au |
  org\.au |
  edu\.au |
  id\.au |
  oz\.au |
  info\.au |
  net\.au |
  asn\.au |
  csiro\.au |
  telememo\.au |
  conf\.au |
  com\.az |
  net\.az |
  org\.az |
  com\.bb |
  net\.bb |
  org\.bb |
  ac\.be |
  belgie\.be |
  dns\.be |
  fgov\.be |
  com\.bm |
  edu\.bm |
  gov\.bm |
  org\.bm |
  net\.bm |
  art\.br |
  sp\.br |
  com\.br |
  etc\.br |
  g12\.br |
  gov\.br |
  ind\.br |
  inf\.br |
  mil\.br |
  net\.br |
  org\.br |
  psi\.br |
  rec\.br |
  tmp\.br |
  com\.bs |
  net\.bs |
  org\.bs |
  ab\.ca |
  bc\.ca |
  mb\.ca |
  nb\.ca |
  nf\.ca |
  ns\.ca |
  nt\.ca |
  nu\.ca |
  on\.ca |
  pe\.ca |
  qc\.ca |
  sk\.ca |
  yk\.ca |
  co\.ck |
  com\.cn |
  edu\.cn |
  gov\.cn |
  net\.cn |
  org\.cn |
  ac\.cn |
  ah\.cn |
  bj\.cn |
  cq\.cn |
  gd\.cn |
  gs\.cn |
  gx\.cn |
  gz\.cn |
  hb\.cn |
  he\.cn |
  hi\.cn |
  hk\.cn |
  hl\.cn |
  hn\.cn |
  jl\.cn |
  js\.cn |
  ln\.cn |
  mo\.cn |
  nm\.cn |
  nx\.cn |
  qh\.cn |
  sc\.cn |
  sn\.cn |
  sh\.cn |
  sx\.cn |
  tj\.cn |
  tw\.cn |
  xj\.cn |
  xz\.cn |
  yn\.cn |
  zj\.cn |
  arts\.co |
  com\.co |
  edu\.co |
  firm\.co |
  gov\.co |
  info\.co |
  int\.co |
  nom\.co |
  mil\.co |
  org\.co |
  rec\.co |
  store\.co |
  web\.co |
  ac\.cr |
  co\.cr |
  ed\.cr |
  fi\.cr |
  go\.cr |
  or\.cr |
  sa\.cr |
  com\.cu |
  net\.cu |
  org\.cu |
  ac\.cy |
  com\.cy |
  gov\.cy |
  net\.cy |
  org\.cy |
  art\.do |
  com\.do |
  edu\.do |
  gov\.do |
  org\.do |
  mil\.do |
  net\.do |
  web\.do |
  com\.ec |
  k12\.ec |
  edu\.ec |
  fin\.ec |
  med\.ec |
  gov\.ec |
  mil\.ec |
  org\.ec |
  net\.ec |
  com\.eg |
  edu\.eg |
  eun\.eg |
  gov\.eg |
  net\.eg |
  org\.eg |
  sci\.eg |
  ac\.fj |
  com\.fj |
  gov\.fj |
  id\.fj |
  org\.fj |
  school\.fj |
  asso\.fr |
  nom\.fr |
  barreau\.fr |
  com\.fr  |
  prd\.fr  |
  presse\.fr  |
  tm\.fr  |
  aeroport\.fr |
  assedic\.fr |
  avocat\.fr |
  avoues\.fr |
  cci\.fr |
  chambagri\.fr |
  chirurgiens-dentistes\.fr |
  experts-comptables\.fr |
  geometre-expert\.fr |
  gouv\.fr |
  greta\.fr |
  huissier-justice\.fr |
  medecin\.fr |
  notaires\.fr |
  pharmacien\.fr |
  port\.fr |
  veterinaire\.fr |
  notaires\.fr |
  com\.ge |
  edu\.ge |
  gov\.ge |
  mil\.ge |
  net\.ge |
  org\.ge |
  pvt\.ge |
  co\.gg |
  org\.gg |
  sch\.gg |
  ac\.gg |
  gov\.gg |
  ltd\.gg |
  ind\.gg |
  net\.gg |
  alderney\.gg |
  guernsey\.gg |
  sark\.gg |
  com\.gu |
  edu\.gu |
  net\.gu |
  org\.gu |
  gov\.gu |
  mil\.gu |
  com\.hk |
  net\.hk |
  org\.hk |
  co\.hu |
  org\.hu |
  info\.hu |
  nui\.hu |
  priv\.hu |
  tm\.hu |
  ac\.id |
  co\.id |
  go\.id |
  mil\.id |
  net\.id |
  or\.id |
  co\.il |
  net\.il |
  org\.il |
  ac\.il |
  gov\.il |
  k12\.il |
  muni\.il |
  co\.im |
  net\.im |
  org\.im |
  ac\.im |
  lkd\.co\.im |
  gov\.im |
  nic\.im |
  plc\.co\.im |
  co\.in |
  net\.in |
  ac\.in |
  ernet\.in |
  gov\.in |
  nic\.in |
  res\.in |
  co\.je |
  net\.je |
  org\.je |
  ac\.je |
  gov\.je |
  ind\.je |
  jersey\.je |
  ltd\.je |
  sch\.je |
  com\.jo |
  net\.jo |
  gov\.jo |
  edu\.jo |
  ad\.jp |
  ac\.jp |
  co\.jp |
  net\.jp |
  org\.jp |
  gov\.jp |
  com\.kh |
  net\.kh |
  org\.kh |
  ac\.kr |
  co\.kr |
  go\.kr |
  nm\.kr |
  or\.kr |
  pe\.kr |
  re\.kr |
  com\.la |
  net\.la |
  org\.la |
  com\.lb |
  org\.lb |
  net\.lb |
  gov\.lb |
  mil\.lb |
  com\.lc |
  edu\.lc |
  gov\.lc |
  net\.lc |
  org\.lc |
  com\.lv |
  net\.lv |
  org\.lv |
  edu\.lv |
  gov\.lv |
  mil\.lv |
  id\.lv |
  asn\.lv |
  conf\.lv |
  com\.ly |
  net\.ly |
  org\.ly |
  com\.mm |
  net\.mm |
  org\.mm |
  edu\.mm |
  gov\.mm |
  com\.mo |
  net\.mo |
  org\.mo |
  edu\.mo |
  gov\.mo |
  com\.mt |
  net\.mt |
  org\.mt |
  com\.mx |
  net\.mx |
  org\.mx |
  com\.my |
  org\.my |
  gov\.my |
  edu\.my |
  net\.my |
  com\.na |
  org\.na |
  net\.na |
  com\.nc |
  net\.nc |
  org\.nc |
  gov\.ng |
  com\.ni |
  com\.np |
  net\.np |
  org\.np |
  gov\.np |
  ac\.nz |
  co\.nz |
  cri\.nz |
  gen\.nz |
  geek\.nz |
  govt\.nz |
  iwi\.nz |
  maori\.nz |
  mil\.nz |
  net\.nz |
  org\.nz |
  school\.nz |
  com\.pa |
  net\.pa |
  org\.pa |
  edu\.pa |
  ac\.pa |
  gob\.pa |
  sld\.pa |
  com\.pe |
  net\.pe |
  org\.pe |
  ac\.pa |
  com\.ph |
  net\.ph |
  org\.ph |
  mil\.ph |
  ngo\.ph |
  com\.pl |
  net\.pl |
  org\.pl |
  com\.py |
  net\.py |
  org\.py |
  edu\.py |
  asso\.re |
  com\.re |
  nom\.re |
  com\.ru |
  net\.ru |
  org\.ru |
  pp\.ru |
  com\.sg |
  net\.sg |
  org\.sg |
  edu\.sg |
  gov\.sg |
  com\.sh |
  net\.sh |
  org\.sh |
  edu\.sh |
  gov\.sh |
  mil\.sh |
  co\.sv |
  com\.sy |
  net\.sy |
  org\.sy |
  ac\.th |
  co\.th |
  go\.th |
  net\.th |
  or\.th |
  com\.tn |
  net\.tn |
  org\.tn |
  edunet\.tn |
  gov\.tn |
  ens\.tn |
  fin\.tn |
  nat\.tn |
  ind\.tn |
  info\.tn |
  intl\.tn |
  rnrt\.tn |
  rnu\.tn |
  rns\.tn |
  tourism\.tn |
  com\.tr |
  net\.tr |
  org\.tr |
  edu\.tr |
  gov\.tr |
  mil\.tr |
  bbs\.tr |
  k12\.tr |
  co\.tv |
  com\.tw |
  net\.tw |
  org\.tw |
  edu\.tw |
  idv\.tw |
  gove\.tw |
  com\.ua |
  net\.ua |
  gov\.ua |
  ac\.ug |
  co\.ug |
  or\.ug |
  go\.ug |
  co\.uk |
  net\.uk |
  org\.uk |
  ltd\.uk |
  plc\.uk |
  sch\.uk |
  ac\.uk |
  gov\.uk |
  nhs\.uk |
  police\.uk |
  mod\.uk |
  com\.uy |
  edu\.uy |
  net\.uy |
  org\.uy |
  com\.ve |
  net\.ve |
  org\.ve |
  co\.ve |
  edu\.ve |
  gov\.ve |
  mil\.ve |
  arts\.ve |
  bib\.ve |
  firm\.ve |
  info\.ve |
  int\.ve |
  nom\.ve |
  rec\.ve |
  store\.ve |
  tec\.ve |
  web\.ve |
  co\.vi |
  net\.vi |
  org\.vi |
  ac\.yu |
  co\.yu |
  edu\.yu |
  org\.yu |
  ac\.za |
  alt\.za |
  bourse\.za |
  city\.za |
  co\.za |
  edu\.za |
  gov\.za |
  law\.za |
  mil\.za |
  net\.za |
  ngo\.za |
  nom\.za |
  org\.za |
  school\.za |
  tm\.za |
  web\.za |
  gov\.zw |
  eu\.org |
  au\.com |
  e164\.arpa )
}ix;

###########################################################################

=item ($hostname, $domain) = split_domain ($fqdn)

Cut a fully-qualified hostname into the hostname part and the domain
part, splitting at the DNS registrar boundary.

Examples:

    "www.foo.com" => ( "www", "foo.com" )
    "www.foo.co.uk" => ( "www", "foo.co.uk" )

=cut

sub split_domain {
  my ($domain) = @_;

  # turn "host.dom.ain" into "dom.ain".
  my $hostname = '';

  if ($domain) {
    my $partsreqd;

    # www..spamassassin.org -> www.spamassassin.org
    $domain =~ tr/././s;

    # leading/trailing dots
    $domain =~ s/^\.+//;
    $domain =~ s/\.+$//;

    if ($domain =~ /${FOUR_LEVEL_DOMAINS}/io)     # Fire-Dept.CI.Los-Angeles.CA.US
    { $partsreqd = 5; }
    elsif ($domain =~ /${THREE_LEVEL_DOMAINS}/io) # demon.co.uk
    { $partsreqd = 4; }
    elsif ($domain =~ /${TWO_LEVEL_DOMAINS}/io)   # co.uk
    { $partsreqd = 3; }
    else                                          # com
    { $partsreqd = 2; }

    # drop any hostname parts, if we can.
    my @domparts = split (/\./, $domain);

    if (@domparts >= $partsreqd) {
      # reset the domain to the last $partsreqd parts
      $domain = join(".", splice(@domparts, -$partsreqd));
      # chopped is everything else ...
      $hostname = join(".", @domparts);
    }
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

=cut

sub is_domain_valid {
  my ($dom) = @_;

  # domains don't have whitespace
  return 0 if ($dom =~ /\s/);

  # ensure it ends in a known-valid TLD, and has at least 1 dot
  return 0 if ($dom !~ /\.${VALID_TLDS}$/io);

  return 1;     # nah, it's ok.
}

1;
