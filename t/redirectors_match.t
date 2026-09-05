#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("redirectors_match");

use strict;
use Test::More;

require Mail::SpamAssassin::Plugin::Redirectors;
require Mail::SpamAssassin::URI;

sub make_conf {
  my $conf = { url_redirector_params => qr/(?:url|u)=(.*)/i };
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'bing.com', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendgrid.com', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.r.af.d.sendibt2.com/tr/cl/', 'get');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'foo.example/tr/op/', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'bar.example/tr/op', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'baz.example/FOO', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'js.example', 'selenium');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.spa.example', 'selenium');
  return $conf;
}

my @cases = (
  # Bare-domain entry: exact host + auto-www only, no other subdomains.
  [ 'https://bing.com/',          'head', 'bare domain matches exact host' ],
  [ 'https://www.bing.com/x',     'head', 'bare domain matches www subdomain' ],
  [ 'https://mail.bing.com/x',    undef,  'bare domain does NOT match other subdomains' ],

  # Leading-dot entry: subdomains only, NOT the bare domain itself.
  [ 'https://sendgrid.com/x',     undef,  'leading-dot does NOT match bare domain' ],
  [ 'https://www.sendgrid.com/x', 'head', 'leading-dot matches www subdomain' ],
  [ 'https://a.b.sendgrid.com/x', 'head', 'leading-dot matches deep subdomain' ],

  # Multi-label leading-dot: still excludes the bare-domain form.
  [ 'https://r.af.d.sendibt2.com/tr/cl/abc',         undef, '.r.af.d.sendibt2.com does NOT match its own bare form' ],
  [ 'https://x.r.af.d.sendibt2.com/tr/cl/abc',       'get', '.r.af.d.sendibt2.com matches subdomain' ],
  [ 'https://gfbgghj.r.af.d.sendibt2.com/tr/cl/abc', 'get', '.r.af.d.sendibt2.com matches deeper subdomain' ],

  # Path-prefix gating, trailing slash in config (/tr/op/).
  [ 'https://gfbgghj.r.af.d.sendibt2.com/tr/op/abc', undef, 'path /tr/op blocked when only /tr/cl/ configured' ],
  [ 'https://foo.example/tr/op/abc', 'head', 'trailing-slash path matches /tr/op/abc' ],
  [ 'https://foo.example/tr/open',   undef, 'trailing-slash path does NOT match /tr/open' ],
  [ 'https://foo.example/tr/op/',    'head', 'trailing-slash path matches itself' ],
  [ 'https://foo.example/tr/op',     undef, 'trailing-slash path does NOT match bare /tr/op' ],

  # Path-prefix gating, no trailing slash in config (/tr/op).
  [ 'https://bar.example/tr/op',      'head', 'no-trailing-slash matches bare path' ],
  [ 'https://bar.example/tr/op/',     'head', 'no-trailing-slash matches with trailing slash' ],
  [ 'https://bar.example/tr/op/abc',  'head', 'no-trailing-slash matches with sub-path' ],
  [ 'https://bar.example/tr/op?x=1',  'head', 'no-trailing-slash matches with query string' ],
  [ 'https://bar.example/tr/op#frag', 'head', 'no-trailing-slash matches with fragment' ],
  [ 'https://bar.example/tr/open',    undef,  'no-trailing-slash does NOT match /tr/open' ],
  [ 'https://bar.example/tr/opfoo',   undef,  'no-trailing-slash does NOT match /tr/opfoo' ],
  
  # A percent-encoded host must still match a configured entry: the host is
  # decoded before the lookup, so encoding a dot cannot hide a redirector.
  [ 'https://bar%2Eexample/tr/op', 'head', 'encoded host still matches configured redirector' ],
  # An encoded slash is different, and must NOT be treated as a path
  # separator. There is no real "/" after the host here, so the whole of
  # "foo.example%2Ftr%2Fop%2Fabc" is the authority; decoding it yields
  # "foo.example/tr/op/abc", which is not a resolvable hostname and which no
  # MUA would fetch. The CPAN URI module reports the same host and an empty
  # path, and is_fqdn_valid() rejects it, so there is no evasion to see
  # through -- unlike the encoded dot above.
  [ 'https://foo.example%2Ftr%2Fop%2Fabc', undef, 'encoded slash does NOT split the authority into host and path' ],

  # Uppercase path
  [ 'https://baz.example/FOO', 'head', 'uppercase path' ],

  # Selenium method round-trips through the entry.
  [ 'https://js.example/',           'selenium', 'selenium method on bare-domain entry' ],
  [ 'https://www.js.example/foo',    'selenium', 'selenium method on www subdomain' ],
  [ 'https://other.js.example/foo',  undef,      'bare-domain selenium does NOT match other subdomains' ],
  [ 'https://app.spa.example/foo',   'selenium', 'selenium method on leading-dot subdomain' ],
);

# A param value is only an embedded URI when it actually looks like one. A bare
# token (referral code, label) must NOT be turned into a fabricated http://<token>.
# Use a param list that includes the short params (r, redirect) that produced the
# original Substack false positives, not just url/u.
my $embedded_conf =
  { url_redirector_params => qr/(?:url|u|uri|r|redir|redirect)=(.*)/i };
my @embedded = (
  # [ uri, expected_extraction (undef = no embedded uri), desc ]
  [ 'https://safe.example/?url=https://evil.com/path', 'https://evil.com/path',
    'explicit scheme is extracted' ],
  [ 'https://safe.example/?url=evil.com/landing', 'http://evil.com/landing',
    'bare host.tld/path is extracted' ],
  [ 'https://safe.example/?url=//evil.com/path', 'http://evil.com/path',
    'scheme-relative //host is extracted' ],
  [ 'https://safe.example/?url=//////evil.com/path', 'http://evil.com/path',
    'scheme-relative host with padded slash run is extracted' ],
  [ 'https://login.microsoft.com//////////////////////////////common/oauth2/v2.0/authorize?state=1202',
    undef,
    'slash run followed by a dotless path segment is NOT an embedded uri' ],
  [ 'https://safe.example/?url=////////', undef,
    'bare slash run with no host is NOT an embedded uri' ],
  [ 'https://safe.example/?url=https%253A%252F%252Fevil.com%252Fpath',
    'https://evil.com/path',
    'double-encoded scheme is decoded' ],
  [ 'https://safe.example/?url=https://evil.com/path&utm_source=news&id=42',
    'https://evil.com/path',
    'extraction stops at the parameter boundary, not end of querystring' ],
  [ 'https://safe.example/?url=https%3A%2F%2Fevil.com%2Fpath&utm_source=news',
    'https://evil.com/path',
    'encoded target stops at the parameter boundary' ],
  # Real-world sample: a padded slash run in the path plus a double-encoded
  # uri= target and trailing binary padding. The uri= target is the real
  # destination and must come back clean.
  [ 'https://login.microsoft.com//////////////////////////////common/oauth2/v2.0/authorize?state=1202&scope=openid+profile+https%253A%252F%252Fgraph.microsoft.com%252FUser.Read&prompt=none&client_id=967ac14a-0b4d-4175-ab8d-694fdba23afa&uri=https%253A%252F%252Fdeveloper.salesforce.com%252Fdashboard%252Fsession%252Fuser%252Fverify%252Fstep1&%255Ca3edq%250C+2e4c%250D%250A%2593bb66f835%2509%258C2979X%25BCint+Builder.Decode%250A%2509Context+%253A%253D+FlowEmail+%255B+OffsetStream+%253A=%2520Token%2509Data%2520%257C%2520Email%257Dfor%2520Stream%253A%253DPayloadBuilder+;+ValueContext+%257D+Trace%250A%2509Decode+.+SignalVector+%257B%2520Offset%257D%250Aa78c998ef06b569e%2597%25E9%252A%25CBa93627d06a07eba872664f4a92c74eae25f60308d1cad09a16e7beef0b79c03d8bd7528c4a7efc8bdb3fc053evar%252BVector-Secret%25250A%252509Decode%252B%25253B%252BBuffer%25250A%252509Encode%252B-%252BSession%25250A%252509Decode%252B%25255D%252BPayload%25250A%252509Offset%252B%25252B%252BBuilder%25250A%252509Builder%252B%252528%252BToken%25250A%252509Encode%252B.%252BKey%25250A%252509Context%252B%25257B%252BToken%25250A%25257D%25250Aelse%252BDecode%25252CBuilder%25250A%252509Stream%252B%25253A%25253D%252BHeader%25250A%252509Vector%252B%252526%252BVector%25250A%252509Payload%252B%25253D%252BBuilder%25250A%252509Value%252B%25257C%252BPayload%25250A%252509Secret%252B%25253D%252BBuffer%25250A%25257D%25250Aswitch%252BPayload%25252CSession%25250A%252509Payload%252B%252529%252BToken%25250A%252509Payload%252B%252526%252BBuilder%25250A%252509Data%252B%25257C%252BDecode%25250A%252509Secret%252B%25255B%252BStream%25250A%25257D%25250Astring%252BBody%252529Session%25250A%252509Session%252B%252528%252BTrace%25250A%252509Buffer%252B%25257B%252BSession%25250A%252509Vector%252B%25252A%252BVector%25250A%252509Context%252B%25253B%252BToken%25250A%252509Value%252B%25252A%252BData%25250A%252509Encode%252B%25253B%252BFlow%25250A%252509Trace%252B%252529%252BTrace%25250A%25257D%25250Aint%252BToken%25257CSignal%25250A%252509Header%252B%25255D%252BFlow%25250A%252509Body%252B.%252BKey%25250A%252509Vector%252B%252528%252BSignal%25250A%252509Session%252B%25252C%252BData%25250A%25257D%25250Ac2FuZGVlcEBmdmNvbS5hZQ==',
    'https://developer.salesforce.com/dashboard/session/user/verify/step1',
    'padded microsoft.com oauth lure yields the real salesforce target' ],
  [ 'https://safe.example/?url=evil.com%2Fp%3Fx%3D1%26tid%3Dgood.com',
    'http://evil.com/p?x=1&tid=good.com',
    'encoded separators stay inside the embedded value' ],
  # An embedded target under a parameter name that is NOT in the configured
  # param list is still found by the bare-embedded-URI fallback. That fallback
  # looks for a literal "//", so it has to recognise the encoded separators
  # too, both single (%3A%2F%2F) and double (%253A%252F%252F) encoded.
  [ 'https://safe.example/?foo=https://example.com', 'https://example.com',
    'unlisted param with a plain embedded uri is extracted' ],
  [ 'https://safe.example/?foo=https%3A%2F%2Fexample.com', 'https://example.com',
    'unlisted param with an encoded embedded uri is extracted' ],
  [ 'https://safe.example/?foo=https%253A%252F%252Fexample.com', 'https://example.com',
    'unlisted param with a double-encoded embedded uri is extracted' ],
  # ...and the fallback must not truncate the embedded URL at its own encoded
  # query separator: only a real "&" ends the value. Matching the encoded form
  # in place (rather than searching a decoded copy of the querystring) is what
  # keeps %26 inside the value here.
  [ 'https://safe.example/?foo=https%3A%2F%2Fevil.com%2Fp%3Fx%3D1%26tid%3Dgood.com',
    'https://evil.com/p?x=1&tid=good.com',
    'unlisted param keeps encoded separators inside the embedded value' ],
  [ 'https://safe.example/?foo=https%253A%252F%252Fevil.com%252Fp%253Fa%253D1%2526b%253D2',
    'https://evil.com/p?a=1&b=2',
    'unlisted param keeps double-encoded separators inside the embedded value' ],
  # Only the path and query are searched, so the wrapper's own host does not
  # have to look like one worth following: a dotless intranet host can still
  # be hiding a target in its querystring.
  [ 'https://localhost/?url=https://evil.com/path', 'https://evil.com/path',
    'a dotless host is still searched for an embedded uri' ],
  [ 'https://substack.com/signup?foo=bar&r=to8ex', undef,
    'bare referral token (r=) is NOT an embedded uri' ],
  [ 'https://open.substack.com/notes?utm_campaign=open-in-app&redirect=app-store-no-desktop', undef,
    'bare hyphenated label (redirect=) is NOT an embedded uri' ],
);

# +1 no-capture-group check, +4 clear_url_redirector checks
plan tests => scalar(@cases) + scalar(@embedded) + 1 + 2 + 4;

for my $c (@cases) {
  my ($uri, $expect_method, $desc) = @$c;
  my $conf = make_conf();
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_lookup_redirector(
            Mail::SpamAssassin::URI->new($uri), $conf);
  if (defined $expect_method) {
    is(($r ? $r->{method} : undef), $expect_method, $desc);
  } else {
    ok(!$r, $desc);
  }
}

for my $c (@embedded) {
  my ($uri, $expect, $desc) = @$c;
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_extract_embedded_uri(
            Mail::SpamAssassin::URI->new($uri), $embedded_conf);
  if (defined $expect) {
    is($r, $expect, $desc);
  } else {
    ok(!defined $r, $desc);
  }
}

# A url_redirector_params regex may capture a subset of the value, which is how
# an admin digs the target out of a value that wraps it.  The capture is used
# when there is one, and the whole value when there is not.
{
  my $wrapped_conf =
    { url_redirector_params => qr/(?:u)=\d+\|(https?:\/\/.*)/i };
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_extract_embedded_uri(
    Mail::SpamAssassin::URI->new('https://safe.example/?u=12345|https://evil.com/p'),
    $wrapped_conf);
  is($r, 'https://evil.com/p', 'capture group pulls the target out of a wrapper');
}

{
  my $nocap_names =
    { url_redirector_params => qr/(?:u|url)=/i };
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_extract_embedded_uri(
    Mail::SpamAssassin::URI->new('https://safe.example/?u=https://evil.com/p'),
    $nocap_names);
  is($r, 'https://evil.com/p', 'without a capture group the whole value is used');
}

# A url_redirector_params regex with no capture group leaves $1 undefined; the
# extractor must bail rather than fabricate a bare "http://".
{
  my $nocap_conf = { url_redirector_params => qr/(?:r|redirect)=[^&]+/i };
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_extract_embedded_uri(
    Mail::SpamAssassin::URI->new('https://substack.com/signup?foo=bar&r=to8ex'),
    $nocap_conf);
  ok(!defined $r, 'no-capture-group param regex yields no embedded uri');
}

# clear_url_redirector behavior
{
  my $conf = { url_redirector_params => qr/(?:url|u)=(.*)/i };
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendibt2.com/tr/cl/', 'get');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendibt2.com/tr/click/', 'get');

  Mail::SpamAssassin::Plugin::Redirectors::_clear_redirector_entry($conf, '.sendibt2.com/tr/cl/');
  ok(!Mail::SpamAssassin::Plugin::Redirectors::_lookup_redirector(
       Mail::SpamAssassin::URI->new('https://x.sendibt2.com/tr/cl/a'), $conf),
     'clear removes /tr/cl/ path');
  ok( Mail::SpamAssassin::Plugin::Redirectors::_lookup_redirector(
       Mail::SpamAssassin::URI->new('https://x.sendibt2.com/tr/click/a'), $conf),
     'clear leaves /tr/click/ path');

  Mail::SpamAssassin::Plugin::Redirectors::_clear_redirector_entry($conf, '.sendibt2.com/tr/click/');
  ok(!Mail::SpamAssassin::Plugin::Redirectors::_lookup_redirector(
       Mail::SpamAssassin::URI->new('https://x.sendibt2.com/tr/click/a'), $conf),
     'clear removes last path');
  ok(!exists $conf->{url_redirector_suffix}->{'sendibt2.com'},
     'host entry dropped when paths empty');
}
