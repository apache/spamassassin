#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("redirectors_match");

use strict;
use Test::More;

require Mail::SpamAssassin::Plugin::Redirectors;

sub make_conf {
  my $conf = { url_redirector_params => qr/(?:url|u)=(.*)/i };
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'bing.com', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendgrid.com', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.r.af.d.sendibt2.com/tr/cl/', 'get');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'foo.example/tr/op/', 'head');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, 'bar.example/tr/op', 'head');
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
);

# clear_url_redirector tests add 4 more checks
plan tests => scalar(@cases) + 4;

for my $c (@cases) {
  my ($uri, $expect_method, $desc) = @$c;
  my $conf = make_conf();
  my $r = Mail::SpamAssassin::Plugin::Redirectors::_is_configured_redirector($uri, $conf);
  if (defined $expect_method) {
    is(($r ? $r->{method} : undef), $expect_method, $desc);
  } else {
    ok(!$r, $desc);
  }
}

# clear_url_redirector behavior
{
  my $conf = { url_redirector_params => qr/(?:url|u)=(.*)/i };
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendibt2.com/tr/cl/', 'get');
  Mail::SpamAssassin::Plugin::Redirectors::_add_redirector_entry($conf, '.sendibt2.com/tr/click/', 'get');

  Mail::SpamAssassin::Plugin::Redirectors::_clear_redirector_entry($conf, '.sendibt2.com/tr/cl/');
  ok(!Mail::SpamAssassin::Plugin::Redirectors::_is_configured_redirector('https://x.sendibt2.com/tr/cl/a', $conf),
     'clear removes /tr/cl/ path');
  ok( Mail::SpamAssassin::Plugin::Redirectors::_is_configured_redirector('https://x.sendibt2.com/tr/click/a', $conf),
     'clear leaves /tr/click/ path');

  Mail::SpamAssassin::Plugin::Redirectors::_clear_redirector_entry($conf, '.sendibt2.com/tr/click/');
  ok(!Mail::SpamAssassin::Plugin::Redirectors::_is_configured_redirector('https://x.sendibt2.com/tr/click/a', $conf),
     'clear removes last path');
  ok(!exists $conf->{url_redirector_suffix}->{'sendibt2.com'},
     'host entry dropped when paths empty');
}
