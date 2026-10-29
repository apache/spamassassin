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

Redirectors - Check for redirected and shortened URLs

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::Redirectors

  url_redirector bing.com
  url_shortener tinyurl.com

  body HAS_REDIR_URL          eval:redir_url()
  describe HAS_REDIR_URL      Message has one or more redirected URLs

  body REDIR_URL_VALID        eval:redir_url_valid()
  describe REDIR_URL_VALID    Message has a redirector that returned a valid redirection

  body REDIR_URL_CHAINED      eval:redir_url_chained()
  describe REDIR_URL_CHAINED  Message has redirected URL chained to other redirectors

  body REDIR_URL_CHAINED_DOM      eval:redir_url_chained_domain()
  describe REDIR_URL_CHAINED_DOM  Message has redirected URL chained to another redirector on the same domain

  body REDIR_URL_MAXCHAIN     eval:redir_url_maxchain()
  describe REDIR_URL_MAXCHAIN Message has redirected URL that causes too many redirections

  body REDIR_URL_LOOP         eval:redir_url_loop()
  describe REDIR_URL_LOOP     Message has redirected URL that loops back to itself

  body REDIR_URL_404          eval:redir_url_code('404') # Can check any non-redirect HTTP code
  describe REDIR_URL_404      Message has redirected URL returning HTTP 404

  body HAS_SHORT_URL          eval:short_url()
  describe HAS_SHORT_URL      Message has one or more shortened URLs

  body SHORT_URL_REDIR        eval:short_url_redir()
  describe SHORT_URL_REDIR    Message has shortened URL that resulted in a valid redirection

  body SHORT_URL_CHAINED      eval:short_url_chained()
  describe SHORT_URL_CHAINED  Message has shortened URL chained to other shorteners

  body SHORT_URL_MAXCHAIN     eval:short_url_maxchain()
  describe SHORT_URL_MAXCHAIN Message has shortened URL that causes too many redirections

  body SHORT_URL_LOOP         eval:short_url_loop()
  describe SHORT_URL_LOOP     Message has short URL that loops back to itself

  body SHORT_URL_200          eval:short_url_code('200') # Can check any non-redirect HTTP code
  describe SHORT_URL_200      Message has shortened URL returning HTTP 200

  body SHORT_URL_404          eval:short_url_code('404') # Can check any non-redirect HTTP code
  describe SHORT_URL_404      Message has shortened URL returning HTTP 404

  uri URI_TINYURL_BLOCKED      m,https://tinyurl\.com/app/nospam,
  describe URI_TINYURL_BLOCKED Message contains a tinyurl that has been disabled due to abuse

  uri URI_BITLY_BLOCKED       m,^https://bitly\.com/a/blocked,
  describe URI_BITLY_BLOCKED  Message contains a bit.ly URL that has been disabled due to abuse

=head1 DESCRIPTION

This plugin looks for URLs redirected or shortened by a list of URL
redirector/shortener services.  Upon finding a matching URL, plugin will
send a HTTP request to the service and retrieve the Location-header which
points to the actual destination URL.  It then adds this URL to the list of
URIs extracted by SpamAssassin which can then be accessed by uri rules and
plugins such as URIDNSBL.

For hosts listed with C<url_redirector> or C<url_redirector_get>, the
request is made with Perl's LWP library (libwww-perl), without a browser.
This documentation calls these two methods "LWP", in contrast to the
Selenium browser used for hosts listed with C<url_redirector_selenium>.

This plugin will follow chained redirections, where a redirected URL leads
to another redirector, in any combination and order -- for example a
redirector that unwraps into what used to be called a "shortener", or vice
versa.  There is no functional difference between a "redirector" and a
"shortener": both are just a domain whose HTTP response redirects
somewhere else, and both are followed by the same code path.
C<url_shortener>/C<url_shortener_get>/C<url_shortener_custom_user_agent>
and their C<max_short_url*>/C<url_shortener_cache_*>/etc. settings are kept
as deprecated aliases of C<url_redirector>/C<url_redirector_get>/etc. for
backwards compatibility, and are planned for removal in a future version.
Likewise, C<short_url()> and its sibling eval rules are aliases of
C<redir_url()> and friends. Redirection depth is limited by
C<max_redir_url_redirections>, and C<max_redir_urls> redirector URLs are
checked in a message (10 by default); setting it to 0 disables HTTP
requests, allowing only C<redir_url()> to work and report found
redirectors.

All supported rule types for checking redirected URLs and redirection
status are documented in L<SYNOPSIS> section.

=head1 NOTES

This plugin runs before priority 0 so that it may modify the parsed URI
list prior to normal uri rules or the URIDNSBL plugin.

=head1 SECURITY CONSIDERATIONS

When C<url_redirector_selenium_host> is set, the Selenium server runs a
real browser that opens URLs chosen by the senders of incoming mail. Read
F<Redirectors-Selenium-Security.pod> before setting it. The file is in the
F<docs> directory of the SpamAssassin distribution, and C<make install>
installs it in the documentation directory, by default
F<PREFIX/share/doc/spamassassin>. To read it, run C<perldoc> with the
file's path.

=head1 ACKNOWLEDGEMENTS

The url_shortener functionality was originally provided by a separate
DecodeShortURLs plugin; that functionality has been merged into this one,
and C<Mail::SpamAssassin::Plugin::DecodeShortURLs> is now a deprecated
compatibility shim that loads this plugin.

=cut

package Mail::SpamAssassin::Plugin::Redirectors;

use Mail::SpamAssassin::Plugin;
use NetAddr::IP 4.000;
use Mail::SpamAssassin::Util qw(compile_regexp);
use Mail::SpamAssassin::URI;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Timeout;
use Time::HiRes ();
use Scalar::Util qw(refaddr);
use MIME::Base64 ();
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 4.10;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; require LWP::Protocol::https; };
use constant HAS_SELENIUM => eval { require Selenium::Chrome; };

sub dbg { my $msg = shift; return Mail::SpamAssassin::Logger::dbg("Redirectors: $msg", @_); }
sub info { my $msg = shift; return Mail::SpamAssassin::Logger::info("Redirectors: $msg", @_); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  if ($mailsaobject->{local_tests_only}) {
    dbg("local tests only, disabling HTTP requests");
    $self->{net_disabled} = 1;
  }
  elsif (!HAS_LWP_USERAGENT) {
    dbg("module LWP::UserAgent not installed, disabling HTTP requests");
    $self->{net_disabled} = 1;
  }

  $self->set_config($mailsaobject->{conf});
  # run at priority -15 so that redirected/shortened uris are always
  # checked in a single pass, regardless of what type of hop starts a chain
  $self->register_method_priority ('check_dnsbl', -15);
  $self->register_eval_rule('redir_url', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_valid', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_404', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_code', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_chained', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_chained_domain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_maxchain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_loop', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_redir', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_200', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_404', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_code', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_chained', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_maxchain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_loop', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_tests'); # for legacy DecodeShortURLs compatibility warning

  return $self;
}

use constant SELENIUM_QUIT_TIMEOUT => 5;

# How long each WebDriver request made while a session is being created
# may wait for the Selenium server, in seconds
use constant SELENIUM_CREATE_TIMEOUT => 10;

# Quit one Selenium session, bounding how long the quit may block.
sub _quit_selenium_ua {
  my ($self, $ua) = @_;
  return unless defined $ua;
  my $t = Mail::SpamAssassin::Timeout->new({ secs => SELENIUM_QUIT_TIMEOUT });
  my $err = $t->run_and_catch(sub { $ua->quit() });
  if ($t->timed_out()) {
    dbg("Selenium session quit exceeded ${\ SELENIUM_QUIT_TIMEOUT}s and was "
        . "abandoned; the session will be left for the Selenium server's own "
        . "session timeout to reclaim");
  } elsif (defined $err && $err =~ /child processing timeout/) {
    (my $e = $err) =~ s/\s+/ /g;
    $e =~ s/ \z//;
    info("spamd child processing timeout reached while quitting the "
         . "Selenium session; absorbed so the child carries on, and the "
         . "session is left for the Selenium server's own session timeout "
         . "to reclaim ($e)");
  } elsif (defined $err && $err ne '') {
    dbg("Error quitting Selenium session: $err");
  }
}

sub per_msg_finish {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $ua = $pms->{redir_selenium_ua};
  my $leftover = delete $self->{redir_selenium_live_ua};

  if (defined $leftover && !(defined $ua && refaddr($ua) == refaddr($leftover))) {
    dbg("quitting a Selenium session that is not this message's own: left "
        . "open by a previous message whose check() did not reach finish(), "
        . "or a kept session set aside at a processing deadline");
    $self->_quit_selenium_ua($leftover);
  }

  return unless defined $ua;
  if ($pms->{conf}->{url_redirector_selenium_reuse_session}
      && !$pms->{redir_deadline_abandoned}) {
    $self->{redir_selenium_kept_ua} = $ua;
    $self->{redir_selenium_kept_args} = $pms->{redir_selenium_args};
    dbg("keeping Selenium session " . $ua->{session_id}
        . " for the next message (url_redirector_selenium_reuse_session)");
    return;
  }
  $self->_quit_selenium_ua($ua);
}

=head1 ADMINISTRATOR SETTINGS

=over 4

=item url_redirector  domain[/path] [domain[/path]...]     (default: none)

Domains that should be considered as a URL redirector.

Domain matching:

=over 4

=item *

A bare domain (e.g. C<bing.com>) matches that exact host and also C<www.bing.com>.

=item *

A leading dot (e.g. C<.sendgrid.com>) matches any subdomain of the domain,
to any depth. It does NOT match the bare domain itself; to match both, also
list the bare domain (C<sendgrid.com>).

=back

An optional C</path> may follow the domain to restrict matching to URLs whose
path begins with that string and ends at a path-segment boundary. C</tr/op> matches
C</tr/op>, C</tr/op/foo>, and C</tr/op?x=1>, but NOT C</tr/open> -- the
configured prefix is treated as one or more whole path segments. Append a
trailing slash (C</tr/op/>) to require at least one more segment after it
(matches C</tr/op/foo> but not bare C</tr/op>). Multiple entries for the
same domain are additive (allowlist); a URL is followed if it matches any
entry.

A bare-domain entry without a path is equivalent to C<domain/>, which matches
any path.

Example:

 url_redirector bing.com
 url_redirector .sendgrid.com
 url_redirector .sendibt2.com/tr/cl/

The last line follows C<https://x.y.sendibt2.com/tr/cl/abc> but not
C<https://x.y.sendibt2.com/tr/op/abc>.

C<url_shortener> (and C<url_shortener_get>, C<clear_url_shortener>) are
deprecated aliases of C<url_redirector> (and C<url_redirector_get>,
C<clear_url_redirector>) kept for backwards compatibility with configs
written for the old DecodeShortURLs plugin, there is no functional
difference between the two names, and the C<url_shortener*> spelling is
planned for removal in a future version.

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  # url_shortener is a pure alias of url_redirector, a "shortener" and a
  # "redirector" are the same mechanism (an HTTP redirect), the terminology
  # difference is not functional. Kept only for config backwards
  # compatibility; planned for removal in a future version.
  my $url_redirector_code = sub {
    my ($self, $key, $value, $line) = @_;
    if ($value eq '') {
      return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
    }
    foreach my $token (split(/\s+/, $value)) {
      _add_redirector_entry($self, $token, 'head');
    }
  };
  push (@cmds, {
    setting => 'url_redirector',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_code,
  });
  push (@cmds, {
    setting => 'url_shortener',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_code,
  });

=over 4

=item url_redirector_selenium_host (default: none)

Set Selenium host to use. Hosts listed in C<url_redirector_selenium> are
looked up only when this is set.

If the Selenium server does not answer when a session is created, each
message that needs a Selenium lookup can be delayed by up to about 20
seconds; if it answers but has no free session, by about 10.
Allow the server at least one session for each SpamAssassin process that
makes Selenium lookups.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_host',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_redirector_selenium_port (default: 4444)

Set Selenium port to use.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_port',
    default => 4444,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_redirector_selenium_reuse_session (0|1)  (default: 0)

If set, the browser session used for a message is kept for the next message
instead of being closed, so cookies, stored data and any page still running
carry over between messages.
This turns off the per-message isolation described under
L</SECURITY CONSIDERATIONS>. Read that before enabling it.

A kept session is closed if it does not answer when it is next needed, or
if the message that needs it uses different browser settings; otherwise the
Selenium server removes it when its session timeout expires.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_reuse_session',
    default => 0,
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=over 4

=item url_redirector_selenium_proxy scheme://host:port  (default: none)

The proxy the Selenium browser uses for the listed hosts. The scheme
is C<http>, C<https> or C<socks5>.
An IPv6 host literal must be bracketed (C<[::1]>).
The port is required.
Only one proxy is accepted. A proxy list, the per-scheme form
(C<http=host:port>) or C<direct://> is rejected, because it could let the
browser bypass the proxy.

The host is the proxy address as seen from the Selenium host or container,
not from SpamAssassin's host.

The browser's own host list applies with or without a proxy. A proxy
configured as described in L</SECURITY CONSIDERATIONS> looks up each
listed host name itself, refuses it if it resolves to an internal
address, and logs requests by host name. Without a proxy, the
firewall and resolver of the Selenium host must refuse internal
addresses.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_proxy',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
        # Unset is allowed: Selenium then runs with no proxy.
        $self->{url_redirector_selenium_proxy} = '';
        return;
      }

      if ($value =~ m{^direct://?$}i) {
        dbg("config: url_redirector_selenium_proxy: 'direct://' would silently disable the proxy; leave the setting unset instead of naming it");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      if ($value =~ /[;,=\s]/) {
        dbg("config: url_redirector_selenium_proxy: '$value' invalid, a single proxy value cannot contain ';', ',', '=' or whitespace");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      my ($scheme, $host, $port) = $value =~ m{
        ^ (https?|socks5) ://
          ( \[ [^\]]* \] | [^/:\s]+ )
          : ([0-9]{1,5})
        $
      }xi;
      if (!defined $scheme || $port < 1 || $port > 65535) {
        dbg("config: url_redirector_selenium_proxy: '$value' invalid, expected scheme://host:port with scheme http, https or socks5");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $scheme = lc $scheme;

      my ($host_valid, $unspecified);
      if ($host =~ /^\[(.*)\]$/) {
        my $inner = $1;
        $host_valid = ($inner =~ /:/ && $inner !~ /^IPv6:/i
                       && $inner =~ IS_IP_ADDRESS);
        if ($host_valid) {
          my $ip = NetAddr::IP->new($inner);
          $unspecified = ($ip && $ip->short =~ /^::(?:ffff:0:0)?\z/i);
        }
      } elsif ($host =~ /^[0-9.]+$/) {
        $host_valid = ($host =~ IS_IPV4_ADDRESS);
        $unspecified = ($host eq '0.0.0.0');
      } else {
        $host_valid = ($host =~ m{
            ^ [A-Za-z0-9] (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
                (?:\. [A-Za-z0-9] (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])? )*
            $
          }x);
      }
      if (!$host_valid) {
        dbg("config: url_redirector_selenium_proxy: '$value' invalid, expected scheme://host:port with scheme http, https or socks5");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      if ($unspecified) {
        dbg("config: url_redirector_selenium_proxy: '$value' invalid, $host is an unspecified address, which a proxy listens on; give an address the browser can reach the proxy at");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{url_redirector_selenium_proxy} = "$scheme://$host:$port";
    },
  });

=over 4

=item clear_url_redirector  [domain[/path]] [domain[/path]...]

Clear domains configured with url_redirector, url_redirector_get or
url_redirector_selenium (or their url_shortener aliases), for example to
override default settings from an update channel.  If no arguments are given,
all entries are cleared. If domains are specified, only those are removed.

When an entry includes a C</path>, only that path is removed from the
domain's allowlist; the domain entry itself is dropped only when its path
list becomes empty. Use C<domain/> to remove the "match any path" entry
added by a bare-domain configuration.

=back

=cut

  my $clear_url_redirector_code = sub {
    my ($self, $key, $value, $line) = @_;
    if ($value eq '') {
      _clear_all_redirector_entries($self);
    } else {
      foreach my $token (split(/\s+/, $value)) {
        _clear_redirector_entry($self, $token);
      }
    }
  };
  push (@cmds, {
    setting => 'clear_url_redirector',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => $clear_url_redirector_code,
  });
  push (@cmds, {
    setting => 'clear_url_shortener',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => $clear_url_redirector_code,
  });

=over 4

=item url_redirector_get  domain[/path] [domain[/path]...]     (default: none)

Domains that should be considered as an URL redirector, accessed using the
HTTP GET method instead of HEAD. Syntax and matching rules are the same as
C<url_redirector>: a bare domain matches that host and C<www.>, a leading
dot matches any subdomain but not the domain itself, and an optional
C</path> prefix restricts the match.

=back

=cut

  my $url_redirector_get_code = sub {
    my ($self, $key, $value, $line) = @_;
    if ($value eq '') {
      return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
    }
    foreach my $token (split(/\s+/, $value)) {
      _add_redirector_entry($self, $token, 'get');
    }
  };
  push (@cmds, {
    setting => 'url_redirector_get',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_get_code,
  });
  push (@cmds, {
    setting => 'url_shortener_get',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_get_code,
  });

=over 4

=item url_redirector_selenium  domain[/path] [domain[/path]...]     (default: none)

Domains that should be fetched using Selenium (headless Chrome) instead of
LWP. Use this only for hosts whose redirects are NOT discoverable via
LWP, such as JavaScript-driven redirects. Syntax and matching rules are
the same as C<url_redirector>.

Selenium executes JavaScript on the destination and always sends GET,
which has weaker safety properties than the LWP path; reserve this list
for hosts that genuinely require browser-driven redirect unwrapping.

The browser connects only to the hosts listed here and in
C<url_redirector_selenium_resource>. Hosts listed here are matched as above
except that paths play no part: a redirect or script that leads to another
path on a listed host is followed, and one that leads to a host in neither
list is not. Its URL is then recorded as the redirect target without the
browser fetching it (see L</SECURITY CONSIDERATIONS>). A page that needs
resources from hosts not listed, such as scripts from a content delivery
network, loads without them, and a redirect that depends on them is not
seen; list such hosts with C<url_redirector_selenium_resource>.
Each time it creates a browser session, the plugin checks that the
browser refuses an address outside this list. If it does not, the plugin
closes the session and skips Selenium lookups, with one warning per
process.

If the same host appears in both C<url_redirector_selenium> and
C<url_redirector>/C<url_redirector_get>, the directive parsed last sets
the method for that host, including any paths listed for it under the
other directive, and a warning is emitted.

Hosts in this list are looked up only when C<url_redirector_selenium_host>
is set. Until then they are skipped (there is no fallback to LWP, since
these hosts wouldn't yield useful results via LWP), and C<redir_url()>
still fires for them so detection rules continue to work.

Due to how Selenium works, C<redir_url_code()> and C<redir_url_404> subs
will not fire for hosts handled by Selenium; Selenium reports only
"redirected" (301) or "not a redirect" (200), not real HTTP status codes.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $token (split(/\s+/, $value)) {
        _add_redirector_entry($self, $token, 'selenium');
      }
    }
  });

=over 4

=item url_redirector_selenium_resource  host [host...]     (default: none)

Hosts the Selenium browser may also fetch from, for pages on
C<url_redirector_selenium> hosts that load scripts or other resources from
another host. URLs on these hosts are not looked up.

Each entry matches only that exact host, not its C<www.> form or other
subdomains. IP addresses, paths, a leading dot and names under
C<.localhost> are not accepted.

List only hosts where senders cannot publish content, not a storage
service or a package CDN. See L</SECURITY CONSIDERATIONS>.

Example:

 url_redirector_selenium_resource code.jquery.com

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_resource',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my @hosts = map { lc } split(/\s+/, $value);
      foreach my $host (@hosts) {
        if (!_is_resource_host($host)) {
          dbg("config: url_redirector_selenium_resource: '$host' invalid, expected a host name such as code.jquery.com, without a path, leading dot or IP address, and not under .localhost");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
      }
      $self->{url_redirector_selenium_resource}->{$_} = 1 foreach @hosts;
    }
  });

=over 4

=item clear_url_redirector_selenium_resource  [host] [host...]

Clear configured url_redirector_selenium_resource hosts, for example to
override default settings from an update channel. If no arguments are
given, all hosts are cleared. If hosts are specified, only those are
removed.

=back

=cut

  push (@cmds, {
    setting => 'clear_url_redirector_selenium_resource',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        $self->{url_redirector_selenium_resource} = {};
      } else {
        foreach my $host (split(/\s+/, $value)) {
          delete $self->{url_redirector_selenium_resource}->{lc $host};
        }
      }
    }
  });

=over 4

=item url_skip_redirect_to  domain [domain...]     (default: none)

Domains that, when found as a redirect destination, should cause the redirect
chain to stop immediately. Useful to break loops caused by consent or gateway
pages that redirect back into the chain.

Example:

 url_skip_redirect_to consent.google.com

=back

=cut

  push (@cmds, {
    setting => 'url_skip_redirect_to',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_skip_redirect_to}->{lc $domain} = 1;
      }
    }
  });

=over 4

=item clear_url_skip_redirect_to  [domain] [domain...]

Clear configured url_skip_redirect_to domains. If domains are specified,
only those are removed from the list.

=back

=cut

  push (@cmds, {
    setting => 'clear_url_skip_redirect_to',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        $self->{url_skip_redirect_to} = {};
      } else {
        foreach my $domain (split(/\s+/, $value)) {
          delete $self->{url_skip_redirect_to}->{lc $domain};
        }
      }
    }
  });

=over 4

=item url_redirector_params regexp (default: (?:adurl|af_web_dp|cm_destination|continue|destination|destURL|goto|h|l|login|location|p1|pval|r|redir|redirect|redirectTo|ret_url|return|returnUrl|referer|service|target|tid|u|url)=(.*))

Regexp used to parse uri parameters in order to detect redirectors and to get redirected domains.
The regexp must match only the redirected domain.

=back

=cut

  push(@cmds, {
    setting => 'url_redirector_params',
    is_admin => 1,
    default => qr/(?:adurl|af_web_dp|cm_destination|continue|destination|destURL|goto|h|l|login|location|p1|pval|r|redir|redirect|redirectTo|ret_url|return|returnUrl|referer|service|target|tid|u|url)=(.*)/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
        dbg("config: invalid url_redirector_params '$value': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{url_redirector_params} = $rec;
    },
  });

=over 4

=item url_redirector_custom_user_agent domain user-agent  (default: none)

Custom HTTP user-agent to be used for specific domains,
instead of the default specified in C<url_redirector_user_agent>.
Required for some services like t.co to return blocked URL correctly.

Example:

 url_redirector_custom_user_agent t.co curl/8.6.0

=back

=cut

  my $url_redirector_custom_user_agent_code = sub {
    my ($self, $key, $value, $line) = @_;
    if ($value eq '') {
      return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
    }
    my @values = split(/\s+/, $value);
    my $domain = shift(@values);
    my $ua = join('', @values);
    $self->{url_redirector_custom_ua}->{lc $domain} = $ua;
  };
  push (@cmds, {
    setting => 'url_redirector_custom_user_agent',
    is_admin => 1,
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => $url_redirector_custom_user_agent_code,
  });
  push (@cmds, {
    setting => 'url_shortener_custom_user_agent',
    is_admin => 1,
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => $url_redirector_custom_user_agent_code,
  });

=over 4

=item url_redirector_cache_type     (default: none)

The cache type that is being utilized.  Currently only supported value is
C<dbi> that implies C<url_redirector_cache_dsn> is a DBI connect string.
DBI module is required.

Example:
url_redirector_cache_type dbi

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_type',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_redirector_cache_dsn		(default: none)

The DBI dsn of the database to use.

For SQLite, the database will be created automatically if it does not
already exist, the supplied path and file must be read/writable by the
user running spamassassin or spamd.

For MySQL/MariaDB or PostgreSQL, see sql-directory for database table
creation clauses.

You will need to have the proper DBI module for your database.  For example
DBD::SQLite, DBD::mysql, DBD::MariaDB or DBD::Pg.

Minimum required SQLite version is 3.24.0 (available from DBD::SQLite 1.59_01).

Examples:

 url_redirector_cache_dsn dbi:SQLite:dbname=/var/lib/spamassassin/Redirectors.db

A config that still loads the deprecated C<DecodeShortURLs> plugin (rather
than loading C<Redirectors> directly) keeps using that plugin's original
C<short_url_cache> table/columns, so an existing cache built before the
plugins were merged keeps working unchanged. Switching C<loadplugin> to
C<Redirectors> starts a fresh C<redir_url_cache> table, as a one-time cost
of migrating.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_dsn',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_redirector_cache_username  (default: none)

The username that should be used to connect to the database.  Not used for
SQLite.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_username',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_redirector_cache_password  (default: none)

The password that should be used to connect to the database.  Not used for
SQLite.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_password',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_redirector_cache_ttl		(default: 86400)

The length of time a cache entry will be valid for in seconds.
Default is 86400 (1 day).

See C<url_redirector_cache_autoclean> for database cleaning.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_ttl',
    is_admin => 1,
    default => 86400,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_shortener_cache_type     (default: none)

Deprecated alias of C<url_redirector_cache_type> -- there is only one
cache now, shared by everything this plugin fetches (redirectors and
shorteners alike).

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_type',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{url_redirector_cache_type} = $value;
    }
  });

=over 4

=item url_shortener_cache_dsn		(default: none)

Deprecated alias of C<url_redirector_cache_dsn>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_dsn',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{url_redirector_cache_dsn} = $value;
    }
  });

=over 4

=item url_shortener_cache_username  (default: none)

Deprecated alias of C<url_redirector_cache_username>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_username',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{url_redirector_cache_username} = $value;
    }
  });

=over 4

=item url_shortener_cache_password  (default: none)

Deprecated alias of C<url_redirector_cache_password>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_password',
    default => '',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{url_redirector_cache_password} = $value;
    }
  });

=over 4

=item url_shortener_cache_ttl		(default: 86400)

Deprecated alias of C<url_redirector_cache_ttl>.

See C<url_redirector_cache_autoclean> for database cleaning.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_ttl',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless ($value =~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{url_redirector_cache_ttl} = $value + 0;
    }
  });

=over 4

=item url_redirector_cache_autoclean	(default: 1000)

Automatically purge old entries from database.  Value describes a random run
chance of 1/x.  The default value of 1000 means that cleaning is run
approximately once for every 1000 messages processed.  Value of 1 would mean
database is cleaned every time a message is processed.

Set 0 to disable automatic cleaning and to do it manually.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_cache_autoclean',
    is_admin => 1,
    default => 1000,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_redirector_loginfo           (default: 0 (off))

If this option is enabled (set to 1), then redirected URLs and the decoded URLs will be logged with info priority.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_loginfo',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=over 4

=item url_redirector_timeout     (default: 5)

Maximum time a redirection URL HTTP request can take, in seconds.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item max_redir_urls                 (default: 10)

Maximum amount of redirector URLs that will be looked up per message.  Chained
redirections are not counted, only initial redirection URLs found.

Setting it to 0 disables HTTP requests, allowing only redir_url() test to
work and report any found redirector URLs.

=back

=cut

  push (@cmds, {
    setting => 'max_redir_urls',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item max_redir_url_redirections     (default: 10)

Maximum depth of chained redirections that a redirector can generate.

Redirection performed by the Selenium browser uses the browser's limits
which look like a failed lookup if exceeded.

=back

=cut

  push (@cmds, {
    setting => 'max_redir_url_redirections',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_redirector_user_agent       (default: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36)

Set User-Agent header for HTTP requests.  Some services require it to look
like a common browser.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_user_agent',
    is_admin => 1,
    default => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_autoclean	(default: 1000)

Deprecated alias of C<url_redirector_cache_autoclean>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_autoclean',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless ($value =~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{url_redirector_cache_autoclean} = $value + 0;
    }
  });

=over 4

=item url_shortener_loginfo           (default: 0 (off))

Deprecated alias of C<url_redirector_loginfo>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_loginfo',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      # bug 4462: allow yes/1 and no/0 for boolean values
      my $lc = lc $value;
      if ($lc eq 'yes' || $lc eq '1') {
        $self->{url_redirector_loginfo} = 1;
      } elsif ($lc eq 'no' || $lc eq '0') {
        $self->{url_redirector_loginfo} = 0;
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

=over 4

=item url_shortener_timeout     (default: 5)

Deprecated alias of C<url_redirector_timeout>.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_timeout',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless ($value =~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{url_redirector_timeout} = $value + 0;
    }
  });

=over 4

=item max_short_urls                 (default: 10)

Deprecated alias of C<max_redir_urls> -- there is only one budget now,
shared by everything this plugin fetches (redirectors and shorteners
alike).

=back

=cut

  push (@cmds, {
    setting => 'max_short_urls',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless ($value =~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{max_redir_urls} = $value + 0;
    }
  });

=over 4

=item max_short_url_redirections     (default: 10)

Deprecated alias of C<max_redir_url_redirections>.

=back

=cut

  push (@cmds, {
    setting => 'max_short_url_redirections',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless ($value =~ /^\d+$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{max_redir_url_redirections} = $value + 0;
    }
  });

=over 4

=item url_shortener_user_agent       (default: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36)

Deprecated alias of C<url_redirector_user_agent>. Per-domain overrides use
C<url_redirector_custom_user_agent> (C<url_shortener_custom_user_agent> is
itself a deprecated alias of that).

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_user_agent',
    is_admin => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      $self->{url_redirector_user_agent} = $value;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub initialise_url_redirector_cache {
  my ($self, $conf) = @_;

  return if $self->{dbh} && $self->{dbh_pid} && $self->{dbh_pid} == $$;
  return if !$conf->{url_redirector_cache_type};

  if (!$conf->{url_redirector_cache_dsn}) {
    warn "Redirectors: invalid cache configuration\n";
    return;
  }

  # The deprecated DecodeShortURLs plugin used table short_url_cache
  # (columns short_url/decoded_url); keep using it for configs that still
  # load that plugin, so their existing cache isn't silently abandoned
  # in favor of the new, empty redir_url_cache table.
  my $is_legacy_shim = ref($self) eq 'Mail::SpamAssassin::Plugin::DecodeShortURLs';
  my $tbl     = $is_legacy_shim ? 'short_url_cache' : 'redir_url_cache';
  my $key_col = $is_legacy_shim ? 'short_url'       : 'redir_url';
  my $val_col = $is_legacy_shim ? 'decoded_url'      : 'target_url';

  ##
  ## SQLite
  ##
  if ($conf->{url_redirector_cache_type} =~ /^(?:dbi|sqlite)$/i
      && $conf->{url_redirector_cache_dsn} =~ /^dbi:SQLite/)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      require DBD::SQLite;
      DBD::SQLite->VERSION(1.59_01); # Required for ON CONFLICT
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_redirector_cache_dsn}, '', '',
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS $tbl (
          $key_col   TEXT PRIMARY KEY NOT NULL,
          $val_col  TEXT NOT NULL,
          hits        INTEGER NOT NULL DEFAULT 1,
          created     INTEGER NOT NULL,
          modified    INTEGER NOT NULL
        )
      ");
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO $tbl ($key_col, $val_col, created, modified)
        VALUES (?,?,strftime('%s','now'),strftime('%s','now'))
        ON CONFLICT($key_col) DO UPDATE
          SET $val_col = excluded.$val_col,
              modified = excluded.modified,
              hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT $val_col FROM $tbl
        WHERE $key_col = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE $key_col = ? AND created < strftime('%s','now') - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE created < strftime('%s','now') - $conf->{url_redirector_cache_ttl}
      ");
    };
  }
  ##
  ## MySQL/MariaDB
  ##
  elsif (lc $conf->{url_redirector_cache_type} eq 'dbi'
      && $conf->{url_redirector_cache_dsn} =~ /^dbi:(?:mysql|MariaDB)/i)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_redirector_cache_dsn},
        $conf->{url_redirector_cache_username},
        $conf->{url_redirector_cache_password},
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO $tbl ($key_col, $val_col, created, modified)
        VALUES (?,?,UNIX_TIMESTAMP(),UNIX_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
          $val_col = VALUES($val_col),
          modified = VALUES(modified),
          hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT $val_col FROM $tbl
        WHERE $key_col = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE $key_col = ? AND created < UNIX_TIMESTAMP() - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE created < UNIX_TIMESTAMP() - $conf->{url_redirector_cache_ttl}
      ");
    };
  }
  ##
  ## PostgreSQL
  ##
  elsif (lc $conf->{url_redirector_cache_type} eq 'dbi'
      && $conf->{url_redirector_cache_dsn} =~ /^dbi:Pg/i)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_redirector_cache_dsn},
        $conf->{url_redirector_cache_username},
        $conf->{url_redirector_cache_password},
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO $tbl ($key_col, $val_col, created, modified)
        VALUES (?,?,CAST(EXTRACT(epoch FROM NOW()) AS INT),CAST(EXTRACT(epoch FROM NOW()) AS INT))
        ON CONFLICT ($key_col) DO UPDATE SET
          $val_col = EXCLUDED.$val_col,
          modified = EXCLUDED.modified,
          hits = $tbl.hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT $val_col FROM $tbl
        WHERE $key_col = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE $key_col = ? AND created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM $tbl
        WHERE created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_redirector_cache_ttl}
      ");
    };
  ##
  ## ...
  ##
  } else {
    warn "Redirectors: invalid cache configuration\n";
    return;
  }

  if ($@ || !$self->{sth_clean}) {
    warn "Redirectors: cache connect failed: $@\n";
    undef $self->{dbh};
    undef $self->{dbh_pid};
    undef $self->{sth_insert};
    undef $self->{sth_select};
    undef $self->{sth_delete};
    undef $self->{sth_clean};
  } else {
    $self->{dbh_pid} = $$;
  }
}

sub redir_url {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url} ? 1 : 0;
}

sub redir_url_valid {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_valid} ? 1 : 0;
}

sub redir_url_404 {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_404} ? 1 : 0;
}

sub redir_url_code {
  my ($self, $pms, undef, $code) = @_;

  $self->_check_redir($pms);

  return 0 unless defined $code && $code =~ /^\d{3}$/;
  return $pms->{"redir_url_$code"} ? 1 : 0;
}

sub redir_url_chained {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_chained} ? 1 : 0;
}

sub redir_url_chained_domain {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_chained_domain} ? 1 : 0;
}

sub redir_url_maxchain {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_maxchain} ? 1 : 0;
}

sub redir_url_loop {
  my ($self, $pms) = @_;

  $self->_check_redir($pms);

  return $pms->{redir_url_loop} ? 1 : 0;
}

# short_url() and friends are deprecated aliases of redir_url() and
# friends, a "shortener" and a "redirector" are the same mechanism, so
# there is nothing left for a separate short_url_* implementation to do.
# short_url_redir/short_url_200 are thin wrappers rather than glob aliases
# since their names don't line up 1:1 with a redir_url_* counterpart.
*short_url          = \&redir_url;
*short_url_chained   = \&redir_url_chained;
*short_url_maxchain  = \&redir_url_maxchain;
*short_url_loop      = \&redir_url_loop;
*short_url_404       = \&redir_url_404;
*short_url_code      = \&redir_url_code;

sub short_url_redir {
  my ($self, $pms) = @_;
  return $self->redir_url_valid($pms);
}

sub short_url_200 {
  my ($self, $pms) = @_;
  return $self->redir_url_code($pms, undef, '200');
}

sub short_url_tests {
  # Legacy DecodeShortURLs compatibility warning done in finish_parsing_start
  return 0;
}

sub finish_parsing_start {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  if ($conf->{eval_to_rule}->{short_url_tests}) {
    warn "Redirectors: Legacy configuration format detected. ".
         "Eval function short_url_tests() is no longer supported, ".
         "please see documentation for the new rule format.\n";
  }

  # finish_parsing_start runs once per loaded plugin instance,
  # warn if both are loaded together.
  if (!$conf->{_redirectors_dual_plugin_warned}) {
    my @loaded = $conf->{main}->{plugins}->get_loaded_plugins_list();
    my $has_decodeshorturls = grep { ref($_) eq 'Mail::SpamAssassin::Plugin::DecodeShortURLs' } @loaded;
    my $has_redirectors = grep { ref($_) eq 'Mail::SpamAssassin::Plugin::Redirectors' } @loaded;
    if ($has_decodeshorturls && $has_redirectors) {
      $conf->{_redirectors_dual_plugin_warned} = 1;
      warn "Redirectors: both Mail::SpamAssassin::Plugin::DecodeShortURLs and ".
           "Mail::SpamAssassin::Plugin::Redirectors are loaded. ".
           "DecodeShortURLs is deprecated and merged into Redirectors; loading ".
           "both is redundant and only one of them ends up actually checking ".
           "and caching redirected URLs. Please load only ".
           "Mail::SpamAssassin::Plugin::Redirectors.\n";
    }
  }
}

# Add a host[/path] entry to the shared exact/suffix lookup buckets.
sub _add_redirector_entry {
  my ($conf, $token, $method) = @_;

  my ($domspec, $path) = split(/\//, $token, 2);
  $path = defined $path ? '/' . $path : '/';

  # The host is matched against Mail::SpamAssassin::URI->host, which is always
  # lowercased, so store the domain lowercased too. The path is left as entered
  # so it can be matched case-sensitively.
  $domspec = lc $domspec;

  my $is_suffix = ($domspec =~ s/^\.//) ? 1 : 0;
  return unless length $domspec;

  my $bucket = $is_suffix ? 'url_redirector_suffix' : 'url_redirector_exact';
  my $existing = $conf->{$bucket}->{$domspec};
  if ($existing && $existing->{method} ne $method) {
    my $display = ($is_suffix ? '.' : '') . $domspec;
    warn "redirectors: $display already registered with method '$existing->{method}'; overriding with '$method'\n";
  }
  # Store new entry to limit change to this scan
  my @paths = $existing ? @{$existing->{paths}} : ();
  push @paths, $path unless grep { $_ eq $path } @paths;
  $conf->{$bucket}->{$domspec} = { method => $method, paths => \@paths };
}

sub _clear_redirector_entry {
  my ($conf, $token) = @_;

  my $has_path = ($token =~ /\//) ? 1 : 0;
  my ($domspec, $path) = split(/\//, $token, 2);
  # Lowercase the domain to match how _add_redirector_entry stored it; the path
  # is matched case-sensitively, so it is left as entered.
  $domspec = lc $domspec;
  $path = '/' . (defined $path ? $path : '');

  my $bucket = ($domspec =~ s/^\.//) ? 'url_redirector_suffix' : 'url_redirector_exact';
  return unless length $domspec;

  my $entry = $conf->{$bucket}->{$domspec} or return;

  if (!$has_path) {
    delete $conf->{$bucket}->{$domspec};
    return;
  }
  # Store new entry to limit change to this scan
  my @paths = grep { $_ ne $path } @{$entry->{paths}};
  if (@paths) {
    $conf->{$bucket}->{$domspec} = { method => $entry->{method}, paths => \@paths };
  } else {
    delete $conf->{$bucket}->{$domspec};
  }
}

# Remove every entry from both lookup buckets. Used by
# clear_url_redirector/clear_url_shortener with no arguments.
sub _clear_all_redirector_entries {
  my ($conf) = @_;
  $conf->{url_redirector_exact} = {};
  $conf->{url_redirector_suffix} = {};
}

sub _entry_match_path {
  my ($entry, $path) = @_;
  for my $p (@{$entry->{paths}}) {
    next unless index($path, $p) == 0;
    # Require a boundary after the configured prefix so /tr/op does not
    # match /tr/open. A trailing '/' in the configured prefix supplies
    # its own boundary; otherwise the next char must be end-of-string
    # or '/'. ('?' and '#' have already been stripped from $path.)
    return 1 if substr($p, -1) eq '/'
             || length($path) == length($p)
             || substr($path, length($p), 1) eq '/';
  }
  return 0;
}

# Returns the redirector entry ({method, paths}) if the URI's host+path matches
# a configured url_redirector / url_redirector_get / url_shortener*, else
# undef.  Takes a Mail::SpamAssassin::URI.
#
# A bare-domain entry also matches its www. form; a leading-dot entry matches
# any subdomain but not the domain itself.
sub _lookup_redirector {
  my ($u, $conf) = @_;

  # The scheme has to be checked here because no domain entry can express one,
  # so an ftp://configured.example would otherwise match.  Everything else
  # about the host the lookup below judges for itself.
  return unless $u->is_http;

  my $host = $u->host;
  return unless defined $host && length $host;
  # An empty path still addresses the root, which is what a bare-domain entry
  # is configured as.
  my $path = length $u->path ? $u->path : '/';

  my $entry;
  if (my $e = $conf->{url_redirector_exact}->{$host}) {
    $entry = $e if _entry_match_path($e, $path);
  }
  if (!$entry && $host =~ /^www\.(.+)$/) {
    if (my $e = $conf->{url_redirector_exact}->{$1}) {
      $entry = $e if _entry_match_path($e, $path);
    }
  }
  if (!$entry) {
    my $h = $host;
    while ($h =~ s/^[^.]+\.//) {
      last unless $h =~ /\./;
      if (my $e = $conf->{url_redirector_suffix}->{$h}) {
        $entry = $e, last if _entry_match_path($e, $path);
      }
    }
  }

  return unless $entry;

  dbg("Found redirection for host $host path $path");
  return $entry;
}

# Repair and vet one candidate target, which has already been decoded.
# Returns an absolute URI, or undef when the value is not one.
sub _embedded_uri_candidate {
  my ($value) = @_;

  return unless defined $value && length $value;

  # Collapse padded slash runs, "http:///host" and "//////host" alike.
  local($1);
  $value =~ s{^(https?:)/*}{$1//}i;
  $value =~ s{^/{2,}}{//};

  # Only an embedded URI if it actually looks like one: an explicit scheme, a
  # scheme-relative //host.tld, or a bare host.tld/path.  A bare token
  # (referral code, label, etc.) is not a URI and must not be turned into a
  # fabricated http://<token>, and a slash run with no dotted host after it
  # ("//////common/oauth2") is not one either.  These stay anchored: a value
  # that merely contains a URL somewhere inside it (a scope list, say) is not
  # a redirect target.
  return unless $value =~ m{^https?:}i
             || $value =~ m{^//[^/?#\s]+\.[^/?#\s]+}
             || $value =~ m{^[^/?#\s]+\.[^/?#\s]+/};

  # Strip any scheme-relative leading slashes, then supply a scheme unless the
  # value already carries one.  Test for the scheme's colon, not a bare "http"
  # prefix: a host may legitimately start with "http" (httpbin.org).
  $value =~ s{^/+}{};
  $value = 'http://' . $value if $value !~ /^https?:/i;

  return $value;
}

# Returns a URI extracted from the given Mail::SpamAssassin::URI's querystring
# or path, else undef.  Does NOT check whether the extracted URI's host is
# configured.
sub _extract_embedded_uri {
  my ($u, $conf) = @_;

  # Only the path and the query are searched, so only they need to hold
  # something.  A fragment does not count: it is stripped before fetching, so
  # it is never part of what a server is asked for.  The host is not looked at
  # at all -- an embedded URI is never taken from it.
  return unless $u->is_http;
  return unless length $u->path || defined $u->query;

  my $rreg = $conf->{url_redirector_params};
  my @params = $u->params;

  # A configured parameter name wins over any other, wherever it appears in
  # the querystring.  url_redirector_params is documented as matching
  # "name=value", so match that, and take the capture group when there is one:
  # a regex can then pull the target out of a value that wraps it, such as
  # "u=12345|https://evil.com/".  Without a capture group the whole value is
  # the candidate, which is what a plain list of parameter names wants.
  if (defined $rreg) {
    foreach my $p (@params) {
      next unless defined $p->{value};
      local($1);
      next unless "$p->{name}=$p->{value}" =~ /^(?:$rreg)/;
      my $newuri = _embedded_uri_candidate(defined $1 ? $1 : $p->{value})
        or next;
      dbg("Found embedded uri $newuri in $u");
      return $newuri;
    }
  }

  # Otherwise any parameter whose value is itself a URI.
  foreach my $p (@params) {
    my $newuri = _embedded_uri_candidate($p->{value}) or next;
    dbg("Found embedded uri $newuri in $u");
    return $newuri;
  }

  # Finally a target embedded in the path rather than in a parameter.
  local($1);
  if ($u->path =~ m{(?:/|_|=)((?:https?:)?//.*)$}) {
    my $newuri = _embedded_uri_candidate($1) or return;
    dbg("Found embedded uri $newuri in $u");
    return $newuri;
  }

  return;
}

# Lazily build (and cache on $pms) the single LWP::UserAgent used for
# every fetch this plugin makes.
sub _get_lwp_ua {
  my ($self, $pms) = @_;
  return $pms->{redir_lwp_ua} if exists $pms->{redir_lwp_ua};

  my $conf = $pms->{conf};
  # prevent "500 Header line too long (limit is 8192)" error when accessing
  # some websites
  eval {
    use LWP::Protocol::http;
    push(@LWP::Protocol::http::EXTRA_SOCK_OPTS, MaxLineLength => 16*1024);
  };
  my $ua = LWP::UserAgent->new(
    'agent'        => $conf->{url_redirector_user_agent},
    'max_redirect' => 0,
    'timeout'      => $conf->{url_redirector_timeout},
  );
  $ua->env_proxy;
  return $pms->{redir_lwp_ua} = $ua;
}

sub _selenium_deadline_reached {
  my ($self, $err, $pms, $why) = @_;
  return 0 unless defined $err && $err =~ /__alarm__ignore__/;
  $pms->{redir_deadline_abandoned} = 1;
  dbg($why);
  return 1;
}

sub _selenium_allowed_hosts {
  my ($conf) = @_;
  my (%exact, %suffix);
  for my $bucket ('url_redirector_exact', 'url_redirector_suffix') {
    my $entries = $conf->{$bucket} || {};
    for my $host (keys %$entries) {
      next unless $entries->{$host}->{method} eq 'selenium';
      my $h = lc $host;
      if ($h !~ /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?
                  (?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)* \z/x) {
        dbg("url_redirector_selenium host '$host' is not a plain host name "
            . "or IPv4 address; the Selenium browser will not connect to it");
        next;
      }
      if ($bucket eq 'url_redirector_exact') {
        $exact{$h} = 1;
        $exact{"www.$h"} = 1 unless $h =~ /^[0-9.]+\z/;
      } elsif ($h =~ /\./) {
        # _lookup_redirector never matches a suffix without a dot.
        $suffix{".$h"} = 1;
      }
    }
  }
  # Checked by _is_resource_host when the configuration was parsed
  $exact{$_} = 1 for keys %{ $conf->{url_redirector_selenium_resource} || {} };
  return ([sort keys %exact], [sort keys %suffix]);
}

# An exact host name whose last label starts with a letter, so not an IP
# address in any form a URL can give one. Chrome resolves names under
# .localhost to a loopback address itself.
sub _is_resource_host {
  my ($host) = @_;
  return $host =~ /^(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+
                    [a-z](?:[a-z0-9-]*[a-z0-9])?\z/x
      && $host !~ /\.localhost\z/;
}

sub _selenium_allowlist_args {
  my ($conf) = @_;
  my ($exact, $suffix) = _selenium_allowed_hosts($conf);
  my $webrtc = '--webrtc-ip-handling-policy=disable_non_proxied_udp';

  my $proxy = $conf->{url_redirector_selenium_proxy};
  if (!length $proxy) {
    return ('--host-resolver-rules=' . join(', ', 'MAP * ~NOTFOUND',
              (map { "EXCLUDE $_" } @$exact),
              (map { "EXCLUDE *$_" } @$suffix)),
            $webrtc);
  }

  my ($scheme, $host, $port) = $proxy =~ m{^(https?|socks5)://(\[[^\]]+\]|[^:]+):(\d+)\z}
    or return ('--host-resolver-rules=MAP * ~NOTFOUND', $webrtc);
  $host = lc $host;
  # Exempt only the proxy's address and port: Chrome matches a MAP
  # pattern against host:port, with an IPv6 address in brackets.
  my $rule_host = $host;
  if ($rule_host =~ /^\[(.+)\]\z/) {
    my $ip = NetAddr::IP->new($1);
    $rule_host = '[' . ($ip ? lc $ip->short : $1) . ']';
  }
  my $route = { http => 'PROXY', https => 'HTTPS', socks5 => 'SOCKS5' }->{$scheme}
              . " $host:$port";
  my $pac = 'function FindProxyForURL(url, host) {'
    . ' var exact = {' . join(', ', map { "\"$_\": 1" } @$exact) . '};'
    . ' var suffix = [' . join(', ', map { "\"$_\"" } @$suffix) . '];'
    . " if (Object.prototype.hasOwnProperty.call(exact, host)) return \"$route\";"
    . ' for (var i = 0; i < suffix.length; i++) {'
    . ' var s = suffix[i];'
    . ' if (host.length > s.length && host.substring(host.length - s.length) == s)'
    . " return \"$route\"; }"
    . ' return "DIRECT"; }';
  return ('--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,'
            . MIME::Base64::encode_base64($pac, ''),
          "--host-resolver-rules=MAP $rule_host:$port $rule_host, MAP * ~NOTFOUND",
          $webrtc);
}

sub _selenium_allowlist_check_url {
  my (@args) = @_;
  my %exempt;
  for my $arg (@args) {
    next unless $arg =~ /^--host-resolver-rules=(.*)\z/;
    my $rules = $1;
    $exempt{lc $_} = 1 for $rules =~ /EXCLUDE ([^,\s]+)/g;
    $exempt{lc $_} = 1 for $rules =~ /MAP ([0-9.]+):\d+ /g;
  }
  my ($n) = grep { !$exempt{"127.0.0.$_"} } 2 .. 254;
  return 'http://127.0.0.' . ($n // 2) . '/';
}

sub _get_selenium_ua {
  my ($self, $pms) = @_;
  return $pms->{redir_selenium_ua} if exists $pms->{redir_selenium_ua};

  if (defined $self->{redir_selenium_live_ua}) {
    dbg("quitting a Selenium session left open by a previous message whose "
        . "check() did not reach finish()");
    $self->_quit_selenium_ua(delete $self->{redir_selenium_live_ua});
  }

  my $conf = $pms->{conf};

  my @selenium_args = ('headless', 'incognito',
                       'user-agent=' . $conf->{url_redirector_user_agent},
                       _selenium_allowlist_args($conf));
  $pms->{redir_selenium_args} = join("\n", @selenium_args);
  if (defined $self->{redir_selenium_kept_ua}
      && ($self->{redir_selenium_kept_args} // '') ne $pms->{redir_selenium_args}) {
    dbg("kept Selenium session was created with other browser arguments "
        . "and is discarded; this message's configuration differs");
    $self->_quit_selenium_ua(delete $self->{redir_selenium_kept_ua});
  }

  if ($conf->{url_redirector_selenium_reuse_session}
      && defined $self->{redir_selenium_kept_ua}) {
    my $kept = delete $self->{redir_selenium_kept_ua};
    if (eval { $kept->get_log('performance'); 1 }) {
      dbg("reusing Selenium session " . $kept->{session_id});
      $self->{redir_selenium_live_ua} = $kept;
      return $pms->{redir_selenium_ua} = $kept;
    }
    my $kept_err = $@;
    if ($self->_selenium_deadline_reached($kept_err, $pms,
          "Selenium session reuse abandoned: a SpamAssassin processing "
          . "deadline was reached while the kept session was being checked")) {
      $self->{redir_selenium_live_ua} = $kept;
      return $pms->{redir_selenium_ua} = undef;
    }
    $kept_err =~ s/\s+/ /g;
    dbg("kept Selenium session did not answer and is discarded; creating a "
        . "new one: $kept_err");
    $self->_quit_selenium_ua($kept);
  }

  if (not HAS_SELENIUM) {
    dbg("url_redirector_selenium_host is set but Selenium::Chrome Perl module not installed");
    return $pms->{redir_selenium_ua} = undef;
  }

  # If option set for one Selenium session per message, no session_id is passed in
  #
  my $wd_ua = LWP::UserAgent->new;
  my $wd_timeout = $wd_ua->timeout;
  $wd_ua->timeout(SELENIUM_CREATE_TIMEOUT);
  my $ua;
  eval {
    $ua = Selenium::Chrome->new('remote_server_addr' => $conf->{url_redirector_selenium_host},
                                        'port' => $conf->{url_redirector_selenium_port},
                                        'ua' => $wd_ua,
                                        'auto_close' => 0,
                                        'browser_name' =>'chrome',
                                        'wd_context_prefix' => '',
                                        'extra_capabilities' => {
                                            'pageLoadStrategy' => 'eager',
                                            'goog:chromeOptions' => {
                                                'args'  => \@selenium_args
                                            },
                                            'goog:loggingPrefs' => {
                                                'performance' => 'ALL'
                                            }
                                        });
  };
  if($@) {
    my $new_err = $@;
    if ($new_err =~ /__alarm__ignore__/
        || ($pms->{master_deadline}
            && Time::HiRes::time() >= $pms->{master_deadline})) {
      $pms->{redir_deadline_abandoned} = 1;
      dbg("Selenium session creation abandoned: a SpamAssassin processing "
          . "deadline was reached while the session was being created; the "
          . "Selenium client reported: $new_err");
      return $pms->{redir_selenium_ua} = undef;
    }
    dbg("Error connecting to Selenium server: $new_err");
    warn("Redirectors: a Selenium session could not be created at $conf->{url_redirector_selenium_host}:$conf->{url_redirector_selenium_port}; Selenium lookups are being skipped. Check url_redirector_selenium_host and url_redirector_selenium_port, that the server serves WebDriver at its root path, and that the server has a free session slot.\n")
      unless $self->{selenium_warned_session_creation_failure}++;
    return $pms->{redir_selenium_ua} = undef;
  }
  dbg("Connecting to Selenium server with session id " . $ua->{session_id});
  $wd_ua->timeout($wd_timeout);
  $self->{redir_selenium_live_ua} = $ua;
  eval {
    $ua->set_timeout('page load', ($conf->{url_redirector_timeout} || 5) * 1000);
  };
  if($@) {
    my $timeout_err = $@;
    return $pms->{redir_selenium_ua} = undef
      if $self->_selenium_deadline_reached($timeout_err, $pms,
           "Selenium session setup abandoned: a SpamAssassin processing "
           . "deadline was reached while the session timeout was being set");
    dbg("Error setting timeout to $conf->{url_redirector_timeout}: $timeout_err");
  }

  # Chrome ignores a switch it does not recognise, so check that this
  # session applies the host list before using it.
  my $probe = _selenium_allowlist_check_url(@selenium_args);
  my $probe_err = eval { $ua->get($probe); 1 } ? '' : $@;
  return $pms->{redir_selenium_ua} = $ua
    if $probe_err =~ /net::ERR_NAME_NOT_RESOLVED/;
  return $pms->{redir_selenium_ua} = undef
    if $self->_selenium_deadline_reached($probe_err, $pms,
         "Selenium session check abandoned: a SpamAssassin processing "
         . "deadline was reached while the new session was being checked");
  $probe_err =~ s/\s+/ /g;
  if ($probe_err eq '' || $probe_err =~ /net::ERR_/) {
    dbg("Selenium browser did not refuse $probe, so it is not applying the "
        . "url_redirector_selenium host list: "
        . ($probe_err eq '' ? 'the page loaded' : $probe_err));
    warn("Redirectors: the Selenium browser did not refuse an address outside url_redirector_selenium, so it is not applying the host list; Selenium lookups are being skipped. Check that the browser still supports the --host-resolver-rules switch.\n")
      unless $self->{selenium_warned_allowlist_check}++;
  } else {
    dbg("Selenium session could not be checked, skipping this message's "
        . "Selenium lookups: $probe_err");
  }
  $self->_quit_selenium_ua(delete $self->{redir_selenium_live_ua});
  return $pms->{redir_selenium_ua} = undef;
}

# Did Chrome stop on it's redirect limit? How many HTTP redirects were followed?
# Returns ($hit_ceiling, $redirects); $redirects is undef when it is not known.
sub _selenium_redirect_summary {
  my ($self, $ua, $redir_url) = @_;

  my $entries = eval { $ua->get_log('performance') };
  die $@ if $@ && $@ =~ /__alarm__ignore__/;
  if ($@ || ref $entries ne 'ARRAY') {
    my $why = $@ || 'no entries returned';
    $why =~ s/\s+/ /g;
    dbg("Selenium performance log could not be read after navigating to "
        . "$redir_url; whether the browser stopped on its own redirect "
        . "limit, and how many redirects it followed, is not known: $why");
    return (0, undef, undef);
  }

  my ($nav_id, %failed, %redirects, %last_hop);
  for my $entry (@$entries) {
    my $raw = ref $entry eq 'HASH' ? $entry->{message} : undef;
    next unless defined $raw
             && $raw =~ /Network\.(?:requestWillBeSent|loadingFailed)/;
    my $message = eval { JSON::decode_json($raw)->{message} };
    next unless ref $message eq 'HASH' && defined $message->{method};
    my $method = $message->{method};
    my $params = ref $message->{params} eq 'HASH' ? $message->{params} : {};

    if ($method eq 'Network.requestWillBeSent') {
      next unless ($params->{type} // '') eq 'Document';
      next unless defined $params->{requestId};
      if ($params->{redirectResponse}) {
        $redirects{ $params->{requestId} }++;
        my $req = $params->{request};
        $last_hop{ $params->{requestId} } = $req->{url}
          if ref $req eq 'HASH' && defined $req->{url};
        next;
      }
      $nav_id = $params->{requestId} unless defined $nav_id;
    }
    elsif ($method eq 'Network.loadingFailed') {
      next unless ($params->{errorText} // '') =~ /ERR_TOO_MANY_REDIRECTS/;
      $failed{ $params->{requestId} } = 1 if defined $params->{requestId};
    }
  }

  return (0, undef, undef) unless defined $nav_id;
  return (($failed{$nav_id} ? 1 : 0), ($redirects{$nav_id} || 0),
          $last_hop{$nav_id});
}

sub _selenium_navigate {
  my ($self, $ua, $redir_url, $pms) = @_;
  my $conf = $pms->{conf};

  if (!eval { $ua->get('about:blank'); $ua->get_log('performance'); 1 }) {
    my $reset_err = $@;
    die $reset_err if $reset_err =~ /__alarm__ignore__/;
    $reset_err =~ s/\s+/ /g;
    dbg("Selenium browser could not be reset before navigating to "
        . "$redir_url; navigating without the reset: $reset_err");
  }

  if (!eval { $ua->get($redir_url); 1 }) {
    my $get_err = $@;
    die $get_err if $get_err =~ /__alarm__ignore__/;
    dbg("Error in Selenium request reading url $redir_url, error $get_err");
    my ($ceiling, $redirects, $last_hop) =
      $self->_selenium_redirect_summary($ua, $redir_url);
    return if $ceiling;
    if (!defined $last_hop) {
      if (length $conf->{url_redirector_selenium_proxy}
          && !$self->{selenium_warned_proxy_failure}++) {
        my $proxy_err = ($get_err =~ /net::ERR_PROXY_/)
          ? ' the configured proxy may be unreachable;' : '';
        warn("Redirectors: Selenium navigation failed with url_redirector_selenium_proxy configured;$proxy_err the lookup was abandoned, not retried direct.\n");
      }
      return;
    }
    dbg("Selenium navigation for $redir_url followed $redirects "
        . "redirect(s) inside the browser before failing; recording the "
        . "URL the last one led to: $last_hop");
    return (301, $last_hop);
  }

  my ($ceiling, $redirects) = $self->_selenium_redirect_summary($ua, $redir_url);
  if (defined $redirects) {
    dbg("Selenium navigation for $redir_url followed $redirects "
        . "redirect(s) inside the browser");
  } else {
    dbg("Selenium navigation for $redir_url: the number of redirects "
        . "followed inside the browser is not known");
  }
  if ($ceiling) {
    dbg("Selenium navigation for $redir_url stopped on the browser's "
        . "own redirect limit, so the lookup is treated as failed "
        . "rather than as a redirect to the last URL the browser "
        . "fetched");
    return;
  }

  my $newurl = $ua->get_current_url();
  my $wait_secs = $conf->{url_redirector_timeout} || 5;
  for (1 .. $wait_secs) {
    last if $newurl ne $redir_url;
    my $polled = eval { sleep 1; $ua->get_current_url() };
    die $@ if $@ && $@ =~ /__alarm__ignore__/;
    $newurl = $polled if defined $polled;
  }
  my $rcode;
  if($newurl ne $redir_url) {
    $rcode = 301;
  } else {
    if ($redir_url =~ /\/(https?:\/\/.{4,256})/) {
      $rcode = 301;
      $newurl = $1;
      dbg("Found $1 in hard-coded redirector");
    } else {
      $rcode = 200;
      dbg("URL is not a redirect: $redir_url = ".$rcode);
    }
  }
  return ($rcode, $newurl);
}

# Perform an HTTP request for $uri (a Mail::SpamAssassin::URI) using $method
# (LWP) or Selenium.
# Returns the absolute, normalized Location URL on a usable redirect,
# or undef otherwise. Sets redir_url_<rcode> flags on $pms and writes
# the cache.
sub _do_http {
  my ($self, $uri, $method, $pms) = @_;
  my $conf = $pms->{conf};

  # Request the URL the way a browser does: rebuilt from its parts, with the
  # host canonicalized and the userinfo and fragment left out. The userinfo
  # ("user[:pass]@" before the host) is dropped because a browser does not send
  # it preemptively -- it holds the credentials back until a server answers 401
  # -- whereas LWP turns it into a preemptive "Authorization: Basic" header.
  # Some shorteners (e.g. da.gd) answer any such request with 403 instead of the
  # redirect, which a spammer exploits: "https://zoom.us-join@shortener/abc"
  # looks like Zoom to a human and resolves in a browser, but 403s for a scanner
  # that fetches it verbatim, hiding the real destination. http_url returns
  # undef when there is nothing a client could fetch (a non-http scheme, or an
  # unresolvable host), in which case there is no redirect to follow.
  my $redir_url = $uri->http_url;
  return unless defined $redir_url;

  my $location;

  if (defined($location = $self->cache_get($redir_url))) {
    if ($conf->{url_redirector_loginfo}) {
      info("found cached $redir_url => $location");
    } else {
      dbg("found cached $redir_url => $location");
    }
    if ($location =~ /^\d{3}$/) {
      $pms->{"redir_url_$location"} = 1;
      $self->cache_add($redir_url, $location);
      return;
    }
  } else {
    # remove additional slashes after http://
    $redir_url =~ s{^(https?:)/*}{$1//}i;
    if($redir_url !~ /^(?:https?:\/\/)?(?:.{1,128}\@)?(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}/) {
      dbg("URL $redir_url is not valid, skipping http check");
      return;
    }

    if($method eq 'selenium') {
      my $ua = $self->_get_selenium_ua($pms);
      return unless defined $ua;

      my ($rcode, $newurl) =
        eval { $self->_selenium_navigate($ua, $redir_url, $pms) };
      if ($@) {
        my $err = $@;
        return if $self->_selenium_deadline_reached($err, $pms,
          "Selenium navigation for $redir_url abandoned: a SpamAssassin "
          . "processing deadline was reached during the navigation");
        die $err;
      }
      return unless defined $rcode;
      $location = $newurl;
      $pms->{"redir_url_$rcode"} = 1
        unless _is_https_upgrade($uri, Mail::SpamAssassin::URI->new($newurl));
      $self->cache_add($redir_url, $rcode);
      if($rcode !~ /^30[12]/) {
        return;
      }
    } else {
      my $ua = $self->_get_lwp_ua($pms);
      my $host = $uri->host;
      my $custom_ua = defined $host ? $conf->{url_redirector_custom_ua}->{$host} : undef;
      $ua->agent(defined $custom_ua ? $custom_ua : $conf->{url_redirector_user_agent});
      my $response = $ua->$method($redir_url);
      return if not defined $response;

      my $http_equiv = 0;
      if (!$response->is_redirect) {
        dbg("URL is not a redirect: $redir_url = ".$response->status_line);
        my $rcode = $response->code;
        if ($rcode =~ /^\d{3}$/) {
          if($rcode eq 500) {
	    my $cw = $response->header('Client-Warning');
	    if(defined $cw and $cw eq 'Internal response') {
	      # LWP synthesized this 500 rather than receiving it from the
	      # server, the reason may be a connection timeout, a DNS failure,
	      # an oversized header, etc.  Report what it actually said.
	      dbg("Client error checking $redir_url: ".$response->status_line);
	    }
          } elsif($rcode eq 200) {
	    if((defined $response->content) and ($response->content =~ /http-equiv=["']?refresh["']?.{1,64}?content=["']?(\d+);\s+url=["']?((?:https?:\/\/)?[^"'\\]+(?:\/[^"'\\]{8,256})?)["']?/is)) {
	      $http_equiv = 1;
	      my $delay = $1;
	      $location = $2;
	      if($delay eq 0) {
	        $rcode = 301;
	      } elsif ($delay > 0) {
	        $rcode = 302;
	      }
	      dbg("Found a meta http-equiv redirector, changing http response code from " . $response->code . " to $rcode");
	    }
	  } else {
            $pms->{"redir_url_$rcode"} = 1;
            $self->cache_add($redir_url, $rcode);
          }
        }
        if($rcode !~ /^30[12]/) {
          return;
        }
      }

      if((exists $response->headers->{location}) or $http_equiv) {
        $location = $response->headers->{location} if not $http_equiv;
        if($redir_url ne $location) {
          if ($conf->{url_redirector_loginfo}) {
            info("found $redir_url => $location");
          } else {
            dbg("found $redir_url => $location");
          }
        }
      }
    }
  }

  return unless defined $location;

  $self->cache_add($redir_url, $location);

  # Resolve relative Location header to absolute.
  if ($location !~ m{^[a-z]+://}i) {
    if($location =~ /^(ftp|mailto|tel):/) {
      dbg("Unsupported protocol scheme \"$1:\"");
      return;
    }
    my $orig_location = $location;
    my $base = $redir_url;
    if (index($location, '/') == 0) {
      $base =~ s{^([a-z]+://.*?)[/?#].*}{$1};
    } else {
      $base =~ s{^([a-z]+://.*/)}{$1};
    }
    $location = "$base$location";
    dbg("looks like a redirection to a relative URI: $redir_url => $location ($orig_location)");
  }

  # Normalize: drop duplicated parameters.
  my %paramseen;
  my $denorm_location = $location;
  my ($hostpart, $querystring) = split /\?|&amp;|&/, $location, 2;
  if(defined $querystring) {
    my @params = split /&amp;|&|%26/, $querystring;
    my @unique_params = grep { !$paramseen{$_}++ } @params;
    my $nquerystring = join '&', @unique_params;
    $location = $hostpart . '?' . $nquerystring;
    if($denorm_location ne $location) {
      dbg("Normalizing redirector parameters from $denorm_location to $location");
    }
  }

  return $location;
}

# A plain http->https on same host is not a redirect
sub _is_https_upgrade {
  my ($from, $to) = @_;
  my ($host, $to_host) = ($from->host, $to->host);
  return $from->scheme eq 'http' && $to->scheme eq 'https'
    && defined $host && defined $to_host && $host eq $to_host;
}

# Recursive chain walker. Stops cleanly when neither
# _lookup_redirector nor _extract_embedded_uri matches. HTTP
# requests are gated on _lookup_redirector returning an entry.
#
# There is no functional distinction between what used to be called a
# "redirector" and a "shortener" -- both are just a configured host whose
# response redirects elsewhere, and a hop of either origin is checked at
# every depth, so a chain can freely mix them in any order.
#
# A plain http->https upgrade on the same host is followed transparently
# rather than counted as a redirect.
sub _walk_redirects {
  my ($self, $uri, $src_info, $pms, $depth, $been_here) = @_;
  my $conf = $pms->{conf};

  return if $pms->{redir_deadline_abandoned};

  # Accepts either a string or an already-parsed URI, so a caller that has one
  # in hand does not pay to parse it twice.  Parsed once here and passed down:
  # _lookup_redirector, _extract_embedded_uri and _do_http all need the same
  # components.  $uri itself is only interpolated below, which an object does
  # as the string it was built from.
  my $u = ref $uri ? $uri : Mail::SpamAssassin::URI->new($uri);

  if (exists $been_here->{"uri:$uri"}) {
    dbg("error: loop detected: $uri");
    $pms->{redir_url_loop} = 1;
    return;
  }
  if ($depth >= $conf->{max_redir_url_redirections}) {
    dbg("found more than $conf->{max_redir_url_redirections} chained redirections");
    $pms->{redir_url_maxchain} = 1;
    return;
  }
  $been_here->{"uri:$uri"} = 1;

  my $rentry = _lookup_redirector($u, $conf);

  # Selenium method requires url_redirector_selenium_host. If it is not set,
  # skip the HTTP lookup but still set redir_url so the message-level
  # detection rule fires (matches the max_redir_urls=0 semantics: "found a
  # redirector but didn't probe it"). Fall through to embedded-URI extraction
  # in case the URL also carries a querystring redirect.
  if ($rentry && $rentry->{method} eq 'selenium' && !length $conf->{url_redirector_selenium_host}) {
    dbg("$uri matches url_redirector_selenium but url_redirector_selenium_host is not set, skipping http lookup");
    $pms->{redir_url} = 1;
    $rentry = undef;
  }

  if ($rentry) {
    $pms->{redir_url} = 1;
    $pms->{redir_url_chained} = 1 if $depth > 0;

    # The parsed host, rather than uri_to_domain(): this only needs a stable
    # identifier for "same host seen again", and the parser has one already.
    my $host = $u->host;
    if (defined $host) {
      if ($depth > 0 && exists $been_here->{"host:$host"}) {
        dbg("Chained redirector that uses the same hostname $host found for $uri");
        $pms->{redir_url_chained_domain} = 1;
      }
      $been_here->{"host:$host"} = 1;
    }

    return if $self->{net_disabled};
    return if !$conf->{max_redir_urls};
    # count each non-duplicate URI that is or contains a redirector
    if (!$been_here->{'seed:counted'}++) {
      return if ++$pms->{redir_seed_count} > $conf->{max_redir_urls};
    }

    my $location = $self->_do_http($u, $rentry->{method}, $pms);
    return unless defined $location;

    # Compare both sides as the form that was actually requested -- host
    # canonicalized, userinfo and fragment excluded: _do_http fetched that
    # form, and a server may still echo a fragment (or the userinfo) back in
    # Location. Two URIs that differ only there are the same request. $u fetched
    # successfully so its http_url is defined; a Location that has none is
    # simply not the same request.
    my $loc_uri = Mail::SpamAssassin::URI->new($location);
    my $loc_http_url = $loc_uri->http_url;
    if (defined $loc_http_url && $u->http_url eq $loc_http_url) {
      dbg("URL redirects to itself");
      $pms->{redir_url_loop} = 1;
      return;
    }

    my $loc_host = $loc_uri->host;

    # A plain http->https upgrade on the same host is not a meaningful redirect
    # just follow it at the same depth so it doesn't count toward redir_url_valid/chained or trip
    # redir_url_chained_domain when the https URL re-matches the same
    # url_redirector entry.
    if (_is_https_upgrade($u, $loc_uri)
        && !$been_here->{"schemeupgrade:$host"}++)
    {
      dbg("http->https upgrade on same host $host, not counting as a redirect: $uri => $location");
      return $self->_walk_redirects($loc_uri, $src_info, $pms, $depth, $been_here);
    }

    if (defined $loc_host && exists $conf->{url_skip_redirect_to}->{$loc_host}) {
      dbg("Stopping redirect chain: destination domain $loc_host is in url_skip_redirect_to ($location)");
      return;
    }

    _add_redirect_uri($pms, $location, $src_info);
    $pms->{redir_url_valid} = 1;

    return $self->_walk_redirects($loc_uri, $src_info, $pms, $depth + 1, $been_here);
  }

  if (my $embedded = _extract_embedded_uri($u, $conf)) {
    _add_redirect_uri($pms, $embedded, $src_info);
    return $self->_walk_redirects($embedded, $src_info, $pms, $depth + 1, $been_here);
  }

  return;
}

sub check_dnsbl {
  my ($self, $opts) = @_;

  $self->_check_redir($opts->{permsgstatus});
}

sub _check_redir {
  my ($self, $pms) = @_;

  return if $pms->{redir_url_checked}++;
  my $conf = $pms->{conf};

  # DecodeShortURLs and Redirectors may both end up loaded at once (e.g. a
  # legacy config still loading the deprecated DecodeShortURLs shim on top
  # of Redirectors, which v402.pre now loads by default). register_eval_rule
  # makes whichever loaded last the one actually bound to redir_url() and
  # friends; do the real work as that instance too, so the eval rules and
  # the cache table choice (legacy short_url_cache vs redir_url_cache, see
  # initialise_url_redirector_cache) are consistent, instead of depending on
  # which plugin's check_dnsbl callback happens to run first.
  my $owner = $conf->{eval_plugins}->{'redir_url'};
  $self = $owner if $owner;

  $self->initialise_url_redirector_cache($conf);

  # The UA is built lazily inside _do_http and cached on $pms. No upfront
  # construction here -- a message with only embedded-URI matches and no
  # HTTP-eligible URIs will not create a UA at all.
  my $uris = $pms->get_uri_detail_list();
  foreach my $uri (keys %{$uris}) {
    if ($pms->{redir_deadline_abandoned}) {
      dbg("a SpamAssassin processing deadline cut short one of this message's "
          . "Selenium calls, skipping its remaining redirector URLs");
      last;
    }
    my $info = $uris->{$uri};
    next unless $info->{domains} && $info->{cleaned};
    next if $info->{types} && keys %{$info->{types}} == 1 && $info->{types}->{img};
    $self->_walk_redirects($uri, $info, $pms, 0, {});
  }

  if ($self->{dbh} && $conf->{url_redirector_cache_autoclean}
      && rand() < 1/$conf->{url_redirector_cache_autoclean})
  {
    dbg("cleaning stale cache entries");
    eval { $self->{sth_clean}->execute(); };
    if ($@) { dbg("cache cleaning failed: $@"); }
  }
}

sub _add_redirect_uri {
  my ($pms, $uri, $src) = @_;

  my %types = $src && $src->{types} ? %{$src->{types}} : ();
  $types{redirect} = 1;

  my $added = $pms->add_uri_detail_list($uri, \%types);

  if ($src && $src->{anchor_text} && @{$src->{anchor_text}}) {
    my $dst = $pms->{uri_detail_list}->{$uri} ||= {};
    my %seen;
    $seen{$_}++ for @{$dst->{anchor_text} || []};
    foreach my $at (@{$src->{anchor_text}}) {
      push @{$dst->{anchor_text}}, $at unless $seen{$at}++;
    }
  }

  return $added;
}

sub cache_add {
  my ($self, $key, $value) = @_;

  return if !$self->{dbh};
  return if length($key) > 256 || length($value) > 512;

  # Upsert
  eval { $self->{sth_insert}->execute($key, $value); };
  if ($@) {
    dbg("could not add to cache: $@");
  }

  return;
}

sub cache_get {
  my ($self, $key) = @_;

  return if !$self->{dbh};

  # Make sure expired entries are gone.  Just a quick check for primary key,
  # not that expensive.
  eval { $self->{sth_delete}->execute($key); };
  if ($@) {
    dbg("cache delete failed: $@");
    return;
  }

  # Now try to get it (don't bother parsing if something was deleted above,
  # it would be rare event anyway)
  eval { $self->{sth_select}->execute($key); };
  if ($@) {
    dbg("cache get failed: $@");
    return;
  }

  my @row = $self->{sth_select}->fetchrow_array();
  if (@row) {
    return $row[0];
  }

  return;
}

# Version features
sub has_redir_url { 1 }
sub has_redir_url_valid { 1 }
sub has_redir_url_404 { 1 }
sub has_redir_url_chained { 1 }
sub has_redir_url_chained_domain { 1 }
sub has_redir_url_maxchain { 1 }
sub has_redir_url_loop { 1 }
sub has_selenium_support { 1 }
sub has_url_redirector_selenium { 1 }
sub has_url_redirector_selenium_resource { 1 }
sub has_url_skip_redirect_to { 1 }
sub has_url_redirector_path { 1 } # path-prefix syntax in url_redirector / url_redirector_get
sub has_short_url { 1 }
sub has_autoclean { 1 }
sub has_short_url_code { 1 }
sub has_user_agent { 1 } # url_shortener_user_agent
sub has_custom_user_agent { 1 } # url_shortener_custom_user_agent
sub has_get { 1 } # url_shortener_get
sub has_clear { 1 } # clear_url_shortener
sub has_timeout { 1 } # url_shortener_timeout
sub has_max_redirections { 1 } # max_short_url_redirections
# short_url() will always hit if matching url_shortener was found, even
# without HTTP requests.  To check if a valid HTTP redirection response was
# seen, use short_url_redir().
sub has_short_url_redir { 1 }

1;
