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

=head1 ACKNOWLEDGEMENTS

The url_shortener functionality was originally provided by a separate
DecodeShortURLs plugin; that functionality has been merged into this one,
and C<Mail::SpamAssassin::Plugin::DecodeShortURLs> is now a deprecated
compatibility shim that loads this plugin.

=cut

package Mail::SpamAssassin::Plugin::Redirectors;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(compile_regexp idn_to_ascii is_fqdn_valid);
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 4.10;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; require LWP::Protocol::https; };
use constant HAS_SELENIUM => eval { require Selenium::Remote::Driver; };

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

=head1 USER SETTINGS

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
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_code,
  });
  push (@cmds, {
    setting => 'url_shortener',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_code,
  });

=over 4

=item url_redirector_use_selenium (default: 0)

Enables the Selenium subsystem. When set to 1, hosts listed in
C<url_redirector_selenium> are fetched using Selenium (headless Chrome).
When 0 (the default), those hosts are skipped entirely -- there is no
fallback to LWP, because hosts only belong in C<url_redirector_selenium>
if their redirects cannot be discovered via LWP (e.g., JavaScript-driven
redirects).

This is a runtime kill switch: an operator can disable the Selenium
subsystem without editing the host allowlist. While it is off, those
hosts are simply not probed -- C<redir_url()> still fires for them so
detection rules continue to work.

Due to how Selenium works, C<redir_url_code()> and C<redir_url_404> subs
will not fire for hosts handled by Selenium; Selenium reports only
"redirected" (301) or "not a redirect" (200), not real HTTP status codes.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_use_selenium',
    default => 0,
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=over 4

=item url_redirector_selenium_host (default: 127.0.0.1)

Set Selenium host to use.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium_host',
    default => '127.0.0.1',
    is_priv => 1,
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
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item clear_url_redirector  [domain[/path]] [domain[/path]...]

Clear configured url_redirector/url_shortener domains, for example to
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
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => $clear_url_redirector_code,
  });
  push (@cmds, {
    setting => 'clear_url_shortener',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS,
    code => $clear_url_redirector_code,
  });

=over 4

=item url_redirector_get  domain[/path] [domain[/path]...]     (default: none)

Domains that should be considered as an URL redirector, accessed using the
HTTP GET method instead of HEAD. Syntax and matching rules are the same as
C<url_redirector>: a bare domain matches that host and C<www.>, a leading
dot matches the domain and any subdomain, and an optional C</path> prefix
restricts the match.

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
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => $url_redirector_get_code,
  });
  push (@cmds, {
    setting => 'url_shortener_get',
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

If the same host appears in both C<url_redirector_selenium> and
C<url_redirector>/C<url_redirector_get>, the directive parsed last sets
the method, and a warning is emitted.

The Selenium subsystem is gated by C<url_redirector_use_selenium>. When
that flag is off, hosts in this list are skipped entirely (there is no
fallback to LWP, since these hosts wouldn't yield useful results via
LWP).

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_selenium',
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

=item url_redirector_params regexp (default: (?:adurl|af_web_dp|cm_destination|continue|destination|destURL|goto|h|l|login|location|p1|pval|r|redir|redirect|redirectTo|return|returnUrl|referer|service|target|tid|u|url)=(.*))

Regexp used to parse uri parameters in order to detect redirectors and to get redirected domains.
The regexp must match only the redirected domain.

=back

=cut

  push(@cmds, {
    setting => 'url_redirector_params',
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
    code => $url_redirector_custom_user_agent_code,
  });
  push (@cmds, {
    setting => 'url_shortener_custom_user_agent',
    code => $url_redirector_custom_user_agent_code,
  });

=head1 PRIVILEGED SETTINGS

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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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
    is_priv => 1,
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

=head1 ADMINISTRATOR SETTINGS

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

  my $is_suffix = ($domspec =~ s/^\.//) ? 1 : 0;
  return unless length $domspec;

  my $bucket = $is_suffix ? 'url_redirector_suffix' : 'url_redirector_exact';
  my $existing = $conf->{$bucket}->{$domspec};
  if ($existing && $existing->{method} ne $method) {
    my $display = ($is_suffix ? '.' : '') . $domspec;
    warn "redirectors: $display already registered with method '$existing->{method}'; overriding with '$method'\n";
  }
  my $entry = $conf->{$bucket}->{$domspec} ||= { method => $method, paths => [] };
  $entry->{method} = $method;
  push @{$entry->{paths}}, $path unless grep { $_ eq $path } @{$entry->{paths}};
}

sub _clear_redirector_entry {
  my ($conf, $token) = @_;

  $token = lc $token;
  my $has_path = ($token =~ /\//) ? 1 : 0;
  my ($domspec, $path) = split(/\//, $token, 2);
  $path = '/' . (defined $path ? $path : '');

  my $bucket = ($domspec =~ s/^\.//) ? 'url_redirector_suffix' : 'url_redirector_exact';
  return unless length $domspec;

  my $entry = $conf->{$bucket}->{$domspec} or return;

  if (!$has_path) {
    delete $conf->{$bucket}->{$domspec};
    return;
  }
  @{$entry->{paths}} = grep { $_ ne $path } @{$entry->{paths}};
  delete $conf->{$bucket}->{$domspec} unless @{$entry->{paths}};
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

sub _lookup_redirector {
  my ($conf, $host, $path) = @_;

  if (my $e = $conf->{url_redirector_exact}->{$host}) {
    return $e if _entry_match_path($e, $path);
  }
  if ($host =~ /^www\.(.+)$/) {
    if (my $e = $conf->{url_redirector_exact}->{$1}) {
      return $e if _entry_match_path($e, $path);
    }
  }
  my $h = $host;
  while ($h =~ s/^[^.]+\.//) {
    last unless $h =~ /\./;
    if (my $e = $conf->{url_redirector_suffix}->{$h}) {
      return $e if _entry_match_path($e, $path);
    }
  }
  return;
}

# Parse a URI, validate it, and split into (normalized_uri, host, path, rest).
# Returns empty list if the URI is unusable. Shared by _is_configured_redirector
# and _extract_embedded_uri so both apply the same validity rules.
sub _parse_uri {
  my ($uri, $conf) = @_;

  local($1,$2);
  # normalize uri only if it doesn't contain more explicit redirects
  # encoded as parameters
  if($uri !~ /https?%3A%2F%2F/) {
    $uri = Mail::SpamAssassin::Util::url_decode($uri);
  }
  return unless $uri =~ m{^
    https?://		# Only http
    (?:[^\@/?#]*\@)?	# Ignore user:pass@
    ([^/?#:]+)		# (Capture hostname)
    (?::\d+)?		# Possible port
    (.*)?		# Some path wanted
    }ix;
  my $host = lc $1;
  my $rest = defined $2 ? $2 : '';
  if($host =~ /\=|\&|\?/) {
    return;
  }
  if(is_fqdn_valid($host)) {
    $host = idn_to_ascii($host);
  }
  my $has_path = length $rest ? 1 : 0;
  my $levels = $host =~ tr/.//;
  return if $levels == 1 && !$has_path;
  return if $uri !~ /([^.]+\.[^.]+)/;
  return if $uri =~ /^([a-z0-9]+?)\@/;

  my $path = $rest;
  $path = $1 if $path =~ /^([^?#]*)/;
  $path = '/' unless length $path;

  return ($uri, $host, $path, $rest);
}

# Returns the redirector entry ({method, paths}) if $uri's host+path
# matches a configured url_redirector / url_redirector_get / url_shortener*,
# else undef.
sub _is_configured_redirector {
  my ($uri, $conf) = @_;

  my ($nuri, $host, $path) = _parse_uri($uri, $conf);
  return unless defined $nuri;

  if (my $e = _lookup_redirector($conf, $host, $path)) {
    dbg("Found redirection for host $host path $path");
    return $e;
  }
  return;
}

# Returns a URI extracted from $uri's querystring/path (via the
# url_redirector_params regex or a bare embedded //URL), else undef.
# Does NOT check whether the extracted URI's host is configured.
sub _extract_embedded_uri {
  my ($uri, $conf) = @_;

  my (undef, undef, undef, $rest) = _parse_uri($uri, $conf);
  return unless defined $rest;

  my $rreg = $conf->{url_redirector_params};
  local($1);
  if (($rest =~ /(?:\?|\&)$rreg/gis) || ($rest =~ /(?:\/|\_|\=)((?:https?:)?\/\/.*)/)) {
    my $newuri = $1;
    # A user-supplied url_redirector_params with no capture group leaves $1
    # undefined here; without this guard we would fabricate a bare "http://".
    return unless defined $newuri;
    # The param value is only an embedded URI if it actually looks like one:
    # an explicit/encoded scheme, a scheme-relative //host, or a bare
    # host.tld/path. A bare token (referral code, label, etc.) is not a URI
    # and must not be turned into a fabricated http://<token>.
    unless ($newuri =~ m{^https?(?::|%3a)}i
         || $newuri =~ m{^//}
         || $newuri =~ m{^[^/?#\s]+\.[^/?#\s]+/}) {
      return;
    }
    dbg("Found embedded uri $newuri in $uri");
    $newuri = 'http://' . $newuri if $newuri !~ /^http/;
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

sub _get_selenium_ua {
  my ($self, $pms) = @_;
  return $pms->{redir_selenium_ua} if exists $pms->{redir_selenium_ua};

  my $conf = $pms->{conf};
  if (not HAS_SELENIUM) {
    dbg("url_redirector_use_selenium enabled but Selenium::Remote::Driver Perl module not installed");
    return $pms->{redir_selenium_ua} = undef;
  }

  my $ua;
  eval {
    $ua = Selenium::Remote::Driver->new('remote_server_addr' => $conf->{url_redirector_selenium_host},
                                        'port' => $conf->{url_redirector_selenium_port},
                                        'auto_close' => 0,
                                        'session_id' => $self->{selenium_session_id},
                                        'browser_name' =>'chrome',
                                        'extra_capabilities' => {
                                            'goog:chromeOptions' => {
                                                'args'  => [
                                                    'headless',
                                                    'incognito',
                                                    'user-agent=' . $conf->{url_redirector_user_agent}
                                                ]
                                            }
                                        });
  };
  if($@) {
    dbg("Error connecting to Selenium server: $@");
    return $pms->{redir_selenium_ua} = undef;
  }
  $ua->{ua}->{max_redirect} = $conf->{max_redir_url_redirections};
  if(not defined $self->{selenium_session_id}) {
    $self->{selenium_session_id} = $ua->{session_id};
    dbg("Connecting to Selenium server with session id " . $self->{selenium_session_id});
  } else {
    $ua->session_id($self->{selenium_session_id});
    dbg("Reusing Selenium session id " . $self->{selenium_session_id});
  }
  eval {
    $ua->set_timeout('implicit', $conf->{url_redirector_timeout} * 1000);
  };
  if($@) {
    dbg("Error setting timeout to $conf->{url_redirector_timeout}: $@");
  }
  return $pms->{redir_selenium_ua} = $ua;
}

# Perform an HTTP request for $uri using $method (LWP) or Selenium.
# Returns the absolute, normalized Location URL on a usable redirect,
# or undef otherwise. Sets redir_url_<rcode> flags on $pms and writes
# the cache.
sub _do_http {
  my ($self, $uri, $method, $pms) = @_;
  my $conf = $pms->{conf};

  my $redir_url = $uri;
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
    $redir_url =~ s|^(https?):\/{3,8}|$1://|;
    if($redir_url !~ /^(?:https?:\/\/)?(?:.{1,128}\@)?(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}/) {
      dbg("URL $redir_url is not valid, skipping http check");
      return;
    }

    if($method eq 'selenium') {
      my $ua = $self->_get_selenium_ua($pms);
      return unless defined $ua;

      my $rcode;
      my $newurl = '';
      eval {
	$ua->get($redir_url);
      };
      if($@) {
	dbg("Error in Selenium request reading url $redir_url, error $@");
	return;
      } else {
        $newurl = $ua->get_current_url();
        # get_current_url() right after ->get() only reflects the page that
        # just finished loading, it does not wait for any client-side
        # (JS/timer-driven) navigation that page goes on to trigger a few
        # seconds later, poll for a bit before concluding this wasn't a redirect.
        my $wait_secs = $conf->{url_redirector_timeout} || 5;
        for (1 .. $wait_secs) {
          last if $newurl ne $redir_url;
          sleep 1;
          my $polled = eval { $ua->get_current_url() };
          $newurl = $polled if defined $polled;
        }
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
      }
      $location = $newurl;
      $pms->{"redir_url_$rcode"} = 1;
      $self->cache_add($redir_url, $rcode);
      if($rcode !~ /^30[12]/) {
        return;
      }
    } else {
      my $ua = $self->_get_lwp_ua($pms);
      my (undef, $host) = _parse_uri($redir_url, $conf);
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

# Recursive chain walker. Stops cleanly when neither
# _is_configured_redirector nor _extract_embedded_uri matches. HTTP
# requests are gated on _is_configured_redirector returning truthy.
#
# There is no functional distinction between what used to be called a
# "redirector" and a "shortener" -- both are just a configured host whose
# response redirects elsewhere, and a hop of either origin is checked at
# every depth, so a chain can freely mix them in any order.
sub _walk_redirects {
  my ($self, $uri, $src_info, $pms, $depth, $been_here) = @_;
  my $conf = $pms->{conf};

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

  my $rentry = _is_configured_redirector($uri, $conf);

  # Selenium method requires url_redirector_use_selenium=1. If the subsystem
  # is off, skip the HTTP lookup but still set redir_url so the message-level
  # detection rule fires (matches the max_redir_urls=0 semantics: "found a
  # redirector but didn't probe it"). Fall through to embedded-URI extraction
  # in case the URL also carries a querystring redirect.
  if ($rentry && $rentry->{method} eq 'selenium' && !$conf->{url_redirector_use_selenium}) {
    dbg("$uri matches url_redirector_selenium but url_redirector_use_selenium=0, skipping http lookup");
    $pms->{redir_url} = 1;
    $rentry = undef;
  }

  if ($rentry) {
    $pms->{redir_url} = 1;
    $pms->{redir_url_chained} = 1 if $depth > 0;

    my (undef, $host) = $self->{main}->{registryboundaries}->uri_to_domain($uri);
    if (defined $host) {
      if ($depth > 0 && exists $been_here->{"host:$host"}) {
        dbg("Chained redirector that uses the same hostname $host found for $uri");
        $pms->{redir_url_chained_domain} = 1;
      }
      $been_here->{"host:$host"} = 1;
    }

    return if $self->{net_disabled};
    return if !$conf->{max_redir_urls};
    if ($depth == 0) {
      return if ++$pms->{redir_seed_count} > $conf->{max_redir_urls};
    }

    # Strip the fragment before fetching, RFC 3986 defines it as
    # client-side-only.
    (my $fetch_uri = $uri) =~ s/#.*//;

    my $location = $self->_do_http($fetch_uri, $rentry->{method}, $pms);
    return unless defined $location;

    if ($fetch_uri eq $location) {
      dbg("URL redirects to itself");
      $pms->{redir_url_loop} = 1;
      return;
    }

    my (undef, $loc_host) = $self->{main}->{registryboundaries}->uri_to_domain($location);
    if (defined $loc_host && exists $conf->{url_skip_redirect_to}->{$loc_host}) {
      dbg("Stopping redirect chain: destination domain $loc_host is in url_skip_redirect_to ($location)");
      return;
    }

    _add_redirect_uri($pms, $location, $src_info);
    $pms->{redir_url_valid} = 1;

    return $self->_walk_redirects($location, $src_info, $pms, $depth + 1, $been_here);
  }

  if (my $embedded = _extract_embedded_uri($uri, $conf)) {
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
