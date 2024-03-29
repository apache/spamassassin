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

DecodeShortURLs - Check for shortened URLs

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::DecodeShortURLs

  url_shortener tinyurl.com
  url_shortener_get bit.ly

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

This plugin looks for URLs shortened by a list of URL shortening services. 
Upon finding a matching URL, plugin will send a HTTP request to the
shortening service and retrieve the Location-header which points to the
actual shortened URL.  It then adds this URL to the list of URIs extracted
by SpamAssassin which can then be accessed by uri rules and plugins such as
URIDNSBL.

This plugin will follow chained redirections, where a short URL redirects to
another short URL.  Redirection depth limit can be set with
C<max_short_url_redirections>.

Maximum of C<max_short_urls> short URLs are checked in a message (10 by
default).  Setting it to 0 disables HTTP requests, allowing only short_url()
test to work and report found shorteners.

All supported rule types for checking short URLs and redirection status are
documented in L<SYNOPSIS> section.

=head1 NOTES

This plugin runs at the check_dnsbl hook (priority -100) so that it may
modify the parsed URI list prior to normal uri rules or the URIDNSBL plugin.

=cut

package Mail::SpamAssassin::Plugin::DecodeShortURLs;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 4.00;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; require LWP::Protocol::https; };

sub dbg { my $msg = shift; return Mail::SpamAssassin::Logger::dbg("DecodeShortURLs: $msg", @_); }
sub info { my $msg = shift; return Mail::SpamAssassin::Logger::info("DecodeShortURLs: $msg", @_); }

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
  $self->register_method_priority ('check_dnsbl', -10);
  $self->register_eval_rule('short_url', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_redir', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_200', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_404', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_code', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_chained', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_maxchain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_loop', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_tests'); # for legacy plugin compatibility warning

  return $self;
}

=head1 USER SETTINGS

=over 4

=item url_shortener  domain [domain...]     (default: none)

Domains that should be considered as an URL shortener.  If the domain begins
with a '.', 3rd level tld of the main domain will be checked.

Example:

 url_shortener tinyurl.com
 url_shortener .page.link

=back

=over 4

=item url_shortener_get  domain [domain...]     (default: none)

Alias to C<url_shortener>.  HTTP request will be done with GET method,
instead of default HEAD.  Required for some services like bit.ly to return
blocked URL correctly.

Example:

 url_shortener_get bit.ly

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'url_shortener',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_shortener}->{lc $domain} = 1; # 1 == head
      }
    }
  });

  push (@cmds, {
    setting => 'url_shortener_get',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_shortener}->{lc $domain} = 2; # 2 == get
      }
    }
  });

=over 4

=item clear_url_shortener  [domain] [domain...]

Clear configured url_shortener and url_shortener_get domains, for example to
override default settings from an update channel.  If domains are specified,
then only those are removed from list.

=back

=cut

  push (@cmds, {
    setting => 'clear_url_shortener',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        $self->{url_shortener} = {};
      } else {
        foreach my $domain (split(/\s+/, $value)) {
          delete $self->{url_shortener}->{lc $domain};
        }
      }
    }
  });

=head1 PRIVILEGED SETTINGS

=over 4

=item url_shortener_cache_type     (default: none)

The cache type that is being utilized.  Currently only supported value is
C<dbi> that implies C<url_shortener_cache_dsn> is a DBI connect string.
DBI module is required.

Example:
url_shortener_cache_type dbi

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_type',
    default => '',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_dsn		(default: none)

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

 url_shortener_cache_dsn dbi:SQLite:dbname=/var/lib/spamassassin/DecodeShortURLs.db

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_dsn',
    default => '',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_username  (default: none)

The username that should be used to connect to the database.  Not used for
SQLite.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_username',
    default => '',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_password  (default: none)

The password that should be used to connect to the database.  Not used for
SQLite.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_password',
    default => '',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_ttl		(default: 86400)

The length of time a cache entry will be valid for in seconds.
Default is 86400 (1 day).

See C<url_shortener_cache_autoclean> for database cleaning.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_ttl',
    is_admin => 1,
    default => 86400,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=head1 ADMINISTRATOR SETTINGS

=over 4

=item url_shortener_cache_autoclean	(default: 1000)

Automatically purge old entries from database.  Value describes a random run
chance of 1/x.  The default value of 1000 means that cleaning is run
approximately once for every 1000 messages processed.  Value of 1 would mean
database is cleaned every time a message is processed.

Set 0 to disable automatic cleaning and to do it manually.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_autoclean',
    is_admin => 1,
    default => 1000,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_shortener_loginfo           (default: 0 (off))

If this option is enabled (set to 1), then short URLs and the decoded URLs will be logged with info priority.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_loginfo',
    is_admin => 1,
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=over 4

=item url_shortener_timeout     (default: 5)

Maximum time a short URL HTTP request can take, in seconds.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item max_short_urls                 (default: 10)

Maximum amount of short URLs that will be looked up per message.  Chained
redirections are not counted, only initial short URLs found.

Setting it to 0 disables HTTP requests, allowing only short_url() test to
work and report any found shortener URLs.

=back

=cut

  push (@cmds, {
    setting => 'max_short_urls',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item max_short_url_redirections     (default: 10)

Maximum depth of chained redirections that a short URL can generate.

=back

=cut

  push (@cmds, {
    setting => 'max_short_url_redirections',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=over 4

=item url_shortener_user_agent       (default: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36)

Set User-Agent header for HTTP requests.  Some services require it to look
like a common browser.

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_user_agent',
    is_admin => 1,
    default => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

  $conf->{parser}->register_commands(\@cmds);
}

=head1 ACKNOWLEDGEMENTS

Original DecodeShortURLs plugin was developed by Steve Freegard.

=cut

sub short_url_tests {
  # Legacy compatibility warning done in finish_parsing_start
  return 0;
}

sub finish_parsing_start {
  my ($self, $opts) = @_;

  if ($opts->{conf}->{eval_to_rule}->{short_url_tests}) {
    warn "DecodeShortURLs: Legacy configuration format detected. ".
         "Eval function short_url_tests() is no longer supported, ".
         "please see documentation for the new rule format.\n";
  }
}

sub initialise_url_shortener_cache {
  my ($self, $conf) = @_;

  return if $self->{dbh};
  return if !$conf->{url_shortener_cache_type};

  if (!$conf->{url_shortener_cache_dsn}) {
    warn "DecodeShortURLs: invalid cache configuration\n";
    return;
  }

  ##
  ## SQLite
  ## 
  if ($conf->{url_shortener_cache_type} =~ /^(?:dbi|sqlite)$/i
      && $conf->{url_shortener_cache_dsn} =~ /^dbi:SQLite/)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      require DBD::SQLite;
      DBD::SQLite->VERSION(1.59_01); # Required for ON CONFLICT
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_shortener_cache_dsn}, '', '',
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{dbh}->do("
        CREATE TABLE IF NOT EXISTS short_url_cache (
          short_url   TEXT PRIMARY KEY NOT NULL,
          decoded_url TEXT NOT NULL,
          hits        INTEGER NOT NULL DEFAULT 1,
          created     INTEGER NOT NULL,
          modified    INTEGER NOT NULL
        )
      ");
      # Maintaining index for cleaning is likely more expensive than occasional full table scan
      #$self->{dbh}->do("
      #  CREATE INDEX IF NOT EXISTS short_url_modified
      #    ON short_url_cache(created)
      #");
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO short_url_cache (short_url, decoded_url, created, modified)
        VALUES (?,?,strftime('%s','now'),strftime('%s','now'))
        ON CONFLICT(short_url) DO UPDATE
          SET decoded_url = excluded.decoded_url,
              modified = excluded.modified,
              hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT decoded_url FROM short_url_cache
        WHERE short_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE short_url = ? AND created < strftime('%s','now') - $conf->{url_shortener_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE created < strftime('%s','now') - $conf->{url_shortener_cache_ttl}
      ");
    };
  }
  ##
  ## MySQL/MariaDB
  ## 
  elsif (lc $conf->{url_shortener_cache_type} eq 'dbi'
      && $conf->{url_shortener_cache_dsn} =~ /^dbi:(?:mysql|MariaDB)/i)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_shortener_cache_dsn},
        $conf->{url_shortener_cache_username},
        $conf->{url_shortener_cache_password},
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO short_url_cache (short_url, decoded_url, created, modified)
        VALUES (?,?,UNIX_TIMESTAMP(),UNIX_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
          decoded_url = VALUES(decoded_url),
          modified = VALUES(modified),
          hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT decoded_url FROM short_url_cache
        WHERE short_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE short_url = ? AND created < UNIX_TIMESTAMP() - $conf->{url_shortener_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE created < UNIX_TIMESTAMP() - $conf->{url_shortener_cache_ttl}
      ");
    };
  }
  ##
  ## PostgreSQL
  ## 
  elsif (lc $conf->{url_shortener_cache_type} eq 'dbi'
      && $conf->{url_shortener_cache_dsn} =~ /^dbi:Pg/i)
  {
    eval {
      local $SIG{'__DIE__'};
      require DBI;
      $self->{dbh} = DBI->connect_cached(
        $conf->{url_shortener_cache_dsn},
        $conf->{url_shortener_cache_username},
        $conf->{url_shortener_cache_password},
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1, AutoCommit => 1}
      );
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO short_url_cache (short_url, decoded_url, created, modified)
        VALUES (?,?,CAST(EXTRACT(epoch FROM NOW()) AS INT),CAST(EXTRACT(epoch FROM NOW()) AS INT))
        ON CONFLICT (short_url) DO UPDATE SET
          decoded_url = EXCLUDED.decoded_url,
          modified = EXCLUDED.modified,
          hits = short_url_cache.hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT decoded_url FROM short_url_cache
        WHERE short_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE short_url = ? AND created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_shortener_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM short_url_cache
        WHERE created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_shortener_cache_ttl}
      ");
    };
  ##
  ## ...
  ##
  } else {
    warn "DecodeShortURLs: invalid cache configuration\n";
    return;
  }

  if ($@ || !$self->{sth_clean}) {
    warn "DecodeShortURLs: cache connect failed: $@\n";
    undef $self->{dbh};
    undef $self->{sth_insert};
    undef $self->{sth_select};
    undef $self->{sth_delete};
    undef $self->{sth_clean};
  }
}

sub short_url {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url} ? 1 : 0;
}

sub short_url_redir {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_redir} ? 1 : 0;
}

sub short_url_200 {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_200} ? 1 : 0;
}

sub short_url_404 {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_404} ? 1 : 0;
}

sub short_url_code {
  my ($self, $pms, undef, $code) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return 0 unless defined $code && $code =~ /^\d{3}$/;
  return $pms->{"short_url_$code"} ? 1 : 0;
}

sub short_url_chained {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_chained} ? 1 : 0;
}

sub short_url_maxchain {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_maxchain} ? 1 : 0;
}

sub short_url_loop {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_short($pms);

  return $pms->{short_url_loop} ? 1 : 0;
}

sub _check_shortener_uri {
  my ($uri, $conf) = @_;

  local($1,$2);
  return 0 unless $uri =~ m{^
    https?://		# Only http
    (?:[^\@/?#]*\@)?	# Ignore user:pass@
    ([^/?#:]+)		# (Capture hostname)
    (?::\d+)?		# Possible port
    (.*?\w)?		# Some path wanted
    }ix;
  my $host = lc $1;
  my $has_path = defined $2;
  my $levels = $host =~ tr/.//;
  # No point looking at single level "xxx.yy" without a path
  return if $levels == 1 && !$has_path;

  if (exists $conf->{url_shortener}->{$host}) {
    return {
      'uri' => $uri,
      'method' => $conf->{url_shortener}->{$host} == 1 ? 'head' : 'get',
    };
  }
  # if domain is a 3rd level domain check if there is a url shortener
  # on the www domain
  elsif($levels == 2 && $host =~ /^www\.([^.]+\.[^.]+)$/i) {
    my $domain = $1;
    if(($host eq "www.$domain") and exists $conf->{url_shortener}->{$domain}) {
      dbg("Found internal www redirection for domain $domain");
      return {
        'uri' => $uri,
        'method' => $conf->{url_shortener}->{$domain} == 1 ? 'head' : 'get',
      };
    }
  }
  # if domain is a 3rd level domain check if there is a url shortener
  # on the 2nd level tld
  elsif ($levels == 2 && $host =~ /^(?!www)[^.]+(\.[^.]+\.[^.]+)$/i &&
           exists $conf->{url_shortener}->{$1}) {
    return {
      'uri' => $uri,
      'method' => $conf->{url_shortener}->{$1} == 1 ? 'head' : 'get',
    };
  }
  return;
}

sub check_dnsbl {
  my ($self, $opts) = @_;

  $self->_check_short($opts->{permsgstatus});
}

sub _check_short {
  my ($self, $pms) = @_;

  return if $pms->{short_url_checked}++;
  my $conf = $pms->{conf};

  # Sort short URLs into hash to de-dup them
  my %short_urls;
  my $uris = $pms->get_uri_detail_list();
  while (my($uri, $info) = each %{$uris}) {
    next unless $info->{domains} && $info->{cleaned};
    # Remove anchors and parameters from shortened uris
    $uri =~ s/(?:\#|\?).*//g;
    if (my $short_url_info = _check_shortener_uri($uri, $conf)) {
      $short_urls{$uri} = $short_url_info;
      last if scalar keys %short_urls >= $conf->{max_short_urls};
    }
  }

  # Bail out if no shortener was found
  return unless %short_urls;

  # Mark that a URL shortener was found
  $pms->{short_url} = 1;

  # Bail out if network lookups not enabled or max_short_urls 0
  return if $self->{net_disabled};
  return if !$conf->{max_short_urls};

  # Initialize cache
  $self->initialise_url_shortener_cache($conf);

  # Initialize LWP
  my $ua = LWP::UserAgent->new(
    'agent' => $conf->{url_shortener_user_agent},
    'max_redirect' => 0,
    'timeout' => $conf->{url_shortener_timeout},
  );
  $ua->env_proxy;

  # Launch HTTP requests
  foreach my $uri (keys %short_urls) {
    $self->recursive_lookup($short_urls{$uri}, $pms, $ua);
  }

  # Automatically purge old entries
  if ($self->{dbh} && $conf->{url_shortener_cache_autoclean}
      && rand() < 1/$conf->{url_shortener_cache_autoclean})
  {
    dbg("cleaning stale cache entries");
    eval { $self->{sth_clean}->execute(); };
    if ($@) { dbg("cache cleaning failed: $@"); }
  }
}

sub recursive_lookup {
  my ($self, $short_url_info, $pms, $ua, %been_here) = @_;
  my $conf = $pms->{conf};

  my $count = scalar keys %been_here;
  dbg("redirection count $count") if $count;
  if ($count >= $conf->{max_short_url_redirections}) {
    dbg("found more than $conf->{max_short_url_redirections} shortener redirections");
    # Fire test
    $pms->{short_url_maxchain} = 1;
    return;
  }

  my $short_url = $short_url_info->{uri};
  my $location;
  if (defined($location = $self->cache_get($short_url))) {
    if ($conf->{url_shortener_loginfo}) {
      info("found cached $short_url => $location");
    } else {
      dbg("found cached $short_url => $location");
    }
    # Cached http code?
    if ($location =~ /^\d{3}$/) {
      $pms->{"short_url_$location"} = 1;
      # Update cache
      $self->cache_add($short_url, $location);
      return;
    }
  } else {
    # Not cached; do lookup
    my $method = $short_url_info->{method};
    my $response = $ua->$method($short_url);
    if (!$response->is_redirect) {
      dbg("URL is not redirect: $short_url = ".$response->status_line);
      my $rcode = $response->code;
      if ($rcode =~ /^\d{3}$/) {
        $pms->{"short_url_$rcode"} = 1;
        # Update cache
        $self->cache_add($short_url, $rcode);
      }
      return;
    }
    $location = $response->headers->{location};
    if ($conf->{url_shortener_loginfo}) {
      info("found $short_url => $location");
    } else {
      dbg("found $short_url => $location");
    }
  }

  # Update cache
  $self->cache_add($short_url, $location);

  # Bail out if $short_url redirects to itself
  if ($short_url eq $location) {
    dbg("URL is redirect to itself");
    return;
  }

  # At this point we have a valid redirection and new URL in $response
  $pms->{short_url_redir} = 1;

  # Set chained here otherwise we might mark a disabled page or
  # redirect back to the same host as chaining incorrectly.
  $pms->{short_url_chained} = 1 if $count;

  # Check if it is a redirection to a relative URI
  # Make it an absolute URI and chain to it in that case
  if ($location !~ m{^[a-z]+://}i) {
    my $orig_location = $location;
    my $orig_short_url = $short_url;
    # Strip to..
    if (index($location, '/') == 0) {
      $short_url =~ s{^([a-z]+://.*?)[/?#].*}{$1}; # ..absolute path base is http://example.com
    } else {
      $short_url =~ s{^([a-z]+://.*/)}{$1}; # ..relative path base is http://example.com/a/b/
    }
    $location = "$short_url$location";
    dbg("looks like a redirection to a relative URI: $orig_short_url => $location ($orig_location)");
  }

  if (exists $been_here{$location}) {
    # Loop detected
    dbg("error: loop detected: $location");
    $pms->{short_url_loop} = 1;
    return;
  }
  $been_here{$location} = 1;
  $pms->add_uri_detail_list($location) if !$pms->{uri_detail_list}->{$location};

  # Check for recursion
  if (my $short_url_info = _check_shortener_uri($location, $conf)) {
    # Recurse...
    $self->recursive_lookup($short_url_info, $pms, $ua, %been_here);
  }
}

sub cache_add {
  my ($self, $short_url, $decoded_url) = @_;

  return if !$self->{dbh};
  return if length($short_url) > 256 || length($decoded_url) > 512;

  # Upsert
  eval { $self->{sth_insert}->execute($short_url, $decoded_url); };
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
sub has_short_url { 1 }
sub has_autoclean { 1 }
sub has_short_url_code { 1 }
sub has_user_agent { 1 } # url_shortener_user_agent
sub has_get { 1 } # url_shortener_get
sub has_clear { 1 } # clear_url_shortener
sub has_timeout { 1 } # url_shortener_timeout
sub has_max_redirections { 1 } # max_short_url_redirections
# short_url() will always hit if matching url_shortener was found, even
# without HTTP requests.  To check if a valid HTTP redirection response was
# seen, use short_url_redir().
sub has_short_url_redir { 1 }

1;
