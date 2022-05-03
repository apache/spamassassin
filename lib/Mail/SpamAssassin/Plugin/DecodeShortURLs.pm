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

# Original code by Steve Freegard <steve.freegard@fsl.com>

=head1 NAME

DecodeShortURLs - Expand shortened URLs

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::DecodeShortURLs

  url_shortener bit.ly
  url_shortener go.to

  body HAS_SHORT_URL          eval:short_url()
  describe HAS_SHORT_URL      Message has one or more shortened URLs

  body SHORT_URL_CHAINED      eval:short_url_chained()
  describe SHORT_URL_CHAINED  Message has shortened URL chained to other shorteners

  body SHORT_URL_MAXCHAIN     eval:short_url_maxchain()
  describe SHORT_URL_MAXCHAIN Message has shortened URL that causes more than 10 redirections

  body SHORT_URL_LOOP         eval:short_url_loop()
  describe SHORT_URL_LOOP     Message has short URL that loops back to itself

  body SHORT_URL_200          eval:short_url_200()
  describe SHORT_URL_200      Message has shortened URL returning HTTP 200

  body SHORT_URL_404          eval:short_url_404()
  describe SHORT_URL_404      Message has shortened URL returning HTTP 404

=head1 DESCRIPTION

This plugin looks for URLs shortened by a list of URL shortening services and
upon finding a matching URL will connect using to the shortening service and
do an HTTP HEAD lookup and retrieve the location header which points to the
actual shortened URL, it then adds this URL to the list of URIs extracted by
SpamAssassin which can then be accessed by other plug-ins, such as URIDNSBL.

This plugin also sets the rule HAS_SHORT_URL if any matching short URLs are
found.

This plug-in will follow 'chained' shorteners e.g.  from short URL to short
URL to short URL and finally to the real URL.

If this form of chaining is found, then the rule 'SHORT_URL_CHAINED' will be
fired.  If a loop is detected then 'SHORT_URL_LOOP' will be fired.  This
plug-in limits the number of chained shorteners to a maximum of 10 at which
point it will fire the rule 'SHORT_URL_MAXCHAIN' and go no further.

If a shortener returns a '404 Not Found' result for the short URL then the
rule 'SHORT_URL_404' will be fired.

If a shortener returns a '200 OK' result for the short URL then the rule
'SHORT_URL_200' will be fired.  This can cover the case when an abuse page
is displayed.

=head1 NOTES

This plugin runs at the check_dnsbl hook with a priority of -10 so that it
may modify the parsed URI list prior to the URIDNSBL plugin.

Currently the plugin queries a maximum of 10 distinct shortened URLs with a
maximum timeout of 5 seconds per lookup.

=head1 ACKNOWLEDGEMENTS

=encoding utf8

A lot of this plugin has been hacked together by using other plugins as
examples.  The author would particularly like to tip his hat to Karsten
Bräckelmann for his work on GUDO.pm, the original version of this plugin
could not have been developed without his code.

=cut

package Mail::SpamAssassin::Plugin::DecodeShortURLs;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 0.12;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; };

sub dbg { my $msg = shift; return Mail::SpamAssassin::Logger::dbg("DecodeShortURLs: $msg", @_); }
sub info { my $msg = shift; return Mail::SpamAssassin::Logger::info("DecodeShortURLs: $msg", @_); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  if ($mailsaobject->{local_tests_only} || !HAS_LWP_USERAGENT) {
    dbg("local tests only, disabling checks");
    $self->{disabled} = 1;
  }
  elsif (!HAS_LWP_USERAGENT) {
    dbg("module LWP::UserAgent not installed, disabling checks");
    $self->{disabled} = 1;
  }

  $self->set_config($mailsaobject->{conf});
  $self->register_method_priority ('check_dnsbl', -10);
  $self->register_eval_rule('short_url', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_200', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_404', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_code', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_chained', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_maxchain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('short_url_loop', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

=head1 PRIVILEGED SETTINGS

=over 4

=item url_shortener     (default: none)

A domain that should be considered as an url shortener.
If the domain begins with a '.', 3rd level tld of the main
domain will be checked.

Example:
url_shortener bit.ly
url_shortener .page.link

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'url_shortener',
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_shorteners}->{lc $domain} = 1;
      }
    }
  });

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

Minimum required SQLite version is 3.24.0 (available from DBD::SQLite 1.59).

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

=item max_short_urls                 (default: 10)

The max depth of short urls that will be chained until it stops looking further.

=back

=cut

  push (@cmds, {
    setting => 'max_short_urls',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
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
      && $conf->{url_shortener_cache_dsn} =~ /^dbi:(?:mysql|MariaDB)/)
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
      && $conf->{url_shortener_cache_dsn} =~ /^dbi:Pg/)
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
        WHERE short_url ? = AND created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_shortener_cache_ttl}
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

  return $pms->{short_url};
}

sub short_url_200 {
  my ($self, $pms) = @_;

  return $pms->{short_url_200};
}

sub short_url_404 {
  my ($self, $pms) = @_;

  return $pms->{short_url_404};
}

sub short_url_code {
  my ($self, $pms, undef, $code) = @_;

  return unless defined $code && $code =~ /^\d{3}$/;
  return $pms->{"short_url_$code"};
}

sub short_url_chained {
  my ($self, $pms) = @_;

  return $pms->{short_url_chained};
}

sub short_url_maxchain {
  my ($self, $pms) = @_;

  return $pms->{short_url_maxchain};
}

sub short_url_loop {
  my ($self, $pms) = @_;

  return $pms->{short_url_loop};
}

sub _check_shortener_uri {
  my ($uri, $conf) = @_;

  return 0 unless $uri =~ m{^
    https?://		# Only http
    (?:[^\@/?#]*\@)?	# Ignore user:pass@
    ([^/?#:]+)		# (Capture hostname)
    (?::\d+)?		# Possible port
    .*?\w		# Some path wanted
    }ix;
  my $host = lc $1;
  if (exists $conf->{url_shorteners}->{$host}) {
    return 1;
  }
  # if domain is a 3rd level domain check if there is a url shortener
  # on the 2nd level tld
  elsif ($host =~ /^(?!www)[^.]+(\.[^.]+\.[^.]+)$/i &&
           exists $conf->{url_shorteners}->{$1}) {
    return 1;
  }
  return 0;
}

sub check_dnsbl {
  my ($self, $opts) = @_;

  return if $self->{disabled};

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  # Sort short URLs into hash to de-dup them
  my %short_urls;
  my $uris = $pms->get_uri_detail_list();
  while (my($uri, $info) = each %{$uris}) {
    next unless $info->{domains} && $info->{cleaned};
    if (_check_shortener_uri($uri, $conf)) {
      $short_urls{$uri} = 1;
    }
  }

  # Make sure we have some work to do
  # Before we open any log files etc.
  return unless %short_urls;

  # Initialize cache
  $self->initialise_url_shortener_cache($conf);

  # Initialize LWP
  my $ua = LWP::UserAgent->new();
  $ua->{max_redirect} = 0;
  $ua->{timeout} = 5;
  $ua->env_proxy;

  # Launch HTTP queries
  my $lookups = 0;
  foreach my $short_url (keys %short_urls) {
    $self->recursive_lookup($short_url, $pms, $ua);
    last if ++$lookups >= $conf->{max_short_urls};
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
  my ($self, $short_url, $pms, $ua, %been_here) = @_;
  my $conf = $pms->{conf};

  my $count = scalar keys %been_here;
  dbg("redirection count $count") if $count;
  if ($count >= 10) {
    dbg("found more than 10 shortener redirections");
    # Fire test
    $pms->{short_url_maxchain} = 1;
    return;
  }

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
    my $response = $ua->head($short_url);
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
    if ($self->{url_shortener_loginfo}) {
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

  # At this point we have a new URL in $response
  $pms->{short_url} = 1;

  # Set chained here otherwise we might mark a disabled page or
  # redirect back to the same host as chaining incorrectly.
  $pms->{short_url_chained} = 1 if $count;

  # Check if we are being redirected to a local page
  # Don't recurse in this case...
  if ($location !~ m{^[a-z]+://}i) {
    my $orig_location = $location;
    my $orig_short_url = $short_url;
    # Strip to..
    if (index($location, '/') == 0) {
      $short_url =~ s{^([a-z]+://.*?)[/?#].*}{$1}; # ..absolute path
    } else {
      $short_url =~ s{^([a-z]+://.*)/}{$1}; # ..relative path
    }
    $location = "$short_url/$location";
    dbg("looks like a local redirection: $orig_short_url => $location ($orig_location)");
    $pms->add_uri_detail_list($location) if !$pms->{uri_detail_list}->{$location};
    return;
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
  if (_check_shortener_uri($location, $conf)) {
    # Recurse...
    $self->recursive_lookup($location, $pms, $ua, %been_here);
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

1;
