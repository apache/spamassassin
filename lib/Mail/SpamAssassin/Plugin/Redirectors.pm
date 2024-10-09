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

Redirectors - Check for redirected URLs

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::Redirectors

  url_redirector bing.com

  body HAS_REDIR_URL          eval:redir_url()
  describe HAS_REDIR_URL      Message has one or more redirected URLs

  body REDIR_URL_CHAINED      eval:redir_url_chained()
  describe REDIR_URL_CHAINED  Message has redirected URL chained to other redirectors

  body REDIR_URL_MAXCHAIN     eval:redir_url_maxchain()
  describe REDIR_URL_MAXCHAIN Message has redirected URL that causes too many redirections

  body REDIR_URL_LOOP         eval:redir_url_loop()
  describe REDIR_URL_LOOP     Message has redirected URL that loops back to itself

  body REDIR_URL_404          eval:redir_url_code('404') # Can check any non-redirect HTTP code
  describe REDIR_URL_404      Message has redirected URL returning HTTP 404

=head1 DESCRIPTION

This plugin looks for URLs redirected by a list of URL redirector services. 
Upon finding a matching URL, plugin will send a HTTP request to the
redirector service and retrieve the Location-header which points to the
actual redirected URL.  It then adds this URL to the list of URIs extracted
by SpamAssassin which can then be accessed by uri rules and plugins such as
URIDNSBL.

This plugin will follow chained redirections, where a redirected URL redirects to
another redirector.  Redirection depth limit can be set with
C<max_redir_url_redirections>.

Maximum of C<max_redir_urls> redirected URLs are checked in a message (10 by
default).  Setting it to 0 disables HTTP requests, allowing only redir_url()
test to work and report found redirectors.

All supported rule types for checking redirector URLs and redirection status are
documented in L<SYNOPSIS> section.

=head1 NOTES

This plugin runs at the check_dnsbl hook (priority -100) so that it may
modify the parsed URI list prior to normal uri rules or the URIDNSBL plugin.

=cut

package Mail::SpamAssassin::Plugin::Redirectors;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 4.02;

use constant HAS_LWP_USERAGENT => eval { require LWP::UserAgent; require LWP::Protocol::https; };

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
  $self->register_method_priority ('check_dnsbl', -10);
  $self->register_eval_rule('redir_url', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_404', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_code', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_chained', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_maxchain', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule('redir_url_loop', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

=head1 USER SETTINGS

=over 4

=item url_redirector  domain [domain...]     (default: none)

Domains that should be considered as an URL redirector.  If the domain begins
with a '.', 3rd level tld of the main domain will be checked.
The 3rd level starting with www with always be checked for every 2tld.

Example:

 url_redirector bing.com
 url_redirector .sendgrid.com

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'url_redirector',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_redirector}->{lc $domain} = 1; # 1 == head
      }
    }
  });

=over 4

=item clear_url_redirector  [domain] [domain...]

Clear configured url_redirector domains, for example to
override default settings from an update channel.  If domains are specified,
then only those are removed from list.

=back

=cut

  push (@cmds, {
    setting => 'clear_url_redirector',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        $self->{url_redirector} = {};
      } else {
        foreach my $domain (split(/\s+/, $value)) {
          delete $self->{url_redirector}->{lc $domain};
        }
      }
    }
  });

=over 4

=item url_redirector_get  domain [domain...]     (default: none)

Domains that should be considered as an URL redirector.  If the domain begins
with a '.', 3rd level tld of the main domain will be checked.
The http GET method will be used to check those domains.

=back

=cut

  push (@cmds, {
    setting => 'url_redirector_get',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_redirector}->{lc $domain} = 2; # 2 == get
      }
    }
  });

=over 4

=item url_redirector_params regexp (default: (?:adurl|af_web_dp|cm_destination|destination|destURL|l|location|p1|pval|r|redir|redirect|redirectTo|return|returnUrl|referer|tid|u|url)=(.*))

Regexp used to parse uri parameters in order to detect redirectors and to get redirected domains.
The regexp must match only the redirected domain.

=back

=cut

  push(@cmds, {
    setting => 'url_redirector_params',
    default => qr/(?:adurl|af_web_dp|cm_destination|destination|destURL|l|login|location|p1|pval|r|redir|redirect|redirectTo|ret_url|return|returnUrl|referer|service|target|tid|u|url)=(.*)/,
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

  $conf->{parser}->register_commands(\@cmds);
}

sub initialise_url_redirector_cache {
  my ($self, $conf) = @_;

  return if $self->{dbh};
  return if !$conf->{url_redirector_cache_type};

  if (!$conf->{url_redirector_cache_dsn}) {
    warn "Redirectors: invalid cache configuration\n";
    return;
  }

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
        CREATE TABLE IF NOT EXISTS redir_url_cache (
          redir_url   TEXT PRIMARY KEY NOT NULL,
          target_url  TEXT NOT NULL,
          hits        INTEGER NOT NULL DEFAULT 1,
          created     INTEGER NOT NULL,
          modified    INTEGER NOT NULL
        )
      ");
      # Maintaining index for cleaning is likely more expensive than occasional full table scan
      #$self->{dbh}->do("
      #  CREATE INDEX IF NOT EXISTS redir_url_modified
      #    ON redir_url_cache(created)
      #");
      $self->{sth_insert} = $self->{dbh}->prepare("
        INSERT INTO redir_url_cache (redir_url, target_url, created, modified)
        VALUES (?,?,strftime('%s','now'),strftime('%s','now'))
        ON CONFLICT(redir_url) DO UPDATE
          SET target_url = excluded.target_url,
              modified = excluded.modified,
              hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT target_url FROM redir_url_cache
        WHERE redir_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
        WHERE redir_url = ? AND created < strftime('%s','now') - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
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
        INSERT INTO redir_url_cache (redir_url, target_url, created, modified)
        VALUES (?,?,UNIX_TIMESTAMP(),UNIX_TIMESTAMP())
        ON DUPLICATE KEY UPDATE
          target_url = VALUES(target_url),
          modified = VALUES(modified),
          hits = hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT target_url FROM redir_url_cache
        WHERE redir_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
        WHERE redir_url = ? AND created < UNIX_TIMESTAMP() - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
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
        INSERT INTO redir_url_cache (redir_url, target_url, created, modified)
        VALUES (?,?,CAST(EXTRACT(epoch FROM NOW()) AS INT),CAST(EXTRACT(epoch FROM NOW()) AS INT))
        ON CONFLICT (redir_url) DO UPDATE SET
          target_url = EXCLUDED.target_url,
          modified = EXCLUDED.modified,
          hits = redir_url_cache.hits + 1
      ");
      $self->{sth_select} = $self->{dbh}->prepare("
        SELECT target_url FROM redir_url_cache
        WHERE redir_url = ?
      ");
      $self->{sth_delete} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
        WHERE redir_url = ? AND created < CAST(EXTRACT(epoch FROM NOW()) AS INT) - $conf->{url_redirector_cache_ttl}
      ");
      $self->{sth_clean} = $self->{dbh}->prepare("
        DELETE FROM redir_url_cache
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
    undef $self->{sth_insert};
    undef $self->{sth_select};
    undef $self->{sth_delete};
    undef $self->{sth_clean};
  }
}

sub redir_url {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url} ? 1 : 0;
}

sub redir_url_redir {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url_redir} ? 1 : 0;
}

sub redir_url_404 {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url_404} ? 1 : 0;
}

sub redir_url_code {
  my ($self, $pms, undef, $code) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return 0 unless defined $code && $code =~ /^\d{3}$/;
  return $pms->{"redir_url_$code"} ? 1 : 0;
}

sub redir_url_chained {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url_chained} ? 1 : 0;
}

sub redir_url_maxchain {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url_maxchain} ? 1 : 0;
}

sub redir_url_loop {
  my ($self, $pms) = @_;

  # Make sure checks are run
  $self->_check_redir($pms);

  return $pms->{redir_url_loop} ? 1 : 0;
}

sub _check_redirector_uri {
  my ($uri, $conf) = @_;

  my $newuri;

  local($1,$2);
  # normalize uri
  $uri = Mail::SpamAssassin::Util::url_decode($uri);
  # remove anchors
  $uri =~ s/\#.{1,32}//g;
  return 0 unless $uri =~ m{^
    https?://		# Only http
    (?:[^\@/?#]*\@)?	# Ignore user:pass@
    ([^/?#:]+)		# (Capture hostname)
    (?::\d+)?		# Possible port
    (.*)?		# Some path wanted
    }ix;
  my $host = lc $1;
  my $has_path = defined $2;
  my $levels = $host =~ tr/.//;
  # No point looking at single level "xxx.yy" without a path
  return if $levels == 1 && !$has_path;

  my $params = $2;
  if($has_path and defined $params and (length($params) > 2)) {
    dbg("Found url with host $host and querystring $params");
  }
  return if $uri !~ /([^.]+\.[^.]+)/;
  # skip wrongly parsed uris
  return if $uri =~ /^([a-z0-9]+?)\@/;

  if (exists $conf->{url_redirector}->{$host}) {
    dbg("Found redirection for host $host");
    return {
      'uri' => $uri,
      'method' => $conf->{url_redirector}->{$host} == 1 ? 'head' : 'get',
    };
  }
  # if domain is a 3rd level domain check if there is a url redirector
  # on the www domain
  elsif($levels == 2 && $host =~ /^www\.([^.]+\.[^.]+)$/i) {
    my $domain = $1;
    if(($host eq "www.$domain") and exists $conf->{url_redirector}->{$domain}) {
      dbg("Found internal www redirection for domain $domain");
      return {
        'uri' => $uri,
        'method' => $conf->{url_redirector}->{$domain} == 1 ? 'head' : 'get',
      };
    }
    if ($newuri = _check_querystring($params, $conf)) {
      return {
        'uri' => $newuri,
        'method' => 'head',
      };
    }
  }
  # if domain is a 3rd level domain check if there is a url redirector
  # on the 2nd level tld
  elsif ($levels == 2 && $host =~ /^(?!www)[^.]+(\.[^.]+\.[^.]+)$/i &&
           exists $conf->{url_redirector}->{$1}) {
    return {
      'uri' => $uri,
      'method' => $conf->{url_redirector}->{$1} == 1 ? 'head' : 'get',
    };
  }
  elsif ($host =~ /(\.[a-z0-9_]+\.[a-z]+)$/i &&
           exists $conf->{url_redirector}->{$1}) {
    return {
      'uri' => $uri,
      'method' => $conf->{url_redirector}->{$1} == 1 ? 'head' : 'get',
    };
  } elsif ($newuri = _check_querystring($params, $conf)) {
    return {
      'uri' => $newuri,
      'method' => 'head',
    };
  } else {
    dbg("No explicit redirector host found for $host");
  }
  return;
}

sub _check_querystring {
  my ($params, $conf) = @_;

  # Redirector params regexp
  my $rreg = $conf->{url_redirector_params};

  # Check parameters regexp and https:// in the querystring
  if (($params =~ /$rreg/gis) or ($params =~ /\/https?:\/\/(.*)/)) {
    dbg("Found redirection with path $params");
    my $newuri = $1;
    if($newuri !~ /^http/) {
      $newuri = 'http://' . $newuri;
    }
    return $newuri;
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

  # Sort redirected URLs into hash to de-dup them
  my %redir_urls;
  my $uris = $pms->get_uri_detail_list();
  foreach my $uri (keys %{$uris}) {
    my $info = $uris->{$uri};
    next unless $info->{domains} && $info->{cleaned};
    if (my $redir_url_info = _check_redirector_uri($uri, $conf)) {
      $redir_urls{$uri} = $redir_url_info;
      last if scalar keys %redir_urls >= $conf->{max_redir_urls};
    }
  }

  # Bail out if no redirector was found
  return unless %redir_urls;

  # Mark that a URL redirector was found
  $pms->{redir_url} = 1;

  # Bail out if network lookups not enabled or max_redir_urls 0
  return if $self->{net_disabled};
  return if !$conf->{max_redir_urls};

  # Initialize cache
  $self->initialise_url_redirector_cache($conf);

  # Initialize LWP
  my $ua = LWP::UserAgent->new(
    'agent' => $conf->{url_redirector_user_agent},
    'max_redirect' => 0,
    'timeout' => $conf->{url_redirector_timeout},
  );
  $ua->env_proxy;

  # Launch HTTP requests
  foreach my $uri (keys %redir_urls) {
    $self->recursive_lookup($redir_urls{$uri}, $pms, $ua);
  }

  # Automatically purge old entries
  if ($self->{dbh} && $conf->{url_redirector_cache_autoclean}
      && rand() < 1/$conf->{url_redirector_cache_autoclean})
  {
    dbg("cleaning stale cache entries");
    eval { $self->{sth_clean}->execute(); };
    if ($@) { dbg("cache cleaning failed: $@"); }
  }
}

sub recursive_lookup {
  my ($self, $redir_url_info, $pms, $ua, %been_here) = @_;
  my $conf = $pms->{conf};

  my $count = scalar keys %been_here;
  dbg("redirection count $count") if $count;
  if ($count >= $conf->{max_redir_url_redirections}) {
    dbg("found more than $conf->{max_redir_url_redirections} redirections");
    # Fire test
    $pms->{redir_url_maxchain} = 1;
    return;
  }

  my $redir_url = $redir_url_info->{uri};
  my $location;
  if (defined($location = $self->cache_get($redir_url))) {
    if ($conf->{url_redirector_loginfo}) {
      info("found cached $redir_url => $location");
    } else {
      dbg("found cached $redir_url => $location");
    }
    # Cached http code?
    if ($location =~ /^\d{3}$/) {
      $pms->{"redir_url_$location"} = 1;
      # add uri to uri_detail_list
      $pms->add_uri_detail_list($redir_url) if !$pms->{uri_detail_list}->{$redir_url};
      # Update cache
      $self->cache_add($redir_url, $location);
      return;
    }
  } else {
    # Not cached; do lookup
    my $method = $redir_url_info->{method};
    my $response = $ua->$method($redir_url);
    if (!$response->is_redirect) {
      dbg("URL is not a redirect: $redir_url = ".$response->status_line);
      my $rcode = $response->code;
      if ($rcode =~ /^\d{3}$/) {
        return if $redir_url !~ /([^.]+\.[^.]+)/;
        $pms->{"redir_url_$rcode"} = 1;
        # Update cache
        $self->cache_add($redir_url, $rcode);
	# add uri to uri_detail_list
        $pms->add_uri_detail_list($redir_url) if !$pms->{uri_detail_list}->{$redir_url};
      }
      return;
    }
    $location = $response->headers->{location};
    if($redir_url ne $location) {
      if ($conf->{url_redirector_loginfo}) {
        info("found $redir_url => $location");
      } else {
        dbg("found $redir_url => $location");
      }
    }
  }

  # Update cache
  $self->cache_add($redir_url, $location);

  # Bail out if $redir_url redirects to itself
  if ($redir_url eq $location) {
    dbg("URL redirects to itself");
    $pms->{redir_url_loop} = 1;
    return;
  }

  # At this point we have a valid redirection and new URL in $response
  $pms->{redir_url_redir} = 1;

  # Set chained here otherwise we might mark a disabled page or
  # redirect back to the same host as chaining incorrectly.
  $pms->{redir_url_chained} = 1 if $count;

  # Check if it is a redirection to a relative URI
  # Make it an absolute URI and chain to it in that case
  if ($location !~ m{^[a-z]+://}i) {
    my $orig_location = $location;
    my $orig_redir_url = $redir_url;
    # Strip to..
    if (index($location, '/') == 0) {
      $redir_url =~ s{^([a-z]+://.*?)[/?#].*}{$1}; # ..absolute path base is http://example.com
    } else {
      $redir_url =~ s{^([a-z]+://.*/)}{$1}; # ..relative path base is http://example.com/a/b/
    }
    $location = "$redir_url$location";
    dbg("looks like a redirection to a relative URI: $orig_redir_url => $location ($orig_location)");
  }

  if (exists $been_here{$location}) {
    # Loop detected
    dbg("error: loop detected: $location");
    $pms->{redir_url_loop} = 1;
    return;
  }
  $been_here{$location} = 1;
  $pms->add_uri_detail_list($location) if !$pms->{uri_detail_list}->{$location};

  # Check for recursion
  if (my $redir_url_info = _check_redirector_uri($location, $conf)) {
    # Recurse...
    $self->recursive_lookup($redir_url_info, $pms, $ua, %been_here);
  }
}

sub cache_add {
  my ($self, $redir_url, $target_url) = @_;

  return if !$self->{dbh};
  return if length($redir_url) > 256 || length($target_url) > 512;

  # Upsert
  eval { $self->{sth_insert}->execute($redir_url, $target_url); };
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

1;
