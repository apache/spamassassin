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
  ...
  body HAS_SHORT_URL          eval:short_url()
  describe HAS_SHORT_URL      Message contains one or more shortened URLs

  body SHORT_URL_CHAINED      eval:short_url_chained()
  describe SHORT_URL_CHAINED  Message has shortened URL chained to other shorteners

=head1 DESCRIPTION

This plugin looks for URLs shortened by a list of URL shortening services and
upon finding a matching URL will connect using to the shortening service and
do an HTTP HEAD lookup and retrieve the location header which points to the
actual shortened URL, it then adds this URL to the list of URIs extracted by
SpamAssassin which can then be accessed by other plug-ins, such as URIDNSBL.

This plugin also sets the rule HAS_SHORT_URL if any matching short URLs are
found.

This plug-in will follow 'chained' shorteners e.g.
from short URL to short URL to short URL and finally to the real URL


If this form of chaining is found, then the rule 'SHORT_URL_CHAINED' will be
fired.  If a loop is detected then 'SHORT_URL_LOOP' will be fired.
This plug-in limits the number of chained shorteners to a maximim of 10 at
which point it will fire the rule 'SHORT_URL_MAXCHAIN' and go no further.

If a shortener returns a '404 Not Found' result for the short URL then the
rule 'SHORT_URL_404' will be fired.

If a shortener returns a '200 OK' result for the short URL then the
rule 'SHORT_URL_200' will be fired.

This can cover the case when an abuse page is displayed.

=head1 NOTES

This plugin runs the check_dnsbl hook with a priority of -10 so that
it may modify the parsed URI list prior to the URIDNSBL plugin which
runs as priority 0.

Currently the plugin queries a maximum of 10 distinct shortened URLs with
a maximum timeout of 5 seconds per lookup.

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
use constant HAS_DBI => eval { require DBI; };

sub dbg { my $msg = shift; return Mail::SpamAssassin::Logger::dbg("DecodeShortURLs: $msg", @_); }
sub info { my $msg = shift; return Mail::SpamAssassin::Logger::info("DecodeShortURLs: $msg", @_); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  if ($mailsaobject->{local_tests_only} || !HAS_LWP_USERAGENT) {
    $self->{disabled} = 1;
  } else {
    $self->{disabled} = 0;
  }

  unless ($self->{disabled}) {
    $self->{ua} = new LWP::UserAgent;
    $self->{ua}->{max_redirect} = 0;
    $self->{ua}->{timeout} = 5;
    $self->{ua}->env_proxy;
    $self->{caching} = 0;
  }

  $self->set_config($mailsaobject->{conf});
  $self->register_method_priority ('check_dnsbl', -10);
  $self->register_eval_rule('short_url');
  $self->register_eval_rule('short_url_200');
  $self->register_eval_rule('short_url_404');
  $self->register_eval_rule('short_url_chained');
  $self->register_eval_rule('short_url_maxchain');
  $self->register_eval_rule('short_url_loop');

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
      if ($value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, $value)) {
        $self->{url_shorteners}->{lc $domain} = 1;
      }
    }
  });

=over 4

=item url_shortener_cache_type     (default: none)

The specific type of cache type that is being utilized. Currently only sqlite
is configured however plans to support redis cache is planned.

Example:
url_shortener_cache_type sqlite

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_type',
    default => undef,
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

=over 4

=item url_shortener_cache_dsn		(default: none)

The dsn to a database file to write cache entries to.  The database will
be created automatically if is does not already exist but the supplied path
and file must be read/writable by the user running spamassassin or spamd.

Note: You will need to have the proper DBI version of the cache type installed.

Example:

url_shortener_cache_dsn dbi:SQLite:dbname=/tmp/DecodeShortURLs.sq3

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

The username that should be used to connect to the database.

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

The password that should be used to connect to the database.

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

NOTE: you will also need to run the following via cron to actually remove the
records from the database:

echo "DELETE FROM short_url_cache WHERE modified < NOW() - C<ttl>; | sqlite3 /path/to/database"

NOTE: replace C<ttl> above with the same value you use for this option

=back

=cut

  push (@cmds, {
    setting => 'url_shortener_cache_ttl',
    is_admin => 1,
    default => 86400,
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
  my($self, $opts) = @_;

  if($self->{url_shortener_cache_type} eq "dbi" && defined $self->{url_shortener_cache_dsn} && HAS_DBI) {
    $self->{url_shortener_dbi_cache} = $self->{url_shortener_cache_dsn};
    return _connect_dbi_cache($self, $opts);
  } else {
    warn "Wrong cache type selected";
    return;
  }
}

sub _connect_dbi_cache {
  my($self, $opts) = @_;

  # Initialise cache if enabled
  if ($self->{url_shortener_dbi_cache} && HAS_DBI) {
    eval {
      local $SIG{'__DIE__'};
      $self->{dbh} = DBI->connect_cached(
        $self->{url_shortener_cache_dsn},
        $self->{url_shortener_cache_username},
        $self->{url_shortener_cache_password},
        {RaiseError => 1, PrintError => 0, InactiveDestroy => 1}
      ) or die $!;
    };
    if ($@) {
      dbg("warn: $@");
    } else {
      $self->{caching} = 1;
    }
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

sub check_dnsbl {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $msg = $opts->{msg};

  return if $self->{disabled};

  # don't keep dereferencing these
  $self->{url_shorteners} = $pms->{main}->{conf}->{url_shorteners};
  if(defined $pms->{main}->{conf}->{url_shortener_cache_type}) {
    $self->{url_shortener_cache_type} = $pms->{main}->{conf}->{url_shortener_cache_type};
    $self->{url_shortener_cache_dsn} = $pms->{main}->{conf}->{url_shortener_cache_dsn};
    $self->{url_shortener_cache_username} = $pms->{main}->{conf}->{url_shortener_cache_username};
    $self->{url_shortener_cache_password} = $pms->{main}->{conf}->{url_shortener_cache_password};
    $self->{url_shortener_cache_ttl} = $pms->{main}->{conf}->{url_shortener_cache_ttl};
  }
  $self->{url_shortener_loginfo} = $pms->{main}->{conf}->{url_shortener_loginfo};

  # Sort short URLs into hash to de-dup them
  my %short_urls;
  my $uris = $pms->get_uri_detail_list();
  my $tldsRE = $self->{main}->{registryboundaries}->{valid_tlds_re};
  while (my($uri, $info) = each %{$uris}) {
    next unless ($info->{domains});
    foreach ( keys %{ $info->{domains} } ) {
      if (exists $self->{url_shorteners}->{lc $_}) {
        # NOTE: $info->{domains} appears to contain all the domains parsed
        # from the single input URI with no way to work out what the base
        # domain is.  So to prevent someone from stuffing the URI with a
        # shortener to force this plug-in to follow a link that *isn't* on
        # the list of shorteners; we enforce that the shortener must be the
        # base URI and that a path must be present.
        if ($uri !~ /^https?:\/\/(?:www\.)?$_\/.+$/i) {
          dbg("Discarding URI: $uri");
          next;
        }
        $short_urls{$uri} = 1;
        next;
      } elsif(/^(?!www)[a-z\d._-]{0,251}\.([a-z\d._-]{0,251}\.${tldsRE})/) {
        # if domain is a 3rd level domain check if there is a url shortener
        # on the 2nd level tld
        my $dom = '.' . $1;
        if (exists $self->{url_shorteners}->{$dom}) {
          if ($uri !~ /^https?:\/\/(?:www\.)?$_\/.+$/i) {
            dbg("Discarding URI: $uri");
            next;
          }
          $short_urls{$uri} = 1;
          next;
        }
      }
    }
  }

  # Make sure we have some work to do
  # Before we open any log files etc.
  my $count = scalar keys %short_urls;
  return unless $count gt 0;

  $self->initialise_url_shortener_cache($opts) if defined $self->{url_shortener_cache_type};

  my $max_short_urls = $pms->{main}->{conf}->{max_short_urls};
  foreach my $short_url (keys %short_urls) {
    next if $max_short_urls <= 0;
    my $location = $self->recursive_lookup($short_url, $pms);
    $max_short_urls--;
  }
}

sub recursive_lookup {
  my ($self, $short_url, $pms, %been_here) = @_;

  my $count = scalar keys %been_here;
  dbg("Redirection count $count") if $count gt 0;
  if ($count >= 10) {
    dbg("Error: more than 10 shortener redirections");
    # Fire test
    $self->{short_url_maxchain} = 1;
    return;
  }

  my $location;
  if ($self->{caching} && ($location = $self->cache_get($short_url))) {
    if ($self->{url_shortener_loginfo}) {
      info("Found cached $short_url => $location");
    } else {
      dbg("Found cached $short_url => $location");
    }
  } else {
    # Not cached; do lookup
    if($count eq 0) {
      undef $pms->{short_url_200};
      undef $pms->{short_url_404};
      undef $pms->{short_url_chained};
    }
    my $response = $self->{ua}->head($short_url);
    if (!$response->is_redirect) {
      dbg("URL is not redirect: $short_url = ".$response->status_line);
      $pms->{short_url_200} = 1 if($response->code == '200');
      $pms->{short_url_404} = 1 if($response->code == '404');
      return;
    }
    $location = $response->headers->{location};
    # Bail out if $short_url redirects to itself
    return if ($short_url eq $location);
    if ($self->{caching}) {
      if ($self->cache_add($short_url, $location)) {
        dbg("Added $short_url to cache");
      } else {
        dbg("Cannot add $short_url to cache");
      }
    }
    if($self->{url_shortener_loginfo}) {
      info("Found $short_url => $location");
    } else {
      dbg("Found $short_url => $location");
    }
  }

  # At this point we have a new URL in $response
  $pms->{short_url} = 1;

  # Set chained here otherwise we might mark a disabled page or
  # redirect back to the same host as chaining incorrectly.
  $pms->{short_url_chained} = 1 if $count > 0;

  $pms->add_uri_detail_list($location);

  # Check if we are being redirected to a local page
  # Don't recurse in this case...
  if($location !~ /^https?:/) {
    my($host) = ($short_url =~ /^(https?:\/\/\S+)\//);
    $location = "$host/$location";
    dbg("Looks like a local redirection: $short_url => $location");
    $pms->add_uri_detail_list($location);
    return $location;
  }

  # Check for recursion
  if ((my ($domain) = ($location =~ /^https?:\/\/(\S+)\//))) {
    if (exists $been_here{$location}) {
      # Loop detected
      dbg("Error: loop detected");
      $self->{short_url_loop} = 1;
      return $location;
    } else {
      my $tldsRE = $self->{main}->{registryboundaries}->{valid_tlds_re};
      if (exists $self->{url_shorteners}->{$domain}) {
        $been_here{$location} = 1;
        # Recurse...
        return $self->recursive_lookup($location, $pms, %been_here);
      } elsif($domain =~ /^(?!www)[a-z\d._-]{0,251}\.([a-z\d._-]{0,251}\.${tldsRE})/) {
        # if domain is a 3rd level domain check if there is a url shortener
        # on the 2nd level tld
        my $dom = '.' . $1;
        if (exists $self->{url_shorteners}->{$dom}) {
          $been_here{$location} = 1;
          # Recurse...
          return $self->recursive_lookup($location, $pms, %been_here);
        }
      }
    }
  }

  # No recursion; just return the final location...
  return $location;
}

sub cache_add {
  my ($self, $short_url, $decoded_url) = @_;
  return 0 if not $self->{caching};

  return 0 if((length($short_url) > 256) or (length($decoded_url) > 512));

  eval {
    $self->{sth_insert} = $self->{dbh}->prepare_cached("
      INSERT INTO short_url_cache (short_url, decoded_url, created, modified)
      VALUES (?,?,?,?)
    ");
  };
  if ($@) {
    dbg("warn: $@");
    return 0;
  };

  $self->{sth_insert}->execute($short_url, $decoded_url, time(), time());
  return 1;
}

sub cache_get {
  my ($self, $key) = @_;
  return if not $self->{caching};

  eval {
    $self->{sth_select} = $self->{dbh}->prepare_cached("
      SELECT decoded_url FROM short_url_cache
      WHERE short_url = ? AND modified > ?
    ");
  };
  if ($@) {
   dbg("warn: $@");
   return;
  }

  eval {
    $self->{sth_update} = $self->{dbh}->prepare_cached("
      UPDATE short_url_cache
      SET modified=?, hits=hits+1
      WHERE short_url = ?
    ");
  };
  if ($@) {
   dbg("warn: $@");
   return;
  }

  my $tcheck = time() - $self->{url_shortener_cache_ttl};
  $self->{sth_select}->execute($key, $tcheck);
  my $row = $self->{sth_select}->fetchrow_array();
  if($row) {
    # Found cache entry; touch it to prevent expiry
    $self->{sth_update}->execute(time(),$key);
    $self->{sth_select}->finish();
    $self->{sth_update}->finish();
    return $row;
  }

  $self->{sth_select}->finish();
  $self->{sth_update}->finish();
  return;
}

# Version features
sub has_short_url { 1 }

1;
