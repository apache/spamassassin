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

Mail::SpamAssassin::BayesStore::Redis - Redis Bayesian Storage Module Implementation

=head1 DESCRIPTION

This module implements a Redis based bayesian storage module with support
for separate read and write servers.

Apache SpamAssassin v3.4.0 introduces support for keeping
a Bayes database on a Redis server, either running locally, or accessed
over network. Similar to SQL backends, the database may be concurrently
used by several hosts running SpamAssassin.

The current implementation only supports a global Bayes database, i.e.
per-recipient sub-databases are not supported. The Redis server supports
access over IPv4 or over a Unix socket, and since Redis version 2.8.0 also
IPv6 is supported. Bear in mind that Redis server only offers limited access
controls, so it is advisable to let the Redis server bind to a loopback interface
only, or to use other mechanisms to limit access, such as local firewall rules.

The Redis backend for Bayes can put a Lua scripting support in a Redis
server to good use, improving performance. The Lua support is available
in Redis server since version 2.6. In absence of a Lua support, the Redis
backend uses batched (pipelined) traditional Redis commands, so it should
work with a Redis server version 2.4 (untested), although this is not
recommended for busy sites.

Expiration of token and 'seen' message id entries is left to the Redis
server. There is no provision for manually expiring a database, so it is
highly recommended to leave the setting bayes_auto_expire to its default
value 1 (i.e. enabled).

The module supports separate read and write servers, allowing for Redis
replication-based scaling and high availability. Multiple read servers can
be configured, with automatic failover if one becomes unavailable.

Example configuration:

  # Basic configuration with single server
  bayes_store_module      Mail::SpamAssassin::BayesStore::Redis
  bayes_redis_write_server server=127.0.0.1:6379;password=foo
  bayes_redis_read_servers server=127.0.0.1:6379;password=foo
  bayes_redis_database    2
  bayes_token_ttl         21d
  bayes_seen_ttl          8d
  bayes_auto_expire       1

  # Configuration with primary/replica setup
  bayes_store_module      Mail::SpamAssassin::BayesStore::Redis
  bayes_redis_write_server server=redis-master.example.com:6379;password=foo
  bayes_redis_read_servers server=redis-replica1.example.com:6379;password=foo,server=redis-replica2.example.com:6379;password=foo
  bayes_redis_database    2
  bayes_redis_prefix      bayes:
  bayes_token_ttl         21d
  bayes_seen_ttl          8d
  bayes_auto_expire       1

A redis server with a Lua support (2.6 or higher) is recommended
for performance reasons.

The following configuration options are available:

  bayes_redis_read_servers

    Comma-separated list of Redis read servers with connection parameters.
    Each server specification is a semicolon-separated list of option=value
    pairs.

    Example: server=replica1.example.com:6379;password=foo,server=replica2.example.com:6379;password=foo

  bayes_redis_write_server

    Redis write server with connection parameters as a semicolon-separated
    list of option=value pairs.

    Example: server=master.example.com:6379;password=foo

  bayes_redis_database

    Database index to use (default: 0). This is passed to a Redis server
    with a SELECT command on connecting and chooses a sub-database index.

  bayes_redis_password

    Password for authentication with Redis servers. This can be overridden
    in individual server specifications.

  bayes_redis_prefix

    Optional prefix for all Redis keys. Allows multiple instances to share
    a Redis database.

    Example: bayes:user1:

  bayes_sql_dsn

    Legacy configuration option, still supported for backward
    compatibility. This is a semicolon-separated list of option=value
    pairs, where an option can be: server, password, database. If this
    option is used and the new options above are not specified, the same
    configuration will be used for both read and write operations.

    Example: server=localhost:6379;password=foo;database=2

  bayes_token_ttl

    Controls token expiry (ttl value in SECONDS, sent as-is to Redis)
    when bayes_auto_expire is true. Default value is 3 weeks (but check
    Mail::SpamAssassin::Conf.pm to make sure).

  bayes_seen_ttl

    Controls 'seen' expiry (ttl value in SECONDS, sent as-is to Redis)
    when bayes_auto_expire is true. Default value is 8 days (but check
    Mail::SpamAssassin::Conf.pm to make sure).

Expiry is done internally in Redis using *_ttl settings mentioned above,
but only if bayes_auto_expire is true (which is a default). This is
why --force-expire etc does nothing, and token counts and atime values
are shown as zero in statistics.

=head2 Redis Replication Considerations

To maintain data consistency, this module is designed to work with Redis
in a primary/replica configuration where:

1. All write operations go to a single primary Redis server.
2. Read operations can be distributed across multiple Redis replicas.

When setting up the Redis servers, configure:
- One Redis server as the primary, handling all writes.
- One or more Redis replicas (read-only) for scaling read operations.

In case of read server failure, the module will automatically attempt to
connect to the next configured read server.

=head2 Key Namespacing

The module supports key namespacing via the bayes_redis_prefix
configuration option. This allows multiple SpamAssassin instances to share
the same Redis database with different key prefixes.

LIMITATIONS: Only global bayes storage is implemented, per-user bayes is
not currently available. Dumping (sa-learn --backup, or --dump) of a huge
database may not be possible if all keys do not fit into process memory.

=cut

package Mail::SpamAssassin::BayesStore::Redis;

use strict;
use warnings;
# use bytes;
use re 'taint';
use Errno qw(EBADF);
use Digest::SHA qw(sha1);

use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var);
use Mail::SpamAssassin::Util::TinyRedis;

our $VERSION = 0.10;
our @ISA = qw( Mail::SpamAssassin::BayesStore );

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::Redis) new (Mail::Spamassassin::Plugin::Bayes $bayes)

Description:
This methods creates a new instance of the Mail::SpamAssassin::BayesStore::Redis
object. It expects to be passed an instance of the Mail::SpamAssassin:Bayes
object which is passed into the Mail::SpamAssassin::BayesStore parent object.

Configuration:
  bayes_redis_read_servers  - Comma-separated list of Redis read servers with connection parameters
  bayes_redis_write_server  - Single Redis write server with connection parameters
  bayes_redis_database      - Redis database number (default: 0)
  bayes_redis_password      - Redis password for authentication
  bayes_redis_prefix        - Key prefix for namespacing (default: "")

Legacy configuration (still supported):
  bayes_sql_dsn             - DSN-style connection string

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new(@_);

  my $bconf = $self->{bayes}->{conf};

  # Initialize default values
  $self->{db_id} = 0;
  $self->{password} = undef;

  $self->{key_prefix} = $bconf->{bayes_redis_prefix} || "";

  my $key_prefix_tok_regex = "^$self->{key_prefix}w:";
  my ($rec, $err) = compile_regexp($key_prefix_tok_regex, 0);
  if (!$rec) {
    die "Can't create regex '$key_prefix_tok_regex': $err\n";
  }
  $self->{key_prefix_tok_regex} = $rec;

  my $key_prefix_seen_regex = "^$self->{key_prefix}s:";
  ($rec, $err) = compile_regexp($key_prefix_seen_regex, 0);
  if (!$rec) {
    die "Can't create regex '$key_prefix_seen_regex': $err\n";
  }
  $self->{key_prefix_seen_regex} = $rec;

  $self->{read_servers} = [];
  $self->{write_server} = undef;
  $self->{current_read_server} = 0;  # Index of current read server

  # Parse legacy configuration first (for backward compatibility)
  if ($bconf->{bayes_sql_dsn}) {
    my %conf = ();
    foreach (split(';', $bconf->{bayes_sql_dsn})) {
      my ($a, $b) = split(/=/, $_, 2);
      if (!defined $b) {
        warn("bayes: invalid bayes_sql_dsn config\n");
        return;
      } elsif ($a eq 'database') {
        $self->{db_id} = $b;
      } elsif ($a eq 'password') {
        $self->{password} = $b;
      } else {
        $conf{$a} = $b eq 'undef' ? undef : untaint_var($b);
      }
    }
    # Use legacy config for both read and write if newer config not specified
    if (%conf) {
      push @{$self->{read_servers}}, \%conf;
      $self->{write_server} = \%conf;
    }
  }

  # Parse new configuration parameters (override legacy if specified)
  if ($bconf->{bayes_redis_read_servers}) {
    @{$self->{read_servers}} = ();  # Clear any legacy config
    my @servers = split(/,/, $bconf->{bayes_redis_read_servers});
    foreach my $server (@servers) {
      my %conf = ();
      foreach (split(';', $server)) {
        my ($a, $b) = split(/=/, $_, 2);
        if (defined $b) {
          $conf{$a} = $b eq 'undef' ? undef : untaint_var($b);
        }
      }
      push @{$self->{read_servers}}, \%conf if %conf;
    }
  }

  if ($bconf->{bayes_redis_write_server}) {
    my %conf = ();
    foreach (split(';', $bconf->{bayes_redis_write_server})) {
      my ($a, $b) = split(/=/, $_, 2);
      if (defined $b) {
        $conf{$a} = $b eq 'undef' ? undef : untaint_var($b);
      }
    }
    $self->{write_server} = \%conf if %conf;
  }

  # Override with specific settings if provided
  $self->{db_id} = $bconf->{bayes_redis_database} if defined $bconf->{bayes_redis_database};
  $self->{password} = $bconf->{bayes_redis_password} if defined $bconf->{bayes_redis_password};

  if (!$bconf->{bayes_auto_expire}) {
    $self->{expire_token} = $self->{expire_seen} = undef;
    warn("bayes: the setting bayes_auto_expire is off, this is ".
         "not a recommended setting for the Redis bayes backend");
  } else {
    $self->{expire_token} = $bconf->{bayes_token_ttl};
    undef $self->{expire_token}  if $self->{expire_token} &&
                                    $self->{expire_token} < 0;
    $self->{expire_seen}  = $bconf->{bayes_seen_ttl};
    undef $self->{expire_seen}   if $self->{expire_seen} &&
                                    $self->{expire_seen} < 0;
  }

  $self->{supported_db_version} = 3;
  $self->{connected_read} = 0;
  $self->{connected_write} = 0;
  $self->{is_officially_open} = 0;
  $self->{is_writable} = 0;
  # store a fake _userid, needed for regression tests
  $self->{_userid} = $self->{db_id};

  $self->{timer} = Mail::SpamAssassin::Timeout->new({
    secs => $self->{conf}->{redis_timeout} || 10
  });

  return $self;
}

sub disconnect {
  my($self) = @_;
  local($@, $!);

  if ($self->{connected_read}) {
    dbg("bayes: Redis disconnect read connection");
    $self->{connected_read} = 0;
    $self->{redis_read}->disconnect if $self->{redis_read};
  }

  if ($self->{connected_write}) {
    dbg("bayes: Redis disconnect write connection");
    $self->{connected_write} = 0;
    $self->{redis_write}->disconnect if $self->{redis_write};
  }

  undef $self->{redis_read};
  undef $self->{redis_write};
}

=head2 DESTROY

Destructor method.

=cut

sub DESTROY {
  my($self) = @_;
  local($@, $!, $_);
  dbg("bayes: Redis destroy");
  $self->{connected_read} = $self->{connected_write} = 0;
  undef $self->{redis_read};
  undef $self->{redis_write};
}

# Called from a Redis module on Redis->new and on automatic re-connect.
# The on_connect() callback must not use batched calls!
sub on_connect {
  my($r, $db_id, $pwd) = @_;
  $db_id ||= 0;
  dbg("bayes: Redis on-connect, db_id %d", $db_id);
  eval {
    $r->call('SELECT', $db_id) eq 'OK' ? 1 : 0;
  } or do {
    if ($@ =~ /^NOAUTH\b/ || $@ =~ /^ERR operation not permitted/) {
      defined $pwd
        or die "Redis server requires authentication, no password provided";
      $r->call('AUTH', $pwd);
      $r->call('SELECT', $db_id);
    } else {
      chomp $@; die "Command 'SELECT $db_id' failed: $@";
    }
  };
  eval {
    $r->call('CLIENT', 'SETNAME', 'sa['.$$.']');
  } or do {
    dbg("bayes: CLIENT SETNAME command failed, don't worry, ".
        "possibly an old redis version: %s", $@);
  };
  1;
}

=head2 _connect_read

private instance (Boolean) _connect_read ()

Description:
Connects to a Redis read server. Tries each configured read server in turn
until one succeeds. If all fail, throws an exception.

=cut

sub _connect_read {
  my($self) = @_;

  return 1 if $self->{connected_read};

  if (!$self->{read_servers} || !@{$self->{read_servers}}) {
    die "bayes: No Redis read servers configured";
  }

  $self->_disconnect_read if $self->{connected_read};
  undef $self->{redis_read};  # just in case

  # Try each read server in turn, starting from the current one
  my $num_servers = scalar @{$self->{read_servers}};
  my $tried = 0;
  my $error = "";

  while ($tried < $num_servers) {
    my $server_index = ($self->{current_read_server} + $tried) % $num_servers;
    my $server_conf = $self->{read_servers}->[$server_index];

    dbg("bayes: trying to connect to read server %d", $server_index);

    my $connected = 0;
    my $err = $self->{timer}->run_and_catch(sub {
      $self->{opened_read_from_pid} = $$;
      my $db_id = $self->{db_id};
      my $pwd = $self->{password};

      $self->{redis_read} = Mail::SpamAssassin::Util::TinyRedis->new(
                       %$server_conf,
                       on_connect => sub { on_connect($_[0], $db_id, $pwd) });

      $self->{redis_read} or die "Error: $!";

      # Test connection with a simple command
      $self->{redis_read}->call('PING') eq 'PONG'
        or die "Failed to get PONG response";

      $connected = 1;
    });

    if ($connected) {
      $self->{current_read_server} = $server_index;  # Remember which server we connected to
      $self->{connected_read} = 1;
      dbg("bayes: connected to read server %d", $server_index);
      return 1;
    }

    if ($self->{timer}->timed_out()) {
      $error = "Connection timed out";
    } else {
      $error = $err || "Connection failed";
    }

    dbg("bayes: failed to connect to read server %d: %s", $server_index, $error);
    undef $self->{redis_read};

    $tried++;
  }

  die "bayes: Failed to connect to any read server: $error";
}

=head2 _connect_write

private instance (Boolean) _connect_write ()

Description:
Connects to the Redis write server. Since there's only one write server,
throws an exception if the connection fails.

=cut

sub _connect_write {
  my($self) = @_;

  return 1 if $self->{connected_write};

  if (!$self->{write_server}) {
    die "bayes: No Redis write server configured";
  }

  $self->_disconnect_write if $self->{connected_write};
  undef $self->{redis_write};  # just in case

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{opened_write_from_pid} = $$;
    my $db_id = $self->{db_id};
    my $pwd = $self->{password};

    $self->{redis_write} = Mail::SpamAssassin::Util::TinyRedis->new(
                     %{$self->{write_server}},
                     on_connect => sub { on_connect($_[0], $db_id, $pwd) });

    $self->{redis_write} or die "Error: $!";

    # Test connection with a simple command
    $self->{redis_write}->call('PING') eq 'PONG'
      or die "Failed to get PONG response";
  });

  if ($self->{timer}->timed_out()) {
    undef $self->{redis_write};
    die "bayes: Redis write connection timed out!";
  } elsif ($err) {
    undef $self->{redis_write};
    die "bayes: Redis write connection failed: $err";
  }

  $self->{connected_write} = 1;
  return 1;
}

=head2 _disconnect_read

private instance () _disconnect_read ()

Description:
Disconnects from the Redis read server.

=cut

sub _disconnect_read {
  my($self) = @_;
  local($@, $!);
  if ($self->{connected_read}) {
    dbg("bayes: Redis disconnect read connection");
    $self->{connected_read} = 0;
    $self->{redis_read}->disconnect if $self->{redis_read};
  }
  undef $self->{redis_read};
}

=head2 _disconnect_write

private instance () _disconnect_write ()

Description:
Disconnects from the Redis write server.

=cut

sub _disconnect_write {
  my($self) = @_;
  local($@, $!);
  if ($self->{connected_write}) {
    dbg("bayes: Redis disconnect write connection");
    $self->{connected_write} = 0;
    $self->{redis_write}->disconnect if $self->{redis_write};
  }
  undef $self->{redis_write};
}

=head2 _key

private instance (String) _key (String $key)

Description:
Prefixes a key with the configured key prefix for namespacing.

=cut

sub _key {
  my($self, $key) = @_;
  return $self->{key_prefix} . $key;
}

=head2 prefork_init

public instance (Boolean) prefork_init ();

Description:
This optional method is called in the parent process shortly before
forking off child processes.

=cut

sub prefork_init {
  my ($self) = @_;

  # Each child process must establish its own connection with a Redis server,
  # re-using a common forked socket leads to serious trouble (garbled data).
  #
  # Parent process may have established its connection during startup, but
  # it is no longer of any use by now, so we shut it down here in the master
  # process, letting a spawned child process re-establish it later.

  if ($self->{connected_read} || $self->{connected_write}) {
    dbg("bayes: prefork_init, closing sessions ".
        "with Redis servers in a parent process");
    $self->untie_db;
    $self->disconnect;
  }
}

=head2 spamd_child_init

public instance (Boolean) spamd_child_init ();

Description:
This optional method is called in a child process shortly after being spawned.

=cut

sub spamd_child_init {
  my ($self) = @_;

  # Each child process must establish its own connection with a Redis server,
  # re-using a common forked socket leads to serious trouble (garbled data).
  #
  # Just in case the parent master process did not call prefork_init() above,
  # we try to silently renounce the use of existing cloned connection here.
  # As the prefork_init plugin callback has only been introduced in
  # SpamAssassin 3.4.0, this situation can arrise in case of some third party
  # software (or a pre-3.4.0 version of spamd) is somehow using this plugin.
  # Better safe than sorry...

  if ($self->{connected_read} || $self->{connected_write}) {
    dbg("bayes: spamd_child_init, closing parent's sessions ".
        "to Redis servers in a child process");
    $self->untie_db;
    $self->disconnect;  # just drop it, don't shut down parent's session
  }
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection for read operations is properly
setup and working.

=cut

sub tie_db_readonly {
  my($self) = @_;

  $self->{is_writable} = 0;
  my $success;
  if ($self->{connected_read}) {
    $success = $self->{is_officially_open} = 1;
  } else {
    $success = $self->_open_db_readonly();
  }

  return $success;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connection for write operations is properly
setup and working. If necessary it will initialize the database so that they can
begin using the database immediately.

=cut

sub tie_db_writable {
  my($self) = @_;

  $self->{is_writable} = 0;
  my $success;
  if ($self->{connected_write}) {
    $success = $self->{is_officially_open} = 1;
  } else {
    $success = $self->_open_db_writable();
  }

  $self->{is_writable} = 1 if $success;

  return $success;
}

=head2 _open_db_readonly

private instance (Boolean) _open_db_readonly ()

Description:
This method ensures that the database connection for read operations is properly setup and
working.  It will initialize bayes variables so that they can begin using
the database immediately.

=cut

sub _open_db_readonly {
  my($self) = @_;

  dbg("bayes: _open_db_readonly(%s)",
      $self->{connected_read} ? 'already connected' : 'not yet connected');

  if ($self->{connected_read}) {
    $self->{is_officially_open} = 1;
    return 1;
  }

  $self->read_db_configs();

  # Try to connect to a read server
  eval {
    $self->_connect_read();
  };
  if ($@) {
    warn("bayes: failed to connect to any read server: $@");
    return 0;
  }

  $self->_check_server_info($self->{redis_read});

  $self->{db_version} = $self->{redis_read}->call('GET', $self->_key('v:DB_VERSION'));

  if (!$self->{db_version}) {
    warn("bayes: database not initialized");
    return 0;
  } else {
    dbg("bayes: found bayes db version %s", $self->{db_version});
    if ($self->{db_version} ne $self->DB_VERSION) {
      warn("bayes: bayes db version $self->{db_version} not supported, aborting\n");
      return 0;
    }
    my $token_format = $self->{redis_read}->call('GET', $self->_key('v:TOKEN_FORMAT')) || 0;
    if ($token_format < 2) {
      warn("bayes: bayes old token format $token_format not supported, ".
           "consider backup/restore or initialize a database\n");
      return 0;
    }
  }

  if ($self->{have_lua} && !defined $self->{multi_hmget_script}) {
    $self->_define_lua_scripts($self->{redis_read});
  }

  $self->{is_officially_open} = 1;

  return 1;
}

=head2 _open_db_writable

private instance (Boolean) _open_db_writable ()

Description:
This method ensures that the database connection for write operations is properly
setup and working. It will initialize the database if necessary.

=cut

sub _open_db_writable {
  my($self) = @_;

  dbg("bayes: _open_db_writable(%s)",
      $self->{connected_write} ? 'already connected' : 'not yet connected');

  if ($self->{connected_write}) {
    $self->{is_officially_open} = 1;
    return 1;
  }

  $self->read_db_configs();

  # Try to connect to the write server
  eval {
    $self->_connect_write();
  };
  if ($@) {
    warn("bayes: failed to connect to write server: $@");
    return 0;
  }

  $self->_check_server_info($self->{redis_write});

  $self->{db_version} = $self->{redis_write}->call('GET', $self->_key('v:DB_VERSION'));

  if (!$self->{db_version}) {
    $self->{db_version} = $self->DB_VERSION;
    my $ret = $self->{redis_write}->call('MSET',
                                   $self->_key('v:DB_VERSION'), $self->{db_version},
                                   $self->_key('v:NSPAM'), 0,
                                   $self->_key('v:NHAM'), 0,
                                   $self->_key('v:TOKEN_FORMAT'), 2 );
    unless ($ret) {
      warn("bayes: failed to initialize database");
      return 0;
    }
    dbg("bayes: initialized empty database, version $self->{db_version}");
  } else {
    dbg("bayes: found bayes db version %s", $self->{db_version});
    if ($self->{db_version} ne $self->DB_VERSION) {
      warn("bayes: bayes db version $self->{db_version} not supported, aborting\n");
      return 0;
    }
    my $token_format = $self->{redis_write}->call('GET', $self->_key('v:TOKEN_FORMAT')) || 0;
    if ($token_format < 2) {
      warn("bayes: bayes old token format $token_format not supported, ".
           "consider backup/restore or initialize a database\n");
      return 0;
    }
  }

  if ($self->{have_lua} && !defined $self->{multi_hmget_script}) {
    $self->_define_lua_scripts($self->{redis_write});
  }

  $self->{is_officially_open} = 1;

  return 1;
}

=head2 _check_server_info

private instance () _check_server_info ($redis)

Description:
Checks and stores Redis server information (version, Lua availability, etc.)

=cut

sub _check_server_info {
  my($self, $redis) = @_;

  if (!defined $self->{redis_server_version}) {
    my $info = $self->{info} = $redis->call("INFO");
    if (defined $info) {
      my $redis_mem; local $1;
      $self->{redis_server_version} =
                          $info =~ /^redis_version:\s*(.*?)\r?$/m ? $1 : '';
      $self->{have_lua} = $info =~ /^used_memory_lua:/m ? 1 : 0;
      $redis_mem = $1  if $info =~ /^used_memory:\s*(.*?)\r?$/m;
      dbg("bayes: redis server version %s, memory used %.1f MiB, Lua %s",
          $self->{redis_server_version}, $redis_mem/1024/1024,
          $self->{have_lua} ? 'is available' : 'is not available');
    }
  }
}

=head2 untie_db

public instance () untie_db ()

Description:
Closes any open db handles. You can safely call this at any time.

=cut

sub untie_db {
  my $self = shift;

  $self->{is_officially_open} = $self->{is_writable} = 0;
  return;
}

=head2 sync_due

public instance (Boolean) sync_due ()

Description:
This method determines if a database sync is currently required.

Unused for Redis implementation.

=cut

sub sync_due {
  return 0;
}

=head2 expiry_due

public instance (Boolean) expiry_due ()

Description:
This methods determines if an expire is due.

Unused for Redis implementation.

=cut

sub expiry_due {
  return 0;
}

=head2 seen_get

public instance (String) seen_get (string $msgid)

Description:
This method retrieves the stored value, if any, for C<$msgid>. The return
value is the stored string ('s' for spam and 'h' for ham) or undef if C<$msgid>
is not found.

=cut

sub seen_get {
  my($self, $msgid) = @_;

  return 0 unless $self->tie_db_readonly();
  return $self->{redis_read}->call('GET', $self->_key("s:$msgid"));
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>. C<$flag> is one
of two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my($self, $msgid, $flag) = @_;

  return 0 unless $self->tie_db_writable();
  my $r = $self->{redis_write};
  if ($self->{expire_seen}) {
    $r->call('SETEX', $self->_key("s:$msgid"), $self->{expire_seen}, $flag);
  } else {
    $r->call('SET',   $self->_key("s:$msgid"), $flag);
  }

  return 1;
}

=head2 seen_delete

public instance (Boolean) seen_delete (string $msgid)

Description:
This method removes C<$msgid> from the database.

=cut

sub seen_delete {
  my($self, $msgid) = @_;

  return 0 unless $self->tie_db_writable();
  $self->{redis_write}->call('DEL', $self->_key("s:$msgid"));
  return 1;
}

=head2 get_storage_variables

public instance (@) get_storage_variables ()

Description:
This method retrieves the various administrative variables used by
the Bayes process and database.

The values returned in the array are in the following order:

0: scan count base
1: number of spam
2: number of ham
3: number of tokens in db
4: last expire atime
5: oldest token in db atime
6: db version value
7: last journal sync
8: last atime delta
9: last expire reduction count
10: newest token in db atime

Only 1,2,6 are used with Redis, others return zero always.

=cut

sub get_storage_variables {
  my($self, @varnames) = @_;

  return 0 unless $self->tie_db_readonly();

  @varnames = qw{LAST_JOURNAL_SYNC NSPAM NHAM NTOKENS LAST_EXPIRE
                 OLDEST_TOKEN_AGE DB_VERSION LAST_JOURNAL_SYNC
                 LAST_ATIME_DELTA LAST_EXPIRE_REDUCE NEWEST_TOKEN_AGE
                 TOKEN_FORMAT}  if !@varnames;
  my $values = $self->{redis_read}->call('MGET', map($self->_key('v:'.$_), @varnames));
  return if !$values;
  return map(defined $_ ? $_ : 0, @$values);
}

=head2 get_running_expire_tok

public instance (String $time) get_running_expire_tok ()

Description:
This method determines if an expire is currently running and returns
the last time set.

=cut

sub get_running_expire_tok {
  return 0;
}

=head2 set_running_expire_tok

public instance (String $time) set_running_expire_tok ()

Description:
This method sets the time that an expire starts running.

=cut

sub set_running_expire_tok {
  return 0;
}

=head2 remove_running_expire_tok

public instance (Boolean) remove_running_expire_tok ()

Description:
This method removes the row in the database that indicates that
and expire is currently running.

=cut

sub remove_running_expire_tok {
  return 1;
}

=head2 tok_get

public instance (Integer, Integer, Integer) tok_get (String $token)

Description:
This method retrieves a specified token (C<$token>) from the database
and returns its spam_count, ham_count and last access time.

=cut

sub tok_get {
  my($self, $token) = @_;

  my $array = $self->tok_get_all($token);
  return if !$array || !@$array;
  return (@{$array->[0]})[1,2,3];
}

=head2 tok_get_all

public instance (\@) tok_get (@ $tokens)

Description:
This method retrieves the specified tokens (C<$tokens>) from storage and
returns a ref to arrays spam count, ham count and last access time.

=cut

sub tok_get_all {
  my $self = shift;
# my @keys = @_;  # avoid copying strings unnecessarily

  return 0 unless $self->tie_db_readonly();

  my @values;
  my $r = $self->{redis_read};

  if (! $self->{have_lua} ) {
    for my $token (@_) {
      $r->b_call('HMGET', $self->_key('w:'.$token), 's', 'h');
    }
    my $results = $r->b_results;

    if (@$results != @_) {
      $self->_disconnect_read;
      die sprintf("bayes: tok_get_all got %d entries, expected %d\n",
                  scalar @$results, scalar @_);
    }
    for my $j (0 .. $#$results) {
      my($s,$h) = @{$results->[$j]};
      push(@values, [$_[$j], ($s||0)+0, ($h||0)+0, 0])  if $s || $h;
    }
  } else {  # have Lua
    # no need for cryptographical strength, just checking for protocol errors
    my $nonce = sprintf("%06x", rand(0xffffff));

    my $result;
    eval {
      $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                         scalar @_, map($self->_key('w:'.$_), @_), $nonce);
      1;
    } or do {  # Lua script probably not cached, define again and re-try
      if ($@ !~ /^NOSCRIPT/) {
        $self->_disconnect_read;
        die "bayes: Redis LUA error: $@\n";
      }
      $self->_define_lua_scripts($r);
      $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                         scalar @_, map($self->_key('w:'.$_), @_), $nonce);
    };
    my @items = split(' ', $result);
    my $r_nonce = pop(@items);
    if ($r_nonce ne $nonce) {
      # redis protocol error?
      $self->_disconnect_read;
      die sprintf("bayes: tok_get_all nonce mismatch, expected %s, got %s\n",
                  $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
    } elsif (@items != @_) {
      $self->_disconnect_read;
      die sprintf("bayes: tok_get_all got %d entries, expected %d\n",
                  scalar @items, scalar @_);
    } else {
      for my $j (0 .. $#items) {
        my($s,$h) = split(m{/}, $items[$j], 2);
        push(@values, [$_[$j], ($s||0)+0, ($h||0)+0, 0])  if $s || $h;
      }
    }
  }

  dbg("bayes: tok_get_all found %d tokens out of %d",
      scalar @values, scalar @_);

  return \@values;
}

=head2 tok_count_change

public instance (Boolean) tok_count_change (
  Integer $dspam, Integer $dham, String $token, String $newatime)

Description:
This method takes a C<$spam_count> and C<$ham_count> and adds it to
C<$tok> along with updating C<$tok>s atime with C<$atime>.

=cut

sub tok_count_change {
  my($self, $dspam, $dham, $token, $newatime) = @_;

  $self->multi_tok_count_change($dspam, $dham, {$token => 1}, $newatime);
}

=head2 multi_tok_count_change

public instance (Boolean) multi_tok_count_change (
  Integer $dspam, Integer $dham, \% $tokens, String $newatime)

Description:
This method takes a C<$dspam> and C<$dham> and adds it to all of the
tokens in the C<$tokens> hash ref along with updating each token's
atime with C<$atime>.

=cut

sub multi_tok_count_change {
  my($self, $dspam, $dham, $tokens, $newatime) = @_;

  return 0 unless $self->tie_db_writable();

  # turn undef or an empty string into a 0
  $dspam ||= 0;
  $dham  ||= 0;
  # the increment must be an integer, otherwise redis returns an error

  dbg("bayes: multi_tok_count_change learning %d spam, %d ham",
      $dspam, $dham);

  my $ttl = $self->{expire_token};  # time-to-live, in seconds
  my $r = $self->{redis_write};

  if ($dspam > 0 || $dham > 0) {  # learning
    while (my($token,$v) = each(%$tokens)) {
      my $key = $self->_key('w:'.$token);
      $r->b_call('HINCRBY', $key, 's', int $dspam) if $dspam > 0;
      $r->b_call('HINCRBY', $key, 'h', int $dham)  if $dham  > 0;
      $r->b_call('EXPIRE',  $key, $ttl)  if $ttl;
    }
    $r->b_results;  # collect response, ignoring results
  }

  if ($dspam < 0 || $dham < 0) {  # unlearning - rare, not as efficient
    while (my($token,$v) = each(%$tokens)) {
      my $key = $self->_key('w:'.$token);
      if ($dspam < 0) {
        my $result = $r->call('HINCRBY', $key, 's', int $dspam);
        if (!$result || $result <= 0) {
          $r->call('HDEL',   $key, 's');
        } elsif ($ttl) {
          $r->call('EXPIRE', $key, $ttl);
        }
      }
      if ($dham < 0) {
        my $result = $r->call('HINCRBY', $key, 'h', int $dham);
        if (!$result || $result <= 0) {
          $r->call('HDEL',   $key, 'h');
        } elsif ($ttl) {
          $r->call('EXPIRE', $key, $ttl);
        }
      }
    }
  }

  return 1;
}

=head2 nspam_nham_get

public instance ($spam_count, $ham_count) nspam_nham_get ()

Description:
This method retrieves the total number of spam and the total number of
ham learned.

=cut

sub nspam_nham_get {
  my($self) = @_;

  return 0 unless $self->tie_db_readonly();
  my @vars = $self->get_storage_variables('NSPAM', 'NHAM');
  dbg("bayes: nspam_nham_get nspam=%s, nham=%s", @vars);
  @vars;
}

=head2 nspam_nham_change

public instance (Boolean) nspam_nham_change (Integer $num_spam,
                                             Integer $num_ham)

Description:
This method updates the number of spam and the number of ham in the database.

=cut

sub nspam_nham_change {
  my($self, $ds, $dh) = @_;

  return 1 unless $ds || $dh;
  return 0 unless $self->tie_db_writable();

  my $r = $self->{redis_write};

  my $err = $self->{timer}->run_and_catch(sub {
    $r->b_call('INCRBY', $self->_key("v:NSPAM"), $ds) if $ds;
    $r->b_call('INCRBY', $self->_key("v:NHAM"),  $dh) if $dh;
    $r->b_results;  # collect response, ignoring results
  });

  if ($self->{timer}->timed_out()) {
    $self->_disconnect_write;
    die("bayes: Redis connection timed out!");
  }
  elsif ($err) {
    $self->_disconnect_write;
    die("bayes: failed to increment nspam $ds nham $dh: $err");
  }

  return 1;
}

=head2 tok_touch

public instance (Boolean) tok_touch (String $token,
                                     String $atime)

Description:
This method updates the given tokens (C<$token>) atime.

The assumption is that the token already exists in the database.

We will never update to an older atime

=cut

sub tok_touch {
  my($self, $token, $atime) = @_;

  return $self->tok_touch_all([$token], $atime);
}

=head2 tok_touch_all

public instance (Boolean) tok_touch (\@ $tokens
                                     String $atime)

Description:
This method does a mass update of the given list of tokens C<$tokens>,
if the existing token atime is < C<$atime>.

=cut

sub tok_touch_all {
  my($self, $tokens, $newatime) = @_;

  return 0 unless $self->tie_db_writable();

  my $ttl = $self->{expire_token};  # time-to-live, in seconds
  return 1  unless $ttl && $tokens && @$tokens;

  dbg("bayes: tok_touch_all setting expire to %s on %d tokens",
      $ttl, scalar @$tokens);

  my $r = $self->{redis_write};

  # Benchmarks for a 'with-Lua' vs. a 'batched non-Lua' case show same speed,
  # so for simplicity we only kept a batched non-Lua code. Note that this
  # only applies to our own implementation of the Redis client protocol
  # which offers efficient command batching (pipelining) - with the Redis
  # CPAN module the batched case would be worse by about 33% on the average.

  # We just refresh TTL on all
  $r->b_call('EXPIRE', $self->_key('w:'.$_), $ttl) for @$tokens;
  $r->b_results;  # collect response, ignoring results

  return 1;
}

=head2 cleanup

public instance (Boolean) cleanup ()

Description:
This method performs any cleanup necessary before moving onto the next
operation.

=cut

sub cleanup {
  return 1;
}

=head2 get_magic_re

public instance (String) get_magic_re ()

Description:
This method returns a regexp which indicates a magic token.

=cut

use constant get_magic_re => undef;

=head2 sync

public instance (Boolean) sync (\% $opts)

Description:
This method performs a sync of the database

=cut

sub sync {
  return 1;
}

=head2 perform_upgrade

public instance (Boolean) perform_upgrade (\% $opts);

Description:
Performs an upgrade of the database from one version to another, not
currently used in this implementation.

=cut

sub perform_upgrade {
  return 1;
}

=head2 clear_database

public instance (Boolean) clear_database ()

Description:
This method deletes all records for a particular user.

Callers should be aware that any errors returned by this method
could causes the database to be inconsistent for the given user.

=cut

sub clear_database {
  my($self) = @_;

  return 0 unless $self->tie_db_writable();

  # We need to flush all keys and reinit the database
  my $r = $self->{redis_write};
  $r->call('FLUSHDB');

  my $keys = $r->call('KEYS', '*');
  my $count = scalar @$keys;

  # Initialize the database
  $self->{db_version} = $self->DB_VERSION;
  my $ret = $r->call('MSET',
                     $self->_key('v:DB_VERSION'), $self->{db_version},
                     $self->_key('v:NSPAM'), 0,
                     $self->_key('v:NHAM'), 0,
                     $self->_key('v:TOKEN_FORMAT'), 2 );
  unless ($ret) {
    warn("bayes: failed to initialize database");
    return 0;
  }

  dbg("bayes: database cleared and reinitialized, version $self->{db_version}");

  return 0 if ($count != 0);
  return 1;
}

=head2 dump_db_toks

public instance () dump_db_toks (String $template, String $regex, Array @vars)

Description:
This method loops over all tokens, computing the probability for the token
and then printing it out according to the passed in token.

=cut

sub dump_db_toks {
  my ($self, $template, $regex, @vars) = @_;

  return 0 unless $self->tie_db_readonly;
  my $r = $self->{redis_read};

  my $atime = time;  # fake

  # let's get past this terrible command as fast as possible
  # (ignoring $regex which makes no sense with SHA digests)
  my $keys = $r->call('KEYS', $self->_key('w:*'));
  dbg("bayes: fetched %d token keys", scalar @$keys);

  # process tokens in chunks of 1000
  for (my $i = 0; $i <= $#$keys; $i += 1000) {
    my $end = $i + 999 >= $#$keys ? $#$keys : $i + 999;

    my @tokensdata;
    if (! $self->{have_lua}) {  # no Lua, 3-times slower

      for (my $j = $i; $j <= $end; $j++) {
        $r->b_call('HMGET', $keys->[$j], 's', 'h');
      }
      my $j = $i;
      my $itemslist_ref = $r->b_results;
      foreach my $item ( @$itemslist_ref ) {
        my($s,$h) = @$item;
        # Strip key prefix for the token
        my $token = $keys->[$j];
        $token =~ s/$self->{key_prefix_tok_regex}//;
        push(@tokensdata, [ $token, ($s||0)+0, ($h||0)+0 ])  if $s || $h;
        $j++;
      }

    } else {  # have_lua

      my $nonce = sprintf("%06x", rand(0xffffff));
      my @tokens = @{$keys}[$i .. $end];
      my $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                            scalar @tokens, @tokens, $nonce);
      my @items = split(' ', $result);
      my $r_nonce = pop(@items);
      if (!defined $r_nonce) {
        $self->_disconnect_read;
        die "bayes: dump_db_toks received no results\n";
      } elsif ($r_nonce ne $nonce) {
        # redis protocol error?
        $self->_disconnect_read;
        die sprintf("bayes: dump_db_toks nonce mismatch, ".
                    "expected %s, got %s\n",
                    $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
      } elsif (@items != @tokens) {
        $self->_disconnect_read;
        die sprintf("bayes: dump_db_toks got %d entries, expected %d\n",
                       scalar @items, scalar @tokens);
      }

      # Strip key prefix for each token
      for (my $j = 0; $j < @tokens; $j++) {
        my($s,$h) = split(m{/}, $items[$j], 2);
        my $token = $tokens[$j];
        $token =~ s/$self->{key_prefix_tok_regex}//;
        push(@tokensdata, [ $token, ($s||0)+0, ($h||0)+0 ])  if $s || $h;
      }
    }

    my $probabilities_ref =
      $self->{bayes}->_compute_prob_for_all_tokens(\@tokensdata,
                                                   $vars[1], $vars[2]);
    foreach my $tokendata (@tokensdata) {
      my $prob = shift(@$probabilities_ref);
      my($token, $s, $h) = @$tokendata;
      next if !$s && !$h;
      $prob = 0.5  if !defined $prob;
      my $encoded = unpack("H*", $token);
      printf($template, $prob, $s, $h, $atime, $encoded)
        or die "Error writing tokens: $!";
    }
  }
  dbg("bayes: written token keys");

  $self->untie_db();

  return;
}

=head2 backup_database

public instance (Boolean) backup_database ()

Description:
This method will dump the users database in a machine readable format.

=cut

sub backup_database {
  my($self) = @_;

  return 0 unless $self->tie_db_readonly;
  my $r = $self->{redis_read};

  my $atime = time;  # fake
  my @vars = $self->get_storage_variables(qw(DB_VERSION NSPAM NHAM));
  print "v\t$vars[0]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  # let's get past this terrible command as fast as possible
  my $keys = $r->call('KEYS', $self->_key('w:*'));
  dbg("bayes: fetched %d token keys", scalar @$keys);

  # process tokens in chunks of 1000
  for (my $i = 0; $i <= $#$keys; $i += 1000) {
    my $end = $i + 999 >= $#$keys ? $#$keys : $i + 999;

    if (! $self->{have_lua}) {  # no Lua, slower

      for (my $j = $i; $j <= $end; $j++) {
        $r->b_call('HMGET', $keys->[$j], 's', 'h');
      }
      my $j = $i;
      my $itemslist_ref = $r->b_results;
      foreach my $item ( @$itemslist_ref ) {
        my $token = $keys->[$j++];
        $token =~ s/$self->{key_prefix_tok_regex}//;
        my($s,$h) = @$item;
        printf("t\t%d\t%d\t%s\t%s\n",
               $s||0, $h||0, $atime, unpack("H*", $token))  if $s || $h;
      }

    } else {  # have_lua

      my $nonce = sprintf("%06x", rand(0xffffff));
      my @tokens = @{$keys}[$i .. $end];
      my $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                            scalar @tokens, @tokens, $nonce);
      my @items = split(' ', $result);
      my $r_nonce = pop(@items);
      if (!defined $r_nonce) {
        $self->_disconnect_read;
        die "bayes: backup_database received no results\n";
      } elsif ($r_nonce ne $nonce) {
        # redis protocol error?
        $self->_disconnect_read;
        die sprintf("bayes: backup_database nonce mismatch, ".
                    "expected %s, got %s\n",
                    $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
      } elsif (@items != @tokens) {
        $self->_disconnect_read;
        die sprintf("bayes: backup_database got %d entries, expected %d\n",
                       scalar @items, scalar @tokens);
      }

      for (my $j = 0; $j < @tokens; $j++) {
        my $token = $tokens[$j];
        $token =~ s/$self->{key_prefix_tok_regex}//;
        my($s,$h) = split(m{/}, $items[$j], 2);
        next if !$s && !$h;
        printf("t\t%d\t%d\t%s\t%s\n", $s||0, $h||0, $atime, unpack("H*", $token));
      }
    }
  }
  dbg("bayes: written token keys");

  $keys = $r->call('KEYS', $self->_key('s:*'));
  dbg("bayes: fetched %d seen keys", scalar @$keys);

  for (my $i = 0; $i <= $#$keys; $i += 1000) {
    my $end = $i + 999 >= $#$keys ? $#$keys : $i + 999;
    my @t = @{$keys}[$i .. $end];
    my $v = $r->call('MGET', @t);
    for (my $i = 0; $i < @$v; $i++) {
      next unless defined $v->[$i];
      my $msgid = $t[$i];
      $msgid =~ s/$self->{key_prefix_seen_regex}//;
      printf("s\t%s\t%s\n", $v->[$i], $msgid);
    }
  }
  dbg("bayes: written seen keys");

  $self->untie_db();

  return 1;
}

=head2 restore_database

public instance (Boolean) restore_database (String $filename, Boolean $showdots)

Description:
This method restores a database from the given filename, C<$filename>.

Callers should be aware that any errors returned by this method
could causes the database to be inconsistent for the given user.

=cut

sub restore_database {
  my ($self, $filename, $showdots) = @_;

  local *DUMPFILE;
  if (!open(DUMPFILE, '<', $filename)) {
    warn("bayes: unable to open backup file $filename: $!");
    return 0;
  }

  unless ($self->clear_database()) {
    return 0;
  }

  return 0 unless $self->tie_db_writable;
  my $r = $self->{redis_write};

  my $token_count = 0;
  my $db_version;
  my $num_spam = 0;
  my $num_ham = 0;
  my $line_count = 0;

  my $line = <DUMPFILE>;
  defined $line  or die "Error reading dump file: $!";
  $line_count++;
  # We require the database version line to be the first in the file so we can
  # figure out how to properly deal with the file.  If it is not the first
  # line then fail
  if ($line =~ m/^v\s+(\d+)\s+db_version/) {
    $db_version = $1;
  } else {
    warn("bayes: database version must be the first line in the backup file, correct and re-run");
    return 0;
  }

  unless ($db_version == 2 || $db_version == 3) {
    warn("bayes: database version $db_version is unsupported, must be version 2 or 3\n");
    return 0;
  }

  my $curtime = time;
  my $q_cnt = 0;
  my $token_ttl = $self->{expire_token};  # possibly undefined
  my $seen_ttl  = $self->{expire_seen};   # possibly undefined

  for ($!=0; defined($line=<DUMPFILE>); $!=0) {
    chomp($line);
    $line_count++;

    if ($showdots && $line_count % 1000 == 0) {
      print STDERR "." if $showdots;
    }

    if ($line =~ /^t\s+/) { # token line
      my @parsed_line = split(/\s+/, $line, 5);
      my $spam_count = $parsed_line[1] + 0;
      my $ham_count = $parsed_line[2] + 0;
      my $token = $parsed_line[4];

      $spam_count = 0 if $spam_count < 0;
      $ham_count = 0 if $ham_count < 0;

      next if !$spam_count && !$ham_count;

      if ($db_version < 3) {
        # versions < 3 use plain text tokens, so we need to convert to hash
        $token = substr(sha1($token), -5);
      } else {
        # turn unpacked binary token back into binary value
        $token = pack("H*",$token);
      }
      my $key = $self->_key('w:'.$token);
      $r->b_call('HINCRBY', $key, 's', int $spam_count) if $spam_count > 0;
      $r->b_call('HINCRBY', $key, 'h', int $ham_count)  if $ham_count  > 0;

      if ($token_ttl) {
        # by introducing some randomness (ttl times a factor of 0.7 .. 1.7),
        # we avoid auto-expiration of many tokens all at once,
        # introducing an unnecessary load spike on a redis server
        $r->b_call('EXPIRE', $key, int($token_ttl * (rand()+0.7)));
      }

      # collect response every now and then, ignoring results
      $r->b_results  if ++$q_cnt % 1000 == 0;

      $token_count++;

    } elsif ($line =~ /^s\s+/) { # seen line
      my @parsed_line = split(/\s+/, $line, 3);
      my $flag  = $parsed_line[1];
      my $msgid = $parsed_line[2];

      unless ($flag eq 'h' || $flag eq 's') {
        dbg("bayes: unknown seen flag ($flag) for line: $line, skipping");
        next;
      }

      unless ($msgid) {
        dbg("bayes: blank msgid for line: $line, skipping");
        next;
      }

      if (!$seen_ttl) {
        $r->b_call('SET', $self->_key("s:$msgid"), $flag);
      } else {
        # by introducing some randomness (ttl times a factor of 0.7 .. 1.7),
        # we avoid auto-expiration of many 'seen' entries all at once,
        # introducing an unnecessary load spike on a redis server
        $r->b_call('SETEX', $self->_key("s:$msgid"), int($seen_ttl * (rand()+0.7)), $flag);
      }

      # collect response every now and then, ignoring results
      $r->b_results  if ++$q_cnt % 1000 == 0;

    } elsif ($line =~ /^v\s+/) {  # variable line
      my @parsed_line = split(/\s+/, $line, 3);
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
        $num_spam = $value;
      } elsif ($parsed_line[2] eq 'num_nonspam') {
        $num_ham = $value;
      } else {
        dbg("bayes: restore_database: skipping unknown line: $line");
      }

    } else {
      dbg("bayes: skipping unknown line: $line");
      next;
    }
  }

  $r->b_results;  # collect any remaining response, ignoring results

  defined $line || $!==0  or
    $!==EBADF ? dbg("bayes: error reading dump file: $!")
      : die "error reading dump file: $!";
  close(DUMPFILE) or die "Can't close dump file: $!";

  print STDERR "\n" if $showdots;

  if ($num_spam <= 0 && $num_ham <= 0) {
    warn("bayes: no num_spam/num_ham found, aborting");
    return 0;
  }
  else {
    $self->nspam_nham_change($num_spam, $num_ham);
  }

  dbg("bayes: parsed $line_count lines");
  dbg("bayes: created database with $token_count tokens ".
      "based on $num_spam spam messages and $num_ham ham messages");

  $self->untie_db();

  return 1;
}

=head2 db_readable

public instance (Boolean) db_readable()

Description:
This method returns a boolean value indicating if the database is in a
readable state.

=cut

sub db_readable {
  my($self) = @_;

  return $self->{is_officially_open};
}

=head2 db_writable

public instance (Boolean) db_writable()

Description:
This method returns a boolean value indicating if the database is in a
writable state.

=cut

sub db_writable {
  my($self) = @_;

  return $self->{is_officially_open} && $self->{is_writable};
}

=head2 _define_lua_scripts

private instance () _define_lua_scripts ($redis)

Description:
Defines Lua scripts used for efficient Redis operations.

=cut

sub _define_lua_scripts {
  my ($self, $redis) = @_;
  dbg("bayes: defining Lua scripts");

  $self->{multi_hmget_script} = $redis->call('SCRIPT', 'LOAD', <<'END');
    local rcall = redis.call
    local nonce = ARGV[1]
    local KEYS = KEYS
    local r = {}
    for j = 1, #KEYS do
      local sh = rcall("HMGET", KEYS[j], "s", "h")
      -- returns counts as a list of spam/ham pairs, zeroes may be omitted
      local s, h = sh[1] or "0", sh[2] or "0"
      local pair
      if h == "0" then
        pair = s  -- just a spam field, possibly zero; a ham field omitted
      elseif s == "0" then
        pair = "/" .. h  -- just a ham field, zero in a spam field suppressed
      else
        pair = s .. "/" .. h
      end
      r[#r+1] = pair
    end
    r[#r+1] = nonce
    -- return counts as a single string, avoids overhead of multiresult parsing
    return table.concat(r," ")
END
  1;
}

1;
