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

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implementes a Redis based bayesian storage module.

Apache SpamAssassin v3.4.0 introduces support for keeping
a Bayes database on a Redis server, either running locally, or accessed
over network. Similar to SQL backends, the database may be concurrently
used by several hosts running SpamAssassin.

The current implementation only supports a global Bayes database, i.e.
per-recipient sub-databases are not supported. The Redis 2.6.* server
supports access over IPv4 or over a Unix socket, starting with Redis 
version 2.8.0 also IPv6 is supported. Bear in mind that Redis server only 
offers limited access controls, so it is advisable to let the Redis server 
bind to a loopback interface only, or to use other mechanisms to limit 
access, such as local firewall rules.

The Redis backend for Bayes can put a Lua scripting support in a Redis
server to good use, improving performance. The Lua support is available
in Redis server since version 2.6.  In absence of a Lua support, the Redis
backend uses batched (pipelined) traditional Redis commands, so it should
work with a Redis server version 2.4 (untested), although this is not
recommended for busy sites.

Expiration of token and 'seen' message id entries is left to the Redis
server. There is no provision for manually expiring a database, so it is
highly recommended to leave the setting bayes_auto_expire to its default
value 1 (i.e. enabled).

Example configuration:

  bayes_store_module  Mail::SpamAssassin::BayesStore::Redis
  bayes_sql_dsn       server=127.0.0.1:6379;password=foo;database=2
  bayes_token_ttl 21d
  bayes_seen_ttl   8d
  bayes_auto_expire 1

A redis server with a Lua support (2.6 or higher) is recommended
for performance reasons.

The bayes_sql_dsn config variable has been hijacked for our purposes:

  bayes_sql_dsn

    Optional config parameters affecting a connection to a redis server.

    This is a semicolon-separated list of option=value pairs, where an option
    can be: server, password, database. Unrecognized options are silently
    ignored.

    The 'server' option specifies a socket on which a redis server is
    listening. It can be an absolute path of a Unix socket, or a host:port
    pair, where a host can be an IPv4 or IPv6 address or a host name.
    An IPv6 address must be enclosed in brackets, e.g. [::1]:6379
    (IPv6 support in a redis server is available since version 2.8.0).
    A default is to connect to an INET socket at 127.0.0.1, port 6379.

    The value of a 'password' option is sent in an AUTH command to a redis
    server on connecting if a server requests authentication. A password is
    sent in plain text and a redis server only offers an optional rudimentary
    authentication. To limit access to a redis server use its 'bind' option
    to bind to a specific interface (typically to a loopback interface),
    or use a host-based firewall.

    The value of a 'database' option can be an non-negative (small) integer,
    which is passed to a redis server with a SELECT command on connecting,
    and chooses a sub-database index. A default database index is 0.

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
but only if bayes_auto_expire is true (which is a default).  This is
why --force-expire etc does nothing, and token counts and atime values
are shown as zero in statistics.

LIMITATIONS: Only global bayes storage is implemented, per-user bayes is
not currently available. Dumping (sa-learn --backup, or --dump) of a huge
database may not be possible if all keys do not fit into process memory.

=cut

package Mail::SpamAssassin::BayesStore::Redis;

use strict;
use warnings;
use bytes;
use re 'taint';
use Errno qw(EBADF);
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Timeout;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Util::TinyRedis;

use vars qw( @ISA $VERSION );

BEGIN {
  $VERSION = 0.09;
  @ISA = qw( Mail::SpamAssassin::BayesStore );
}

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::Redis) new (Mail::Spamassassin::Plugin::Bayes $bayes)

Description:
This methods creates a new instance of the Mail::SpamAssassin::BayesStore::Redis
object.  It expects to be passed an instance of the Mail::SpamAssassin:Bayes
object which is passed into the Mail::SpamAssassin::BayesStore parent object.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new(@_);

  my $bconf = $self->{bayes}->{conf};

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
      push @{$self->{redis_conf}}, $a => $b eq 'undef' ?
        undef : untaint_var($b);
    }
  }

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
  $self->{connected} = 0;
  $self->{is_officially_open} = 0;
  $self->{is_writable} = 0;

  $self->{timer} = Mail::SpamAssassin::Timeout->new({
    secs => $self->{conf}->{redis_timeout} || 10
  });

  return $self;
}

sub disconnect {
  my($self) = @_;
  local($@, $!);
  if ($self->{connected}) {
    dbg("bayes: Redis disconnect");
    $self->{connected} = 0;
    $self->{redis}->disconnect;
  }
  undef $self->{redis};
}

sub DESTROY {
  my($self) = @_;
  local($@, $!, $_);
  dbg("bayes: Redis destroy");
  $self->{connected} = 0; undef $self->{redis};
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

sub connect {
  my($self) = @_;

  $self->disconnect if $self->{connected};
  undef $self->{redis};  # just in case

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{opened_from_pid} = $$;
    # Bug 7034: avoid a closure passing $self to $self->{redis}->{on_connect},
    # otherwise a circular reference prevents object destruction!
    my $db_id = $self->{db_id};
    my $pwd = $self->{password};
    # will keep a persistent session open to a redis server
    $self->{redis} = Mail::SpamAssassin::Util::TinyRedis->new(
                       @{$self->{redis_conf}},
                       on_connect => sub { on_connect($_[0], $db_id, $pwd) });
    $self->{redis} or die "Error: $!";
  });
  if ($self->{timer}->timed_out()) {
    undef $self->{redis};
    die "bayes: Redis connection timed out!";
  } elsif ($err) {
    undef $self->{redis};
    die "bayes: Redis failed: $err";
  }
  $self->{connected} = 1;
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

  if ($self->{connected}) {
    dbg("bayes: prefork_init, closing a session ".
        "with a Redis server in a parent process");
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

  if ($self->{connected}) {
    dbg("bayes: spamd_child_init, closing a parent's session ".
        "to a Redis server in a child process");
    $self->untie_db;
    $self->disconnect;  # just drop it, don't shut down parent's session
  }
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection is properly setup and working.

=cut

sub tie_db_readonly {
  my($self) = @_;

  $self->{is_writable} = 0;
  my $success;
  if ($self->{connected}) {
    $success = $self->{is_officially_open} = 1;
  } else {
    $success = $self->_open_db();
  }

  return $success;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connection is properly setup and
working. If necessary it will initialize the database so that they can
begin using the database immediately.

=cut

sub tie_db_writable {
  my($self) = @_;

  $self->{is_writable} = 0;
  my $success;
  if ($self->{connected}) {
    $success = $self->{is_officially_open} = 1;
  } else {
    $success = $self->_open_db();
  }

  $self->{is_writable} = 1 if $success;

  return $success;
}

=head2 _open_db

private instance (Boolean) _open_db (Boolean $writable)

Description:
This method ensures that the database connection is properly setup and
working.  It will initialize bayes variables so that they can begin using
the database immediately.

=cut

sub _open_db {
  my($self) = @_;

  dbg("bayes: _open_db(%s)",
      $self->{connected} ? 'already connected' : 'not yet connected');

  if ($self->{connected}) {
    $self->{is_officially_open} = 1;
    return 1;
  }

  $self->read_db_configs();
  $self->connect;

  if (!defined $self->{redis_server_version}) {
    my $info = $self->{info} = $self->{redis}->call("INFO");
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

  $self->{db_version} = $self->{redis}->call('GET', 'v:DB_VERSION');

  if (!$self->{db_version}) {
    $self->{db_version} = $self->DB_VERSION;
    my $ret = $self->{redis}->call('MSET',
                                   'v:DB_VERSION', $self->{db_version},
                                   'v:NSPAM', 0,
                                   'v:NHAM', 0,
                                   'v:TOKEN_FORMAT', 2 );
    unless ($ret) {
      warn("bayes: failed to initialize database");
      return 0;
    }
    dbg("bayes: initialized empty database, version $self->{db_version}");
  }
  else {
    dbg("bayes: found bayes db version %s", $self->{db_version});
    if ($self->{db_version} ne $self->DB_VERSION) {
      warn("bayes: bayes db version $self->{db_version} not supported, aborting\n");
      return 0;
    }
    my $token_format = $self->{redis}->call('GET', 'v:TOKEN_FORMAT') || 0;
    if ($token_format < 2) {
      warn("bayes: bayes old token format $token_format not supported, ".
           "consider backup/restore or initialize a database\n");
      return 0;
    }
  }

  if ($self->{have_lua} && !defined $self->{multi_hmget_script}) {
    $self->_define_lua_scripts;
  }

  $self->{is_officially_open} = 1;

  return 1;
}

=head2 untie_db

public instance () untie_db ()

Description:
Closes any open db handles.  You can safely call this at any time.

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
This method retrieves the stored value, if any, for C<$msgid>.  The return
value is the stored string ('s' for spam and 'h' for ham) or undef if C<$msgid>
is not found.

=cut

sub seen_get {
  my($self, $msgid) = @_;

  return $self->{redis}->call('GET', "s:$msgid");
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is one
of two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my($self, $msgid, $flag) = @_;

  my $r = $self->{redis};
  if ($self->{expire_seen}) {
    $r->call('SETEX', "s:$msgid", $self->{expire_seen}, $flag);
  } else {
    $r->call('SET',   "s:$msgid", $flag);
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

  $self->{redis}->call('DEL', "s:$msgid");
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

  @varnames = qw{LAST_JOURNAL_SYNC NSPAM NHAM NTOKENS LAST_EXPIRE
                 OLDEST_TOKEN_AGE DB_VERSION LAST_JOURNAL_SYNC
                 LAST_ATIME_DELTA LAST_EXPIRE_REDUCE NEWEST_TOKEN_AGE
                 TOKEN_FORMAT}  if !@varnames;
  my $values = $self->{redis}->call('MGET', map('v:'.$_, @varnames));
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
This method retrieves a specificed token (C<$token>) from the database
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

  my @values;
  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  if (! $self->{have_lua} ) {

    $r->b_call('HMGET', 'w:'.$_, 's', 'h')  for @_;
    my $results = $r->b_results;

    if (@$results != @_) {
      $self->disconnect;
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
                         scalar @_, map('w:'.$_, @_), $nonce);
      1;
    } or do {  # Lua script probably not cached, define again and re-try
      if ($@ !~ /^NOSCRIPT/) {
        $self->disconnect;
        die "bayes: Redis LUA error: $@\n";
      }
      $self->_define_lua_scripts;
      $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                         scalar @_, map('w:'.$_, @_), $nonce);
    };
    my @items = split(' ', $result);
    my $r_nonce = pop(@items);
    if ($r_nonce ne $nonce) {
      # redis protocol error?
      $self->disconnect;
      die sprintf("bayes: tok_get_all nonce mismatch, expected %s, got %s\n",
                  $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
    } elsif (@items != @_) {
      $self->disconnect;
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

  # turn undef or an empty string into a 0
  $dspam ||= 0;
  $dham  ||= 0;
  # the increment must be an integer, otherwise redis returns an error

  dbg("bayes: multi_tok_count_change learning %d spam, %d ham",
      $dspam, $dham);

  my $ttl = $self->{expire_token};  # time-to-live, in seconds

  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  if ($dspam > 0 || $dham > 0) {  # learning
    while (my($token,$v) = each(%$tokens)) {
      my $key = 'w:'.$token;
      $r->b_call('HINCRBY', $key, 's', int $dspam) if $dspam > 0;
      $r->b_call('HINCRBY', $key, 'h', int $dham)  if $dham  > 0;
      $r->b_call('EXPIRE',  $key, $ttl)  if $ttl;
    }
    $r->b_results;  # collect response, ignoring results
  }

  if ($dspam < 0 || $dham < 0) {  # unlearning - rare, not as efficient
    while (my($token,$v) = each(%$tokens)) {
      my $key = 'w:'.$token;
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

  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  my $err = $self->{timer}->run_and_catch(sub {
    $r->b_call('INCRBY', "v:NSPAM", $ds) if $ds;
    $r->b_call('INCRBY', "v:NHAM",  $dh) if $dh;
    $r->b_results;  # collect response, ignoring results
  });

  if ($self->{timer}->timed_out()) {
    $self->disconnect;
    die("bayes: Redis connection timed out!");
  }
  elsif ($err) {
    $self->disconnect;
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

  my $ttl = $self->{expire_token};  # time-to-live, in seconds
  return 1  unless $ttl && $tokens && @$tokens;

  dbg("bayes: tok_touch_all setting expire to %s on %d tokens",
      $ttl, scalar @$tokens);

  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  # Benchmarks for a 'with-Lua' vs. a 'batched non-Lua' case show same speed,
  # so for simplicity we only kept a batched non-Lua code. Note that this
  # only applies to our own implementation of the Redis client protocol
  # which offers efficient command batching (pipelining) - with the Redis
  # CPAN module the batched case would be worse by about 33% on the average.

  # We just refresh TTL on all

  $r->b_call('EXPIRE', 'w:'.$_, $ttl) for @$tokens;
  $r->b_results;  # collect response, ignoring results

  return 1;
}

=head2 cleanup

public instance (Boolean) cleanup ()

Description:
This method perfoms any cleanup necessary before moving onto the next
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

  # TODO
  warn("bayes: note: assuming the database is empty; ".
       "to manually clear a database: redis-cli -n <db-ind> FLUSHDB\n");

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
  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  my $atime = time;  # fake

  # let's get past this terrible command as fast as possible
  # (ignoring $regex which makes no sense with SHA digests)
  my $keys = $r->call('KEYS', 'w:*');
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
        push(@tokensdata,
             [ substr($keys->[$j],2), ($s||0)+0, ($h||0)+0 ])  if $s || $h;
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
        $self->disconnect;
        die "bayes: dump_db_toks received no results\n";
      } elsif ($r_nonce ne $nonce) {
        # redis protocol error?
        $self->disconnect;
        die sprintf("bayes: dump_db_toks nonce mismatch, ".
                    "expected %s, got %s\n",
                    $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
      } elsif (@items != @tokens) {
        $self->disconnect;
        die sprintf("bayes: dump_db_toks got %d entries, expected %d\n",
                       scalar @items, scalar @tokens);
      }
      # stripping a leading "w:"
      @tokensdata = map { my($s,$h) = split(m{/}, shift @items, 2);
                          [ substr($_,2), ($s||0)+0, ($h||0)+0 ] } @tokens;
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
  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  my $atime = time;  # fake
  my @vars = $self->get_storage_variables(qw(DB_VERSION NSPAM NHAM));
  print "v\t$vars[0]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  # let's get past this terrible command as fast as possible
  my $keys = $r->call('KEYS', 'w:*');
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
        my $encoded = unpack("H*", substr($keys->[$j++], 2));
        my($s,$h) = @$item;
        printf("t\t%d\t%d\t%s\t%s\n",
               $s||0, $h||0, $atime, $encoded)  if $s || $h;
      }

    } else {  # have_lua

      my $nonce = sprintf("%06x", rand(0xffffff));
      my @tokens = @{$keys}[$i .. $end];
      my $result = $r->call('EVALSHA', $self->{multi_hmget_script},
                            scalar @tokens, @tokens, $nonce);
      my @items = split(' ', $result);
      my $r_nonce = pop(@items);
      if (!defined $r_nonce) {
        $self->disconnect;
        die "bayes: backup_database received no results\n";
      } elsif ($r_nonce ne $nonce) {
        # redis protocol error?
        $self->disconnect;
        die sprintf("bayes: backup_database nonce mismatch, ".
                    "expected %s, got %s\n",
                    $nonce, defined $r_nonce ? $r_nonce : 'UNDEF');
      } elsif (@items != @tokens) {
        $self->disconnect;
        die sprintf("bayes: backup_database got %d entries, expected %d\n",
                       scalar @items, scalar @tokens);
      }
      foreach my $token (@tokens) {
        my($s,$h) = split(m{/}, shift @items, 2);
        next if !$s && !$h;
        my $encoded = unpack("H*", substr($token,2));  # strip leading "w:"
        printf("t\t%d\t%d\t%s\t%s\n", $s||0, $h||0, $atime, $encoded);
      }
    }
  }
  dbg("bayes: written token keys");

  $keys = $r->call('KEYS', 's:*');
  dbg("bayes: fetched %d seen keys", scalar @$keys);

  for (my $i = 0; $i <= $#$keys; $i += 1000) {
    my $end = $i + 999 >= $#$keys ? $#$keys : $i + 999;
    my @t = @{$keys}[$i .. $end];
    my $v = $r->call('MGET', @t);
    for (my $i = 0; $i < @$v; $i++) {
      next unless defined $v->[$i];
      printf("s\t%s\t%s\n", $v->[$i], substr($t[$i], 2));
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
  $self->connect if !$self->{connected};
  my $r = $self->{redis};

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
      my $key = 'w:'.$token;
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
        $r->b_call('SET', "s:$msgid", $flag);
      } else {
        # by introducing some randomness (ttl times a factor of 0.7 .. 1.7),
        # we avoid auto-expiration of many 'seen' entries all at once,
        # introducing an unnecessary load spike on a redis server
        $r->b_call('SETEX', "s:$msgid", int($seen_ttl * (rand()+0.7)), $flag);
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

#
# Redis functions
#

sub _define_lua_scripts {
  my $self = shift;
  dbg("bayes: defining Lua scripts");

  $self->connect if !$self->{connected};
  my $r = $self->{redis};

  $self->{multi_hmget_script} = $r->call('SCRIPT', 'LOAD', <<'END');
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
