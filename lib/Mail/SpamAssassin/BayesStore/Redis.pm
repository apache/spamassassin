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

A redis server with a Lua support (2.6 or higher) is strongly recommended
for performance reasons.

The bayes_sql_dsn config variable has been hijacked for our purposes:

  bayes_sql_dsn

    Optional config parameters sent as is to Redis->new().
    Example: server=localhost:6379;password=foo;reconnect=20

    By default encoding=undef is set as suggested by Redis module.

    To use non-default database id, use "database=x". This is not passed
    to new(), but specially handled to call Redis->select($id).

  bayes_token_ttl

    Controls token expiry (ttl value in SECONDS, sent as is to Redis)
    when bayes_auto_expire is true. Default value is 3 weeks (but check
    Mail::SpamAssassin::Conf.pm to make sure).

  bayes_seen_ttl

    Controls 'seen' expiry (ttl value in SECONDS, sent as is to Redis)
    when bayes_auto_expire is true. Default value is 8 days (but check
    Mail::SpamAssassin::Conf.pm to make sure).

Expiry is done internally in Redis using *_ttl settings mentioned above,
but only if bayes_auto_expire is true (which is a default).  This is
why --force-expire etc does nothing and token counts and atime values
are shown zero in statistics.

LIMITATIONS: Only global bayes storage is implemented, per-user bayes is
not available. Dumping (sa-learn --backup) of a very large database may
not be possible due to memory limitations and inefficient full database
traversal mechanism. This backend storage module is new with SpamAssassin
3.4.0 and may be revised in future versions as more experience is gained.

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

use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;

use vars qw( @ISA $VERSION );

BEGIN {
  $VERSION = 0.09;
  @ISA = qw( Mail::SpamAssassin::BayesStore );
}

# Support for "SCRIPT LOAD" command is needed, provided by Redis version 1.954
use constant HAS_REDIS => eval { require Redis; Redis->VERSION(1.954) };

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

  unless (HAS_REDIS) {
    dbg("bayes: unable to connect to database: Redis module not available");
  }

  my $bconf = $self->{bayes}->{conf};
  push @{$self->{redis_conf}}, 'encoding' => undef;

  foreach (split(';', $bconf->{bayes_sql_dsn})) {
    my ($a, $b) = split('=');
    unless (defined $b) {
      warn("bayes: invalid bayes_sql_dsn config\n");
      return;
    }
    if ($a eq 'database') {
      $self->{db_id} = $b;
    }
    else {
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
  $self->{is_really_open} = 0;
  $self->{is_writable} = 0;
  $self->{is_officially_open} = 0;

  $self->{timer} = Mail::SpamAssassin::Timeout->new({
    secs => $self->{conf}->{redis_timeout} || 2
  });

  return $self;
}

sub DESTROY {
  my($self) = @_;
  if ($self->{is_really_open} && $self->{redis}) {
    eval { $self->{redis}->quit };  # close session, ignoring any failures
  }
}

=head2 prefork_init

public instance (Boolean) prefork_init ();

Description:
This optional method is called in the parent process shortly before
forking off child processes.

=cut

sub prefork_init {
  my ($self) = @_;

  HAS_REDIS or return;

  # Each child process must establish its own connection with a Redis server,
  # re-using a common forked socket leads to serious trouble (garbled data).
  #
  # Parent process may have established its connection during startup, but
  # it is no longer of any use by now, so we shut it down here in the master
  # process, letting a spawned child process re-establish it later.

  if ($self->{is_really_open}) {
    dbg("bayes: prefork_init, closing a session ".
        "with a Redis server in a parent process");
    $self->untie_db;
    if ($self->{redis}) {
      eval { $self->{redis}->quit };  # close session, ignoring any failures
    }
    undef $self->{redis};
    $self->{is_really_open} = 0;
  }
}

=head2 spamd_child_init

public instance (Boolean) spamd_child_init ();

Description:
This optional method is called in a child process shortly after being spawned.

=cut

sub spamd_child_init {
  my ($self) = @_;

  HAS_REDIS or return;

  # Each child process must establish its own connection with a Redis server,
  # re-using a common forked socket leads to serious trouble (garbled data).
  #
  # Just in case the parent master process did not call prefork_init() above,
  # we try to silently renounce the use of existing cloned connection here.
  # As the prefork_init plugin callback has only been in introduced in
  # SpamAssassin 3.4.0, this situation can arrise in case of some third party
  # software (or a pre-3.4.0 version of spamd) is somehow using this plugin.
  # Better safe than sorry...

  if ($self->{is_really_open}) {
    dbg("bayes: spamd_child_init, closing a parent's session ".
        "with a Redis server in a child process");
    $self->untie_db;
    undef $self->{redis};  # just drop it, don't shut down parent's session
    $self->{is_really_open} = 0;
  }
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection is properly setup and
working.

=cut

sub tie_db_readonly {
  my($self) = @_;

  return 0 unless (HAS_REDIS);

  my $really_open = $self->{is_really_open};
  if ($really_open) {
    $self->{is_officially_open} = 1;
  } else {
    $really_open = $self->_open_db();
  }
  $self->{is_writable} = 0;

  return $really_open;
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

  return 0 unless (HAS_REDIS);

  my $really_open = $self->{is_really_open};
  if ($really_open) {
    $self->{is_officially_open} = 1;
  } else {
    $really_open = $self->_open_db();
  }

  $self->{is_writable} = 1 if $really_open;

  return $really_open;
}

=head2 _open_db

private instance (Boolean) _open_db (Boolean $writable)

Description:
This method ensures that the database connection is properly setup and
working.  It will initialize a users bayes variables so that they
can begin using the database immediately.

=cut

sub _open_db {
  my($self) = @_;

  dbg("bayes: _open_db(%s); Redis %s",
      $self->{is_really_open} ? 'already open' : 'not yet open',
      Redis->VERSION);

  if ($self->{is_really_open}) {
    $self->{is_officially_open} = 1;
    return 1;
  }

  $self->read_db_configs();

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{opened_from_pid} = $$;
    # will keep a persistent session open to a redis server
    $self->{redis} = Redis->new(@{$self->{redis_conf}});
    $self->{redis}->select($self->{db_id}) if defined $self->{db_id};
  });

  if ($self->{timer}->timed_out()) {
    warn("bayes: Redis connection timed out!");
    return 0;
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    warn("bayes: Redis connection failed: $err");
    return 0;
  }

  my $have_lua = $self->{have_lua};
  if (!$self->{redis_server_version}) {
    my $info = $self->{info} = $self->{redis}->info;
    if ($info) {
      $self->{redis_server_version} = $info->{redis_version};
      $have_lua = $self->{have_lua} = 1  if exists $info->{used_memory_lua};

      dbg("bayes: redis server version %s, memory used %.1f MiB%s",
          $info->{redis_version}, $info->{used_memory}/1024/1024,
          !$have_lua ? '' : ", Lua is available");
    }
    if (!$have_lua) {
      warn "bayes: Redis server does not support Lua, ".
           "upgrade or expect slower operation\n";
    }
  }

  $self->{db_version} = $self->_get('v:DB_VERSION');

  if (!$self->{db_version}) {
    $self->{db_version} = $self->DB_VERSION;
    my $ret = $self->{redis}->mset('v:DB_VERSION', $self->{db_version},
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
    my $token_format = $self->_get('v:TOKEN_FORMAT') || 0;
    if ($token_format < 2) {
      warn("bayes: bayes old token format $token_format not supported, ".
           "consider backup/restore or initialize a database\n");
      return 0;
    }
  }

  if ($have_lua && !defined $self->{multi_hmget_script}) {
    $self->_define_lua_scripts;
  }

  $self->{is_really_open} = 1;
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

  $self->{is_officially_open} = 0;
  $self->{is_writable} = 0;
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

  return $self->_get("s:$msgid");
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is one
of two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my($self, $msgid, $flag) = @_;

  $self->_set("s:$msgid", $flag, $self->{expire_seen});
  return 1;
}

=head2 seen_delete

public instance (Boolean) seen_delete (string $msgid)

Description:
This method removes C<$msgid> from the database.

=cut

sub seen_delete {
  my($self, $msgid) = @_;

  $self->_del("s:$msgid");
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
  @varnames = map("v:$_", @varnames);
  my $values = $self->_mget(\@varnames);
  return if !$values;
  return map(defined $_ ? $_ : 0, @$values);
}

=head2 get_running_expire_tok

public instance (String $time) get_running_expire_tok ()

Description:
This method determines if an expire is currently running and returns
the last time set.

There can be multiple times, so we just pull the greatest (most recent)
value.

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
  my $r = $self->{redis};

  if (! $self->{have_lua} ) {
    foreach my $token (@_) {
      $r->hmget('w:'.$token, 's', 'h', sub {
        my($values, $error) = @_;
        return if !$values || @$values != 2;
        return if !$values->[0] && !$values->[1];
        push(@values, [$token, $values->[0]||0, $values->[1]||0, 0]);
        1;
      });
    }
    $self->_wait_all_responses;

  } else {  # have Lua, faster
    my @results;
    eval {
      @results = $r->evalsha($self->{multi_hmget_script}, scalar @_, @_);
      1;
    } or do {  # Lua script probably not cached, define again and re-try
      $@ =~ /^\Q[evalsha] NOSCRIPT\E/ or die "bayes: Redis LUA error: $@\n";
      $self->_define_lua_scripts;
      @results = $r->evalsha($self->{multi_hmget_script}, scalar @_, @_);
    };
    @results = split(' ', $results[0])  if @results == 1;
    @results == @_
      or die sprintf("bayes: tok_get_all got %d results, expected %d\n",
                     scalar @results, scalar @_);
    foreach my $token (@_) {
      my($s,$h) = split(m{/}, shift @results, 2);
      push(@values, [$token, ($s||0)+0, ($h||0)+0, 0])  if $s || $h;
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

  my $ttl = $self->{expire_token};  # time-to-live, in seconds

  dbg("bayes: multi_tok_count_change learning %d spam, %d ham",
      $dspam, $dham);

  if ($self->{have_lua}) {

    my $r = $self->{redis};
    my $ntokens = scalar keys %$tokens;
    my $cnt;
    eval {
      $cnt = $r->evalsha($self->{multi_hincrby},
                         $ntokens, keys %$tokens, $dspam, $dham, $ttl);
      1;
    } or do {  # Lua script probably not cached, define again and re-try
      $@ =~ /^\Q[evalsha] NOSCRIPT\E/ or die "bayes: Redis LUA error: $@\n";
      $self->_define_lua_scripts;
      $cnt = $r->evalsha($self->{multi_hincrby},
                         $ntokens, keys %$tokens, $dspam, $dham, $ttl);
    };
    $cnt == $ntokens
      or die sprintf("bayes: multi_tok_count_change got %d, expected %d\n",
                     $cnt, $ntokens);

  } else {  # no Lua, slower

    if ($dspam > 0 || $dham > 0) {  # learning
      while (my($token,$v) = each(%$tokens)) {
        $self->_hincrby_p('w:'.$token, 's', $dspam)  if $dspam > 0;
        $self->_hincrby_p('w:'.$token, 'h', $dham)   if $dham  > 0;
        $self->_expire_p('w:'.$token, $ttl)  if $ttl;
      }
      $self->_wait_all_responses;
    }

    if ($dspam < 0 || $dham < 0) {  # unlearning - rare, not as efficient
      while (my($token,$v) = each(%$tokens)) {
        if ($dspam < 0) {
          my $result = $self->_hincrby('w:'.$token, 's', int $dspam);
          if (!$result || $result <= 0) {
            $self->_hdel_p('w:'.$token, 's');
          } elsif ($ttl) {
            $self->_expire_p('w:'.$token, $ttl);
          }
        }
        if ($dham < 0) {
          my $result = $self->_hincrby('w:'.$token, 'h', int $dham);
          if (!$result || $result <= 0) {
            $self->_hdel_p('w:'.$token, 'h');
          } elsif ($ttl) {
            $self->_expire_p('w:'.$token, $ttl);
          }
        }
      }
      $self->_wait_all_responses;
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

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->incrby("v:NSPAM", $ds) if $ds;
    $self->{redis}->incrby("v:NHAM", $dh) if $dh;
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: Redis connection timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
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
  return 1 unless defined $ttl;

  dbg("bayes: tok_touch_all setting expire to %s on %d tokens",
      $ttl, scalar @$tokens);

  # We just refresh TTL on all
  if (! $self->{have_lua} ) {
    $self->_expire_p("w:$_", $ttl) for @$tokens;
    $self->_wait_all_responses;

  } else {  # have Lua, faster
    my $r = $self->{redis};
    my $cnt;
    eval {
      $cnt = $r->evalsha($self->{multi_expire_script},
                         scalar @$tokens, @$tokens, $ttl);
      1;
    } or do {  # Lua script probably not cached, define again and re-try
      $@ =~ /^\Q[evalsha] NOSCRIPT\E/ or die "bayes: Redis LUA error: $@\n";
      $self->_define_lua_scripts;
      $cnt = $r->evalsha($self->{multi_expire_script},
                         scalar @$tokens, @$tokens, $ttl);
    };
    $cnt == @$tokens
      or die sprintf("bayes: tok_touch_all got %d, expected %d\n",
                     $cnt, scalar @$tokens);
  }
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
  warn("bayes: you need to manually clear Redis database\n");

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
  my $r = $self->{redis};
  my $atime = time;  # fake

  # Sadly it's impossible to prevent Redis-module itself keeping all
  # resulting keys in memory.
  my @keys;

  # let's get past this terrible command as fast as possible
  # (ignoring $regex which makes no sense with SHA digests)
  @keys = $r->keys('w:*');
  dbg("bayes: fetched %d token keys", scalar @keys);

  # process tokens in chunks of 1000
  for (my $i = 0; $i <= $#keys; $i += 1000) {
    my $end = $i + 999 >= $#keys ? $#keys : $i + 999;

    my @tokensdata;
    if ($self->{have_lua}) {
      my @tokens = map(substr($_,2), @keys[$i .. $end]);  # strip leading "w:"
      my @results = $r->evalsha($self->{multi_hmget_script},
                                scalar @tokens, @tokens);
      @results = split(' ', $results[0])  if @results == 1;
      @tokensdata = map { my($s,$h) = split(m{/}, shift @results, 2);
                          [ $_, $s||0, $h||0 ] } @tokens;

    } else {  # no Lua, 3-times slower
      for (my $j = $i; $j <= $end; $j++) {
        my $token = $keys[$j];
        $r->hmget($token, 's', 'h', sub {
          my($val, $error) = @_;
          push(@tokensdata, [ substr($token,2), $val->[0]||0, $val->[1]||0 ])
            if $val && @$val == 2;
          1;
        });
      }
      $self->_wait_all_responses;
    }

    foreach my $tokendata (@tokensdata) {
      my($token, $s, $h) = @$tokendata;
      next if !$s && !$h;
      my $prob =
        $self->{bayes}->_compute_prob_for_token($token, $vars[1], $vars[2],
                                                $s, $h);
      $prob = 0.5  if !defined $prob;
      my $encoded = unpack("H*", $token);
      printf($template, $prob, $s, $h, $atime, $encoded)
        or die "Error writing tokens: $!";
    }
  }

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

  my $atime = time;  # fake
  my @vars = $self->get_storage_variables(qw(DB_VERSION NSPAM NHAM));
  print "v\t$vars[0]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  my $r = $self->{redis};

  # Sadly it's impossible to prevent Redis-module itself keeping all
  # resulting keys in memory.
  my @keys;

  # let's get past this terrible command as fast as possible
  @keys = $r->keys('w:*');
  dbg("bayes: fetched %d token keys", scalar @keys);

  # process tokens in chunks of 1000
  for (my $i = 0; $i <= $#keys; $i += 1000) {
    my $end = $i + 999 >= $#keys ? $#keys : $i + 999;

    if ($self->{have_lua}) {
      my @tokens = map(substr($_,2), @keys[$i .. $end]);  # strip leading "w:"
      my @results = $r->evalsha($self->{multi_hmget_script},
                                scalar @tokens, @tokens);
      @results = split(' ', $results[0])  if @results == 1;
      foreach my $token (@tokens) {
        my($s,$h) = split(m{/}, shift @results, 2);
        next if !$s && !$h;
        my $encoded = unpack("H*", $token);
        printf("t\t%d\t%d\t%s\t%s\n", $s||0, $h||0, $atime, $encoded);
      }

    } else {   # no Lua, slower
      for (my $j = $i; $j <= $end; $j++) {
        my $token = $keys[$j];
        $r->hmget($token, 's', 'h', sub {
          my($values, $error) = @_;
          return if !$values || @$values != 2;
          return if !$values->[0] && !$values->[1];
          my $encoded = unpack("H*", substr($token, 2));
          printf("t\t%d\t%d\t%s\t%s\n",
                 $values->[0]||0, $values->[1]||0, $atime, $encoded);
          1;
        });
      }
      $self->_wait_all_responses;
    }
  }

  @keys = $r->keys('s:*');
  dbg("bayes: fetched %d seen keys", scalar @keys);

  for (my $i = 0; $i <= $#keys; $i += 1000) {
    my $end = $i + 999 >= $#keys ? $#keys : $i + 999;
    my @t = @keys[$i .. $end];
    my $v = $self->_mget(\@t);
    die "bayes: seen fetch failed" unless $v && @$v;
    for (my $i = 0; $i < @$v; $i++) {
      next unless defined $v->[$i];
      printf("s\t%s\t%s\n", $v->[$i], substr($t[$i], 2));
    }
  }

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

  # This is the critical phase (moving sql around), so don't allow it
  # to be interrupted.
  #local $SIG{'INT'} = 'IGNORE';
  #local $SIG{'HUP'} = 'IGNORE'
  #  if !Mail::SpamAssassin::Util::am_running_on_windows();
  #local $SIG{'TERM'} = 'IGNORE';

  unless ($self->clear_database()) {
    return 0;
  }

  unless ($self->tie_db_writable()) {
    return 0;
  }

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

      next if $spam_count == 0 && $ham_count == 0;

      if ($db_version < 3) {
        # versions < 3 use plain text tokens, so we need to convert to hash
        $token = substr(sha1($token), -5);
      } else {
        # turn unpacked binary token back into binary value
        $token = pack("H*",$token);
      }
      my $key = 'w:'.$token;
      $self->_hincrby_p($key, 's', int $spam_count) if $spam_count > 0;
      $self->_hincrby_p($key, 'h', int $ham_count)  if $ham_count  > 0;
      $self->_expire_p($key, $self->{expire_token})
        if defined $self->{expire_token};

      $self->{redis}->wait_all_responses if ++$q_cnt % 10000 == 0;
      $token_count++;
    } elsif ($line =~ /^s\s+/) { # seen line
      my @parsed_line = split(/\s+/, $line, 3);
      my $flag = $parsed_line[1];
      my $msgid = $parsed_line[2];

      unless ($flag eq 'h' || $flag eq 's') {
        dbg("bayes: unknown seen flag ($flag) for line: $line, skipping");
        next;
      }

      unless ($msgid) {
        dbg("bayes: blank msgid for line: $line, skipping");
        next;
      }

      $self->_set_p("s:$msgid", $flag, $self->{expire_seen});
      $self->{redis}->wait_all_responses if ++$q_cnt % 10000 == 0;
    }
    elsif ($line =~ /^v\s+/) {     # variable line
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

  defined $line || $!==0  or
    $!==EBADF ? dbg("bayes: error reading dump file: $!")
      : die "error reading dump file: $!";
  close(DUMPFILE) or die "Can't close dump file: $!";

  $self->{redis}->wait_all_responses;

  print STDERR "\n" if $showdots;

  if ($num_spam <= 0 && $num_ham <= 0) {
    warn("bayes: no num_spam/num_ham found, aborting");
    return 0;
  }
  else {
    $self->nspam_nham_change($num_spam, $num_ham);
  }

  dbg("bayes: parsed $line_count lines");
  dbg("bayes: created database with $token_count tokens based on $num_spam spam messages and $num_ham ham messages");

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

  return $self->{is_really_open} && $self->{is_officially_open};
}

=head2 db_writable

public instance (Boolean) db_writable()

Description:
This method returns a boolean value indicating if the database is in a
writable state.

=cut

sub db_writable {
  my($self) = @_;

  return $self->{is_really_open} && $self->{is_officially_open} &&
         $self->{is_writable};
}

#
# Redis functions
#

sub _define_lua_scripts {
  my $self = shift;
  dbg("bayes: defining Lua scripts");
  my $r = $self->{redis};

  $self->{multi_hmget_script} = $r->script_load(<<'END');
    local rcall = redis.call
    local r = {}
    for j = 1, #KEYS do
      local sh = rcall("HMGET", "w:" .. KEYS[j], "s", "h")
      -- returns counts as a list of spam/ham pairs, zeroes may be omitted
      local s, h = sh[1] or "0", sh[2] or "0"
      local pair
      if h == "0" then
        pair = s  -- just a spam field, possibly zero; a ham field omitted
      elseif s == "0" then
        pair = "/" .. h  -- just a ham field, zero in spam suppressed
      else
        pair = s .. "/" .. h
      end
      r[#r+1] = pair
    end
    -- return as a single string, avoids overhead of multiresult parsing
    return table.concat(r, " ")
END

  $self->{multi_expire_script} = $r->script_load(<<'END');
    local ttl = ARGV[1]
    local rcall = redis.call
    for j = 1, #KEYS do
      rcall("EXPIRE", "w:" .. KEYS[j], ttl)
    end
    return #KEYS
END

  $self->{multi_hincrby} = $r->script_load(<<'END');
    local s, h, ttl = ARGV[1], ARGV[2], ARGV[3]
    local set_expire = ttl and tonumber(ttl) > 0
    local rcall = redis.call
    if tonumber(s) ~= 0 then
      for j = 1, #KEYS do
        local token = "w:" .. KEYS[j]
        local cnt = rcall("HINCRBY", token, "s", s)
        if cnt <= 0 then
          rcall("HDEL", token, "s")
        elseif set_expire then
          rcall("EXPIRE", token, ttl)
        end
      end
    end
    if tonumber(h) ~= 0 then
      for j = 1, #KEYS do
        local token = "w:" .. KEYS[j]
        local cnt = rcall("HINCRBY", token, "h", h)
        if cnt <= 0 then
          rcall("HDEL", token, "h")
        elseif set_expire then
          rcall("EXPIRE", token, ttl)
        end
      end
    end
    return #KEYS
END

  1;
}

sub _get {
  my ($self, $key) = @_;

  my $value;

  my $err = $self->{timer}->run_and_catch(sub {
    $value = $self->{redis}->get($key);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: get timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: get failed: $err");
  }

  return $value;
}

sub _mget {
  my ($self, $keys) = @_;

  my @values;

  my $err = $self->{timer}->run_and_catch(sub {
    @values = $self->{redis}->mget(@$keys);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: mget timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: mget failed: $err");
  }

  return \@values;
}

sub _hmget {
  my ($self, $key, @fields) = @_;

  my $value;
  my $err = $self->{timer}->run_and_catch(sub {
    $value = $self->{redis}->hmget($key, @fields);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: hmget timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: hmget failed: $err");
  }

  return $value;
}

sub _set {
  my ($self, $key, $value, $expire) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    if (defined $expire) {
      $self->{redis}->setex($key, $expire, $value);
    } else {
      $self->{redis}->set($key, $value);
    }
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: set timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: set failed: $err");
  }

  return 1;
}

sub _hincrby {
  my ($self, $key, $field, $incr) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->hincrby($key, $field, $incr);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: hincrby timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: hincrby failed: $err");
  }

  return 1;
}

# Pipelined set, must call _wait_all_responses after
sub _set_p {
  my ($self, $key, $value, $expire) = @_;

  if (defined $expire) {
    $self->{redis}->setex($key, $expire, $value, sub {});
  } else {
    $self->{redis}->set($key, $value, sub {});
  }

  return 1;
}

# Pipelined hincrby, must call _wait_all_responses after
sub _hincrby_p {
  my ($self, $key, $field, $incr) = @_;

  $self->{redis}->hincrby($key, $field, $incr, sub {});

  return 1;
}

# Pipelined del, must call _wait_all_responses after
sub _del_p {
  my ($self, $key) = @_;

  $self->{redis}->del($key, sub {});

  return 1;
}

# Pipelined hdel, must call _wait_all_responses after
sub _hdel_p {
  my ($self, $key, $field) = @_;

  $self->{redis}->hdel($key, $field, sub {});

  return 1;
}

# Pipelined expire, must call _wait_all_responses after
sub _expire_p {
  my ($self, $key, $expire) = @_;

  if (defined $expire) {
    $self->{redis}->expire($key, $expire, sub {});
  }

  return 1;
}

sub _wait_all_responses {
  my ($self) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->wait_all_responses;
  });

  if ($self->{timer}->timed_out()) {
    die sprintf("bayes: wait_all_responses timed out! called from line %s\n",
                (caller)[2]);
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die sprintf("bayes: wait_all_responses failed: %s, called from line %s\n",
                $err, (caller)[2]);
  }

  return 1;
}

sub _del {
  my ($self, $key) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->del($key);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: del timed out!");
  }
  elsif ($err) {
    $err =~ s{ at /.*}{}s; # skip full trace
    $self->{is_really_open} = 0;
    die("bayes: del failed: $err");
  }

  return 1;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
