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
!! IT IS STILL EXPERIMENTAL AND SUBJECT TO CHANGE !!

These config variables have been hijacked for our purposes:

  bayes_sql_dsn

    Optional config parameters sent as is to Redis->new().
    Example: server=localhost:6379;password=foo
    By default encoding=undef is set as suggested by Redis module.

    To use non-default database id, use "database=x". This is not passed
    to new(), but specially handled to call Redis->select($id).

  bayes_expiry_max_db_size

    Controls token/seen expiry (ttl value in SECONDS, sent as is to Redis).
    Default 150000 (41 hours) is sane (that's why we abuse this variable),
    but you should try atleast 604800 (1 week).

Expiry is done internally in Redis using EXPIRY value mentioned above. This
is why --force-expire etc does nothing and token counts and atime values are
shown zero in statistics.

=cut

package Mail::SpamAssassin::BayesStore::Redis;

use strict;
use warnings;
use bytes;
use re 'taint';
use Errno qw(EBADF);
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Timeout;

my $VERSION = 0.09;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore );

use constant HAS_REDIS => eval { require Redis; };

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
    dbg("bayes: unable to connect to database: DBI module not available: $!");
  }

  push @{$self->{redis_conf}}, 'encoding' => undef;

  foreach (split(';', $self->{bayes}->{conf}->{bayes_sql_dsn})) {
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

  $self->{expire_seen} =
    $self->{bayes}->{conf}->{bayes_expiry_max_db_size} || 150000;
  $self->{expire_token} =
    $self->{bayes}->{conf}->{bayes_expiry_max_db_size} || 150000;

  $self->{supported_db_version} = 3;
  $self->{is_really_open} = 0;
  $self->{is_writable} = 0;
  $self->{is_officially_open} = 0;

  $self->{timer} = Mail::SpamAssassin::Timeout->new({
    secs => $self->{conf}->{redis_timeout} || 2
  });

  return $self;
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

  my $result = $self->{is_really_open} || $self->_open_db();
  $self->{is_writable} = 0 if $result;

  return $result;
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

  my $result = $self->{is_really_open} || $self->_open_db();
  $self->{is_writable} = 1 if $result;

  return $result;
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
    $self->{redis} = Redis->new(@{$self->{redis_conf}});
    $self->{redis}->select($self->{db_id}) if defined $self->{db_id};
  });

  if ($self->{timer}->timed_out()) {
    warn("bayes: Redis connection timed out!");
    return 0;
  }
  elsif ($err) {
    $err =~ s! at /.*!!s; # skip full trace
    warn("bayes: Redis connection failed: $err");
    return 0;
  }

  $self->{db_version} = $self->_get('v:DB_VERSION');

  if (!$self->{db_version}) {
      $self->{db_version} = $self->DB_VERSION;
      my $ret = $self->_mset([
        'v:DB_VERSION', $self->{db_version},
        'v:NSPAM', 0,
        'v:NHAM', 0,
      ]);
      unless ($ret) {
          warn("bayes: failed to initialize database");
          return 0;
      }
      dbg("bayes: initialized empty database, version $self->{db_version}");
  }
  else {
    dbg("bayes: found bayes db version $self->{db_version}");
    if ($self->{db_version} ne $self->DB_VERSION) {
      warn("bayes: bayes db version $self->{db_version} not supported, aborting\n");
      return 0;
    }
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
  my($self) = @_;

  my @tokens = map {"v:$_"}
               qw{LAST_JOURNAL_SYNC NSPAM NHAM NTOKENS LAST_EXPIRE
                  OLDEST_TOKEN_AGE DB_VERSION LAST_JOURNAL_SYNC
                  LAST_ATIME_DELTA LAST_EXPIRE_REDUCE NEWEST_TOKEN_AGE};
  my @values = $self->_mget(\@tokens);
  foreach (@values) {
    $_ = 0 unless $_;
  }

  return @values;
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
  return !@$array ? () : (@{$array->[0]})[1,2,3];
}

=head2 tok_get_all

public instance (\@) tok_get (@ $tokens)

Description:
This method retrieves the specified tokens (C<$tokens>) from storage and
returns an array ref of arrays spam count, ham acount and last access time.

=cut

sub tok_get_all {
  my($self, @keys) = @_;

  my @t = map {"t:$_"} @keys;
  my @results = $self->_mget(\@t);
  my @values;

  foreach my $token (@keys) {
    my $value = shift(@results);
    push(@values, [$token, _unpack_token($value), 0]) if defined $value;
  }

  dbg("bayes: tok_get_all found %d tokens out of %d search keys",
      scalar(@values), scalar(@keys));

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
tokens in the C<$tokens> hash ref along with updating each tokens
atime with C<$atime>.

=cut

sub multi_tok_count_change {
  my($self, $dspam, $dham, $tokens, $newatime) = @_;

  # Make sure we have some values
  $dspam ||= 0;
  $dham ||= 0;

  my @t = map {"t:$_"} keys %{$tokens};
  my @v = $self->_mget(\@t);

  foreach my $token (@t) {
    my $value = shift(@v);
    my ($spam, $ham) = defined $value ? _unpack_token($value) : (0,0);
    $spam += $dspam;
    $ham += $dham;
    $spam = 0 if $spam < 0;
    $ham = 0 if $ham < 0;
    if ($ham == 0 && $spam == 0) {
      $self->_del_p($token);
    } else {
      $self->_set_p($token, _pack_token($spam, $ham), $self->{expire_token});
    }
  }

  $self->_wait_all_responses;

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

  my @vars = $self->get_storage_variables();
  ($vars[1], $vars[2]);
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
    $err =~ s! at /.*!!s; # skip full trace
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

  # We just refresh TTL on all
  foreach (map {"t:$_"} @$tokens) {
    $self->_expire_p($_, $self->{expire_token});
  }

  $self->_wait_all_responses;

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

=head2 backup_database

public instance (Boolean) backup_database ()

Description:
This method will dump the users database in a machine readable format.

=cut

sub backup_database {
  my($self) = @_;

  return 0 unless $self->tie_db_writable;

  my $atime = time;
  my @vars = $self->get_storage_variables;
  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  # Process tokens in chunks of 10000 to save some memory on large sets
  # (sadly it's impossible to prevent Redis-module itself keeping all
  # resulting keys in memory)

  $self->{redis}->keys('t:*', sub {
    my ($reply, $error) = @_;
    die "bayes: token keys fetch failed: $error" if defined $error;
    for (my $i = 0; $i < @$reply; $i += 10000) {
      my $end = $i + 10000 > @$reply ? @$reply - 1 : $i + 9999;
      my @t = @$reply[$i .. $end];
      my @v = $self->_mget(\@t);
      die "bayes: token fetch failed" unless @v;
      for (my $i = 0; $i < @v; $i++) {
	next unless defined $v[$i];
        my($ts, $th) = _unpack_token($v[$i]);
        my $encoded = unpack("H*", substr($t[$i], 2));
        print "t\t$ts\t$th\t$atime\t$encoded\n";
      }
    }
  });
  $self->{redis}->wait_all_responses;

  $self->{redis}->keys('s:*', sub {
    my ($reply, $error) = @_;
    die "bayes: seen keys fetch failed: $error" if defined $error;
    for (my $i = 0; $i < @$reply; $i += 10000) {
      my $end = $i + 10000 > @$reply ? @$reply - 1 : $i + 9999;
      my @t = @$reply[$i .. $end];
      my @v = $self->_mget(\@t);
      die "bayes: seen fetch failed" unless @v;
      for (my $i = 0; $i < @v; $i++) {
	next unless defined $v[$i];
        print "s\t$v[$i]\t".substr($t[$i], 2)."\n";
      }
    }
  });
  $self->{redis}->wait_all_responses;

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

      $self->_set_p("t:$token", _pack_token($spam_count, $ham_count),
                    $self->{expire_token});
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

# token marshalling format for tokens
# pack CC for values <256, VV for the rest, keep it simple

sub _unpack_token {
  my $value = shift;

  my ($ts, $th);

  if (length($value) == 2) {
    ($ts, $th) = unpack("CC", $value);
  }
  elsif (length($value) == 8) {
    ($ts, $th) = unpack("VV", $value);
  }
  else {
    dbg("bayes: unknown token format: ".unpack("H*", $value));
  }

  return ($ts||0, $th||0);
}

sub _pack_token {
  my($ts, $th) = @_;

  if ($ts < 256 && $th < 256) {
    return pack("CC", $ts, $th);
  } else {
    return pack("VV", $ts, $th);
  }
}

#
# Redis functions
#

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
    $err =~ s! at /.*!!s; # skip full trace
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
    $err =~ s! at /.*!!s; # skip full trace
    die("bayes: mget failed: $err");
  }

  return @values;
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
    $err =~ s! at /.*!!s; # skip full trace
    die("bayes: set failed: $err");
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

# Pipelined del, must call _wait_all_responses after
sub _del_p {
  my ($self, $key) = @_;

  $self->{redis}->del($key, sub {});

  return 1;
}

# Pipelined expire, must call _wait_all_responses after
sub _expire_p {
  my ($self, $key, $expire) = @_;

  $self->{redis}->expire($key, $expire, sub {});

  return 1;
}

sub _wait_all_responses {
  my ($self) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->wait_all_responses;
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: wait_all_responses timed out!");
  }
  elsif ($err) {
    $err =~ s! at /.*!!s; # skip full trace
    die("bayes: wait_all_responses failed: $err");
  }

  return 1;
}

sub _mset {
  my ($self, $values) = @_;

  my $err = $self->{timer}->run_and_catch(sub {
    $self->{redis}->mset(@$values);
  });

  if ($self->{timer}->timed_out()) {
    die("bayes: mset timed out!");
  }
  elsif ($err) {
    $err =~ s! at /.*!!s; # skip full trace
    die("bayes: mset failed: $err");
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
    $err =~ s! at /.*!!s; # skip full trace
    die("bayes: mset failed: $err");
  }

  return 1;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
