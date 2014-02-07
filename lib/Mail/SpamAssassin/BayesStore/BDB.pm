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

Mail::SpamAssassin::BayesStore::BDB - BerkeleyDB Bayesian Storage Module Implementation

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implementes a BDB based bayesian storage module.

=cut

package Mail::SpamAssassin::BayesStore::BDB;

use strict;
use warnings;
use bytes;
use re 'taint';
use Errno qw(EBADF);
#use Data::Dumper;
use File::Basename;
use File::Path;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore );

use constant HAS_BDB => eval { require BerkeleyDB; BerkeleyDB->import; };

my $rmw = DB_RMW;
my $next = DB_NEXT;

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::SQL) new (Mail::Spamassassin::Plugin::Bayes $bayes)

Description:
This methods creates a new instance of the Mail::SpamAssassin::BayesStore::BDB
object.  It expects to be passed an instance of the Mail::SpamAssassin:Bayes
object which is passed into the Mail::SpamAssassin::BayesStore parent object.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new(@_);
  $self->{supported_db_version} = 3;
  $self->{is_really_open} = 0;
  $self->{is_writable} = 0;
  $self->{is_officially_open} = 0;
  return $self;
}

sub DESTROY {
  my $self = shift;
  $self->_close_db;
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection is properly setup and
working.

=cut

sub tie_db_readonly {
  my($self) = @_;
  #dbg("bayes: tie_db_readonly");
# my $result = ($self->{is_really_open} && !$self->{is_writable})
#              || $self->_open_db(0);
  my $result = $self->{is_really_open} || $self->_open_db(0);
  dbg("bayes: tie_db_readonly, result is $result");
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
  #dbg("bayes: tie_db_writable");
  my $result = ($self->{is_really_open} && $self->{is_writable})
               || $self->_open_db(1);
  dbg("bayes: tie_db_writable, result is $result");
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
  my($self, $writable) = @_;

  dbg("bayes: _open_db(%s, %s); BerkeleyDB %s, libdb %s",
      $writable ? 'for writing' : 'for reading',
      $self->{is_really_open} ? 'already open' : 'not yet open',
      BerkeleyDB->VERSION, $BerkeleyDB::db_version);

  # Always notice state changes
  $self->{is_writable} = $writable;

  return 1 if $self->{is_really_open};

  #dbg("bayes: not already tied");

  my $main = $self->{bayes}->{main};

  if (!defined($main->{conf}->{bayes_path})) {
    dbg("bayes: bayes_path not defined");
    return 0;
  }

  #dbg("bayes: Reading db configs");
  $self->read_db_configs();

  my $path = dirname $main->sed_path($main->{conf}->{bayes_path});

  #dbg("bayes: Path is $path");
  # Path must exist or we must be in writable mode
  if (-d $path) {
    # All is cool
  } elsif ($writable) {
    # Create the path
    eval {
      mkpath($path, 0, (oct($main->{conf}->{bayes_file_mode}) & 0777));
    };
    warn("bayes: Couldn't create path: $@") if $@;
  } else {
    # FAIL
    warn("bayes: bayes_path doesn't exist and can't create: $path");
    return 0;
  }

  # Now we can set up our environment
  my $flags = DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN;
  $flags |= DB_CREATE if $writable;
  # DB_REGISTER|DB_RECOVER|

  # In the Berkeley DB 4.7 release, the logging subsystem is configured
  # using the DB_ENV->log_set_config method instead of the previously used
  # DB_ENV->set_flags method. The DB_ENV->set_flags method no longer accepts
  # flags DB_DIRECT_LOG, DB_DSYNC_LOG, DB_LOG_INMEMORY or DB_LOG_AUTOREMOVE.
  # Applications should be modified to use the equivalent flags accepted by
  # the DB_ENV->log_set_config method.
  #   -SetFlags => DB_LOG_AUTOREMOVE

  dbg("bayes: %s environment: %s, 0x%x, %s",
      $writable ? 'Opening or creating' : 'Opening existing',
      $path, $flags, $main->{conf}->{bayes_file_mode});
  unless ($self->{env} = BerkeleyDB::Env->new(
      -Cachesize => 67108864, -Home => $path, -Flags => $flags,
      -Mode => (oct($main->{conf}->{bayes_file_mode}) & 0666),
  )) {

    dbg("bayes: berkeleydb environment couldn't initialize: $BerkeleyDB::Error");
    return 0;
  }

  $flags = $writable ? DB_CREATE : 0;

  #dbg("bayes: Opening vars");
  unless ($self->{handles}->{vars} = BerkeleyDB::Btree->new(
      -Env => $self->{env}, -Filename => "vars.db", -Flags => $flags)) {
    warn("bayes: couldn't open vars.db: $BerkeleyDB::Error");
    delete $self->{handles}->{vars};
    $self->untie_db;
    return 0;
  }

  #dbg("bayes: Looking for db_version");
  unless ($self->{db_version} = $self->_get(vars => "DB_VERSION")) {
    if ($writable) {
      $self->{db_version} = $self->DB_VERSION;
      $self->{handles}->{vars}->db_put(DB_VERSION => $self->{db_version}) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
      $self->{handles}->{vars}->db_put(NTOKENS => 0) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
      dbg("bayes: new db, set db version %s and 0 tokens",$self->{db_version});
    } else {
      warn("bayes: vars.db not intialized: $BerkeleyDB::Error");
      $self->untie_db;
      return 0;
    }
  } elsif ($self->{db_version}) {
    dbg("bayes: found bayes db version $self->{db_version}");
    if ($self->{db_version} != $self->DB_VERSION) {
      warn("bayes: bayes db version $self->{db_version} is not able to be used, aborting: $BerkeleyDB::Error");
      $self->untie_db();
      return 0;
    }
  }

  #dbg("bayes: Opening tokens");
  unless ($self->{handles}->{tokens} = BerkeleyDB::Btree->new(
      -Env => $self->{env}, -Filename => "tokens.db",
      -Flags => $flags, -Property => DB_REVSPLITOFF)) {
    warn("bayes: couldn't open tokens.db: $BerkeleyDB::Error");
    delete $self->{handles}->{tokens};
    $self->untie_db;
    return 0;
  }

  #dbg("bayes: Opening atime secondary DB");
  unless ($self->{handles}->{atime} = BerkeleyDB::Btree->new(
      -Env => $self->{env}, -Filename => "atime.db",
      -Flags => $flags, -Property => DB_DUP|DB_DUPSORT)) {
    warn("bayes: couldn't open atime.db: $BerkeleyDB::Error");
    delete $self->{handles}->{atime};
    $self->untie_db;
    return 0;
  }

  #dbg("bayes: Opening seen DB");
  unless ($self->{handles}->{seen} = BerkeleyDB::Btree->new(
      -Env => $self->{env}, -Filename => "seen.db", -Flags => $flags)) {
    warn("bayes: couldn't open tokens.db: $BerkeleyDB::Error");
    delete $self->{handles}->{seen};
    $self->untie_db;
    return 0;
  }

  # This MUST be outside the transaction that opens the DB,
  # or it just doesn't work.  Dunno Why.
  !$self->{handles}->{tokens}->associate($self->{handles}->{atime},
                                         \&_extract_atime)
    or die "Couldn't associate DBs: $BerkeleyDB::Error";

  $self->{is_really_open} = 1;
  $self->{is_officially_open} = 1;

  dbg("bayes: _open_db done");
  return 1;
}

=head2 untie_db

public instance () untie_db ()

Description:
Closes any open db handles.  You can safely call this at any time.

=cut

sub untie_db {
  my $self = shift;

  dbg("bayes: pretend to be closing a database");
  $self->{is_writable} = 0;
  $self->{is_officially_open} = 0;

  $self->{env}->txn_checkpoint(128, 1)  if $self->{env};

  for my $handle (keys %{$self->{handles}}) {
    my $handles = $self->{handles};
    if (defined $handles && $handles->{$handle}) {
      $handles->{$handle}->db_sync == 0
        or die "Couldn't sync $handle: $BerkeleyDB::Error";
    }
  }

  return;
}

sub _close_db {
  my $self = shift;

  dbg("bayes: really closing a database");
  $self->{is_writable} = 0;
  $self->{is_really_open} = 0;
  $self->{is_officially_open} = 0;
  $self->{db_version} = undef;

  for my $handle (keys %{$self->{handles}}) {
    my $handles = $self->{handles};
    if (defined $handles && $handles->{$handle}) {
      dbg("bayes: closing database $handle");
      eval { $handles->{$handle}->db_close };  # ignoring status
    }
    delete $handles->{$handle};
  }

  delete $self->{env};
  return;
}

=head2 calculate_expire_delta

public instance (%) calculate_expire_delta (
  Integer $newest_atime, Integer $start, Integer $max_expire_mult)

Description:
This method performs a calculation on the data to determine the
optimum atime for token expiration.

=cut

sub calculate_expire_delta {
  my($self, $newest_atime, $start, $max_expire_mult) = @_;
  dbg("bayes: calculate_expire_delta starting");

  my %delta;    # use a hash since an array is going to be very sparse

  my $cursor = $self->{handles}->{atime}->db_cursor;
  $cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

  my($atime, $value) = ("", "");

  # Do the first pass, figure out atime delta by iterating over our
  # *secondary* index, avoiding the decoding overhead
  while ($cursor->c_get($atime, $value, $next) == 0) {

    # Go through from $start * 1 to $start * 512, mark how many tokens
    # we would expire
    my $age = $newest_atime - $atime;
    for (my $i = 1; $i <= $max_expire_mult; $i <<= 1) {
      if ($age >= $start * $i) {
        $delta{$i}++;
      } else {
        # If the token age is less than the expire delta, it'll be
        # less for all upcoming checks too, so abort early.
        last;
      }
    }
  }

  $cursor->c_close == 0
    or die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $cursor;

  dbg("bayes: calculate_expire_delta done");
  return %delta;
}

=head2 token_expiration

public instance (Integer, Integer,
                 Integer, Integer) token_expiration (\% $opts,
                                                     Integer $newdelta,
                                                     @ @vars)

Description:
This method performs the database specific expiration of tokens based on
the passed in C<$newdelta> and C<@vars>.

=cut

sub token_expiration {
  my($self, $opts, $newdelta, @vars) = @_;
  dbg("bayes: Entering token_expiration");

  my($kept, $deleted, $hapaxes, $lowfreq) = (0, 0, 0, 0);

  # Reset stray too-new tokens
  {
    my $cursor = $self->{handles}->{atime}->db_cursor;
    $cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

    # Grab the token for a tight RWM loop
    my($atime, $flag) = ($vars[10], DB_SET_RANGE|$rmw);
    # Find the first token eq or gt the current newest
    while ($cursor->c_pget($atime, my $token, my $value, $flag) == 0) {
      my($ts, $th, $current) = _unpack_token($value);
      $self->{handles}->{tokens}->db_put($token,
                                         _pack_token($ts, $th, $atime)) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
      # We need to adjust our flag to continue on from the first rec
      $flag = $next|$rmw;
    }

    $cursor->c_close == 0
      or die "Couldn't close cursor: $BerkeleyDB::Error";
    undef $cursor;
  }

  # Figure out how old is too old...
  my $too_old = $vars[10] - $newdelta; # tooold = newest - delta
  dbg("bayes: Too old is $too_old");

  dbg("bayes: Getting db stats");
  my $count;

  # Estimate the number of keys to be deleted
  {
    my $stats = $self->{handles}->{atime}->db_stat(DB_FAST_STAT);
    #dbg("bayes: Stats: %s", Dumper($stats));
    # Scan if we've never gotten stats before
    $stats = $self->{handles}->{atime}->db_stat if $stats->{bt_ndata} == 0;
    #dbg("bayes: Stats: %s", Dumper($stats));
    if ($self->{handles}->{atime}->db_key_range(
                            $too_old, my $less, my $equal, my $greater) == 0) {
      dbg("bayes: less is $less, equal is $equal, greater is $greater");
      $count = $stats->{bt_ndata} - $stats->{bt_ndata} * $greater;
    }
  }

  dbg("bayes: Considering deleting $vars[3], $count");

  # As long as too many tokens wouldn't be deleted
  if ($vars[3] - $count >= 100000) {

    dbg("bayes: Preparing to iterate");

    my $cursor = $self->{handles}->{atime}->db_cursor;
    $cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

    my ($atime, $oldest, $token, $value);

    $atime = 0;

    while ($cursor->c_pget($atime, $token, $value, $next) == 0) {
      # We're traversing in order, so done
      $oldest = $atime, last if $atime >= $too_old;
      dbg("bayes: Deleting record");
      $cursor->c_del;
      $deleted++;
      my($ts, $th, $atime) = _unpack_token($value);
      if ($ts + $th == 1) {
        $hapaxes++;
      } elsif ($ts < 8 && $th < 8) {
        $lowfreq++;
      }
    }

    dbg("bayes: Done with cursor");
    $cursor->c_close == 0
      or die "Couldn't close cursor: $BerkeleyDB::Error";
    undef $cursor;

    $kept = $self->_get(vars => "NTOKENS", $rmw) - $deleted;
    $self->{handles}->{vars}->db_put(NTOKENS => $kept) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE => time) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $oldest) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE_REDUCE => $deleted) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_ATIME_DELTA => $newdelta) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";

    #$self->{handles}->{atime}->compact;
    #$self->{handles}->{tokens}->compact;
    #$self->{handles}->{vars}->compact;

  } else {
    dbg("bayes: Update vars to regenerate histogram");
    # Make sure we regenerate our histogramn
    $kept = $self->_get(vars => "NTOKENS");
    $self->{handles}->{vars}->db_put(LAST_EXPIRE => time) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_ATIME_DELTA => 0) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE_REDUCE => 0) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
  }

  dbg("bayes: token_expiration done");
  return($kept, $deleted, $hapaxes, $lowfreq);
}

=head2 sync_due

public instance (Boolean) sync_due ()

Description:
This method determines if a database sync is currently required.

Unused for BDB implementation.

=cut

sub sync_due {
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
  dbg("bayes: Entering seen_get");

  my $value = $self->_get(seen => $msgid);

  return $value;
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is one
of two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my($self, $msgid, $flag) = @_;
  dbg("bayes: Entering seen_put");

  $self->{handles}->{seen}->db_put($msgid, $flag) == 0
    or die "Couldn't put record: $BerkeleyDB::Error";

  return 1;
}

=head2 seen_delete

public instance (Boolean) seen_delete (string $msgid)

Description:
This method removes C<$msgid> from the database.

=cut

sub seen_delete {
  my($self, $msgid) = @_;
  dbg("bayes: Entering seen_delete");

  my $result;

  my $status = $self->{handles}->{seen}->db_del($msgid);

  if ($status == 0) {
    $result = 1;
  } elsif ($status == DB_NOTFOUND) {
    $result = 0E0;
  } else {
    die "Couldn't delete record: $BerkeleyDB::Error";
  }

  return $result;
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

=cut

sub get_storage_variables {
  my($self) = @_;
  dbg("bayes: get_storage_variables starting");

  my @values;
  for my $token (qw{LAST_JOURNAL_SYNC NSPAM NHAM NTOKENS LAST_EXPIRE
                    OLDEST_TOKEN_AGE DB_VERSION LAST_JOURNAL_SYNC
                    LAST_ATIME_DELTA LAST_EXPIRE_REDUCE NEWEST_TOKEN_AGE}) {
    my $value = $self->_get(vars => $token);
    $value = 0 unless $value && $value =~ /\d+/;
    push @values, $value;
  }

  dbg("bayes: get_storage_variables done");
  return @values;
}

=head2 dump_tokens

public instance () dump_tokens (String $template, String $regex, Array @vars)

Description:
This method loops over all tokens, computing the probability for the token
and then printing it out according to the passed in token.

=cut

sub dump_db_toks { dump_tokens(@_) }
sub dump_tokens {
  my($self, $template, $regex, @vars) = @_;
  dbg("bayes: dump_tokens starting");

  my $cursor = $self->{handles}->{tokens}->db_cursor;
  $cursor or die "Couldn't get cursor: $BerkeleyDB::Error";
  my ($token, $value) = ("", "");
  while ($cursor->c_get($token, $value, $next) == 0) {
    next if defined $regex && $token !~ /$regex/o;
    my($ts, $th, $atime) = _unpack_token($value);
    my $prob = $self->{bayes}->_compute_prob_for_token(
                                  $token, $vars[1], $vars[2], $ts, $th) || 0.5;
    my $encoded = unpack("H*",$token);
    printf $template, $prob, $ts, $th, $atime, $encoded;
  }

  $cursor->c_close == 0
    or die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $cursor;

  dbg("bayes: dump_tokens done");
  return 1;
}

=head2 set_last_expire

public instance (Boolean) set_last_expire (Integer $time)

Description:
This method sets the last expire time.

=cut

sub set_last_expire {
  my($self, $time) = @_;
  dbg("bayes: Entering set_last_expire");
  $self->{handles}->{vars}->db_put(LAST_EXPIRE => $time) == 0
    or die "Couldn't put record: $BerkeleyDB::Error";
  return 1;
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
  my($self) = @_;
  dbg("bayes: Entering get_running_expire_tok");

  my $value = $self->_get(vars => "RUNNING_EXPIRE") || "";
  my $result;
  $result = $value if $value =~ /^\d+$/;

  dbg("bayes: get_running_expire_tok exiting with %s",
      !defined $result ? 'UNDEF' : $result);
  return $result;
}

=head2 set_running_expire_tok

public instance (String $time) set_running_expire_tok ()

Description:
This method sets the time that an expire starts running.

=cut

sub set_running_expire_tok {
  my($self) = @_;

  my $time = time;
  $self->{handles}->{vars}->db_put(RUNNING_EXPIRE => $time) == 0
   or die "Couldn't put record: $BerkeleyDB::Error";

  return $time;
}

=head2 remove_running_expire_tok

public instance (Boolean) remove_running_expire_tok ()

Description:
This method removes the row in the database that indicates that
and expire is currently running.

=cut

sub remove_running_expire_tok {
  my($self) = @_;

  my $status = $self->{handles}->{vars}->db_del("RUNNING_EXPIRE");

  my $result;

  if ($status == 0) {
    $result = 1;
  } elsif ($status == DB_NOTFOUND) {
    $result = 0E0;
  } else {
    die "Couldn't delete record: $BerkeleyDB::Error";
  }

  return $result;
}

=head2 tok_get

public instance (Integer, Integer, Integer) tok_get (String $token)

Description:
This method retrieves a specificed token (C<$token>) from the database
and returns its spam_count, ham_count and last access time.

=cut

sub tok_get {
  my($self, $token) = @_;
  dbg("bayes: Entering tok_get");
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
  #dbg("bayes: Entering tok_get_all");

  my @results = $self->_mget(tokens => \@keys);
  my @values;
  for my $token (@keys) {
    my $value = shift(@results);
    push(@values, [$token, _unpack_token($value)])  if defined $value;
  }

  dbg("bayes: tok_get_all found %d tokens out of %d search keys",
      scalar(@values), scalar(@keys));
  #dbg("bayes: tok_get_all returning with %s", Dumper(\@values));
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
  dbg("bayes: Entering tok_count_change");
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
  $newatime ||= 0;

  # No changes, just return
  return 1 unless ($dspam or $dham);

  # Collect this for updates at the end
  my $newtokens = 0;

  for my $token (keys %{$tokens}) {
    #dbg("bayes: token %s", $tokens->{$token});
    my $status = $self->{handles}->{tokens}->db_get($token => my $value, $rmw);

    if ($status == 0) {
      my ($spam, $ham, $oldatime) = _unpack_token($value);
      $spam += $dspam;
      $spam = 0 if $spam < 0;
      $ham += $dham;
      $ham = 0 if $ham < 0;
      my $newvalue = _pack_token($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
    }

    elsif ($status == DB_NOTFOUND) {
      my $spam = $dspam;
      $spam = 0 if $spam < 0;
      my $ham = $dham;
      $ham = 0 if $ham < 0;
      my $newvalue = _pack_token($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
      $newtokens++;
    }

    else {
      die "Couldn't get record: $BerkeleyDB::Error";
    }
  }

  if ($newtokens) {
    my $ntokens = $self->_get(vars => "NTOKENS", $rmw) || 0;
    $ntokens += $newtokens;
    $ntokens = 0 if $ntokens < 0;
    $self->{handles}->{vars}->db_put(NTOKENS => $ntokens) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
  }

  my $newmagic = $self->_get(vars => "NEWEST_TOKEN_AGE", $rmw) || 0;
  if ($newatime > $newmagic) {
    $self->{handles}->{vars}->db_put(NEWEST_TOKEN_AGE => $newatime) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
  }

  my $oldmagic = $self->_get(vars => "OLDEST_TOKEN_AGE", $rmw) || time;
  if ($newatime && $newatime < $oldmagic) {
    $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $newatime) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
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
  dbg("bayes: Entering nspam_nham_get");
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

  my $nspam = $self->_get(vars => "NSPAM", $rmw) || 0;
  $nspam += ($ds || 0);
  $nspam = 0 if $nspam < 0;
  $self->{handles}->{vars}->db_put(NSPAM => $nspam) == 0
    or die "Couldn't put record: $BerkeleyDB::Error";

  my $nham = $self->_get(vars => "NHAM", $rmw) || 0;
  $nham += ($dh || 0);
  $nham = 0 if $nham < 0;
  $self->{handles}->{vars}->db_put(NHAM => $nham) == 0
    or die "Couldn't put record: $BerkeleyDB::Error";

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

The assumption is that the tokens already exist in the database.

We should never be touching more than N_SIGNIFICANT_TOKENS, so we can
make some assumptions about how to handle the data (ie no need to
batch like we do in tok_get_all)

=cut

sub tok_touch_all {
  my($self, $tokens, $newatime) = @_;

  for my $token (@{$tokens}) {
    my $status = $self->{handles}->{tokens}->db_get($token => my $value, $rmw);
    if ($status == 0) {
      my ($spam, $ham, $oldatime) = _unpack_token($value);
      my $newvalue = _pack_token($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
    }

    elsif ($status == DB_NOTFOUND) {
      # Do nothing
    }

    else {
      die "Couldn't get record: $BerkeleyDB::Error";
    }
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
  my ($self) = @_;
  dbg("Running cleanup");
  return 1;
}

=head2 get_magic_re

public instance (String) get_magic_re ()

Description:
This method returns a regexp which indicates a magic token.

Unused in BDB implementation.

=cut

use constant get_magic_re => undef;

=head2 sync

public instance (Boolean) sync (\% $opts)

Description:
This method performs a sync of the database

=cut

sub sync {
  my($self, $opts) = @_;
  dbg("Running sync");
  return 1;
}

=head2 perform_upgrade

public instance (Boolean) perform_upgrade (\% $opts);

Description:
Performs an upgrade of the database from one version to another, not
currently used in this implementation.

=cut

sub perform_upgrade {
  dbg("bayes: Entering perform_upgrade");
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
  dbg("bayes: Entering clear_database");

  $self->untie_db();
  dbg("bayes: removing db.");
  my $main = $self->{bayes}->{main};
  my $path = $main->sed_path($main->{conf}->{bayes_path});
  eval {rmpath($path)};
  return 1;
}

=head2 backup_database

public instance (Boolean) backup_database ()

Description:
This method will dump the users database in a machine readable format.

=cut

sub backup_database {
  my($self) = @_;
  dbg("bayes: Entering backup_database");
  return 0 unless $self->tie_db_writable;
  my @vars = $self->get_storage_variables;

  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  my $tokens = $self->{handles}->{tokens}->db_cursor;
  $tokens or die "Couldn't get cursor: $BerkeleyDB::Error";

  my($token, $value) = ("", "");
  while ($tokens->c_get($token, $value, $next) == 0) {
    my($ts, $th, $atime) = _unpack_token($value);
    my $encoded = unpack("H*", $token);
    print "t\t$ts\t$th\t$atime\t$encoded\n";
  }

  $tokens->c_close == 0
    or die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $tokens;

  my $seen = $self->{handles}->{seen}->db_cursor;
  $seen or die "Couldn't get cursor: $BerkeleyDB::Error";

  $token = "";
  while ($seen->c_get($token, $value, $next) == 0) {
    print "s\t$token\t$value\n";
  }

  $seen->c_close == 0
    or die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $seen;

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
  dbg("bayes: Entering restore_database");

  local *DUMPFILE;
  if (!open(DUMPFILE, '<', $filename)) {
    dbg("bayes: unable to open backup file $filename: $!");
    return 0;
  }

  # This is the critical phase (moving sql around), so don't allow it
  # to be interrupted.
  local $SIG{'INT'} = 'IGNORE';
  local $SIG{'HUP'} = 'IGNORE'
    if !Mail::SpamAssassin::Util::am_running_on_windows();
  local $SIG{'TERM'} = 'IGNORE';

  unless ($self->clear_database()) {
    return 0;
  }

  # we need to go ahead close the db connection so we can then open it up
  # in a fresh state after clearing
  $self->untie_db();

  unless ($self->tie_db_writable()) {
    return 0;
  }

  my $token_count = 0;
  my $db_version;
  my $num_spam;
  my $num_ham;
  my $error_p = 0;
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
    dbg("bayes: database version must be the first line in the backup file, correct and re-run");
    return 0;
  }

  unless ($db_version == 2 || $db_version == 3) {
    warn("bayes: database version $db_version is unsupported, must be version 2 or 3");
    return 0;
  }

  my $token_error_count = 0;
  my $seen_error_count = 0;

  for ($!=0; defined($line=<DUMPFILE>); $!=0) {
    chomp($line);
    $line_count++;

    if ($line_count % 1000 == 0) {
      print STDERR "." if $showdots;
    }

    if ($line =~ /^v\s+/) {     # variable line
      my @parsed_line = split(/\s+/, $line, 3);
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
        $num_spam = $value;
      } elsif ($parsed_line[2] eq 'num_nonspam') {
        $num_ham = $value;
      } else {
        dbg("bayes: restore_database: skipping unknown line: $line");
      }
    } elsif ($line =~ /^t\s+/) { # token line
      my @parsed_line = split(/\s+/, $line, 5);
      my $spam_count = $parsed_line[1] + 0;
      my $ham_count = $parsed_line[2] + 0;
      my $atime = $parsed_line[3] + 0;
      my $token = $parsed_line[4];

      my $token_warn_p = 0;
      my @warnings;

      if ($spam_count < 0) {
        $spam_count = 0;
        push(@warnings, 'spam count < 0, resetting');
        $token_warn_p = 1;
      }
      if ($ham_count < 0) {
        $ham_count = 0;
        push(@warnings, 'ham count < 0, resetting');
        $token_warn_p = 1;
      }

      if ($spam_count == 0 && $ham_count == 0) {
        dbg("bayes: token has zero spam and ham count, skipping");
        next;
      }

      if ($atime > time()) {
        $atime = time();
        push(@warnings, 'atime > current time, resetting');
        $token_warn_p = 1;
      }

      if ($token_warn_p) {
        dbg("bayes: token (%s) has the following warnings:\n%s",
            $token, join("\n",@warnings));
      }

      if ($db_version < 3) {
        # versions < 3 use plain text tokens, so we need to convert to hash
        $token = substr(sha1($token), -5);
      } else {
        # turn unpacked binary token back into binary value
        $token = pack("H*",$token);
      }

      unless ($self->_put_token($token, $spam_count, $ham_count, $atime)) {
        dbg("bayes: error inserting token for line: $line");
        $token_error_count++;
      }
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

      unless ($self->seen_put($msgid, $flag)) {
        dbg("bayes: error inserting msgid in seen table for line: $line");
        $seen_error_count++;
      }
    } else {
      dbg("bayes: skipping unknown line: $line");
      next;
    }

    if ($token_error_count >= 20) {
      warn "bayes: encountered too many errors (20) while parsing token line, reverting to empty database and exiting\n";
      $self->clear_database();
      return 0;
    }

    if ($seen_error_count >= 20) {
      warn "bayes: encountered too many errors (20) while parsing seen lines, reverting to empty database and exiting\n";
      $self->clear_database();
      return 0;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("bayes: error reading dump file: $!")
      : die "error reading dump file: $!";
  close(DUMPFILE) or die "Can't close dump file: $!";

  print STDERR "\n" if $showdots;

  unless (defined($num_spam)) {
    dbg("bayes: unable to find num spam, please check file");
    $error_p = 1;
  }

  unless (defined($num_ham)) {
    dbg("bayes: unable to find num ham, please check file");
    $error_p = 1;
  }

  if ($error_p) {
    dbg("bayes: error(s) while attempting to load $filename, clearing database, correct and re-run");
    $self->clear_database();
    return 0;
  }

  if ($num_spam || $num_ham) {
    unless ($self->nspam_nham_change($num_spam, $num_ham)) {
      dbg("bayes: error updating num spam and num ham, clearing database");
      $self->clear_database();
      return 0;
    }
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
  #dbg("bayes: Entering db_readable");
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
  dbg("bayes: Entering db_writable");
  return $self->{is_really_open} && $self->{is_officially_open} &&
         $self->{is_writable};
}

=head2 _extract_atime

private instance () _extract_atime (String $token,
                                    String $value,
                                    String $index)

Description:
This method ensures that the database connection is properly setup and
working. If appropriate it will initialize a users bayes variables so
that they can begin using the database immediately.

=cut

sub _extract_atime {
  my ($token, $value) = @_;
  #dbg("bayes: Entering _extract_atime");
  my($ts, $th, $atime) = _unpack_token($value);
  #dbg("bayes: _extract_atime found $atime for $token");
  $_[2] = $atime;
  #dbg("bayes: Leaving db_writable");
  return 0;
}

=head2 _put_token

FIXME: This is rarely a good interface, because of the churn that will
often happen in the "magic" tokens.  Open-code this stuff in the
presence of loops.

=cut

sub _put_token {
  my($self, $token, $ts, $th, $atime) = @_;
  dbg("bayes: Entering _put_token");

  $ts ||= 0;
  $th ||= 0;

  dbg("bayes: $token has spam $ts, ham $th, atime $atime");

  my $value = $self->_get(tokens => $token, $rmw);

  my $exists_already = defined $value ? 1 : 0;

  dbg("bayes: $token exists: $exists_already");
  if ($ts == 0 && $th == 0) {
    return unless $exists_already; # If the token doesn't exist, just return
    my $ntokens = $self->_get(vars => "NTOKENS", $rmw);
    $self->{handles}->{vars}->db_put(NTOKENS => --$ntokens) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
    dbg("bayes: ntokens is $ntokens");

    my $status = $self->{handles}->{tokens}->db_del($token);

    $status == 0 || $status == DB_NOTFOUND
      or die "Couldn't delete record: $BerkeleyDB::Error";
    dbg("bayes: $token deleted");
  } else {
    unless ($exists_already) {
      # If the token doesn't exist, raise the token count
      my $ntokens = $self->_get(vars => "NTOKENS", $rmw);
      $self->{handles}->{vars}->db_put(NTOKENS => ++$ntokens) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
      dbg("bayes: ntokens is $ntokens");
    }

    my $newmagic = $self->_get(vars => "NEWEST_TOKEN_AGE", $rmw) || 0;
    dbg("bayes: NEWEST_TOKEN_AGE is $newmagic");

    if ($atime > $newmagic) {
      dbg("bayes: Updating NEWEST_TOKEN_AGE");
      $self->{handles}->{vars}->db_put(NEWEST_TOKEN_AGE => $atime) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
    }

    my $oldmagic = $self->_get(vars => "OLDEST_TOKEN_AGE", $rmw) || time;
    dbg("bayes: OLDEST_TOKEN_AGE is $oldmagic");
    if ($atime && $atime < $oldmagic) {
      dbg("bayes: Updating OLDEST_TOKEN_AGE to $atime");
      $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $atime) == 0
        or die "Couldn't put record: $BerkeleyDB::Error";
    }

    my $value = _pack_token($ts, $th, $atime);

    dbg("bayes: Setting $token to $value");
    dbg("bayes: Handle is $self->{handles}->{tokens}");

    $self->{handles}->{tokens}->db_put($token, $value) == 0
      or die "Couldn't put record: $BerkeleyDB::Error";
  }

  dbg("bayes: Leaving _put_token");
  return 1;
}

# token marshalling format for tokens.

# Since we may have many entries with few hits, especially thousands of hapaxes
# (1-occurrence entries), use a flexible entry format, instead of simply "2
# packed ints", to keep the memory and disk space usage down.  In my
# 18k-message test corpus, only 8.9% have >= 8 hits in either counter, so we
# can use a 1-byte representation for the other 91% of low-hitting entries
# and save masses of space.

# This looks like: XXSSSHHH (XX = format bits, SSS = 3 spam-count bits, HHH = 3
# ham-count bits).  If XX in the first byte is 11, it's packed as this 1-byte
# representation; otherwise, if XX in the first byte is 00, it's packed as
# "CLL", ie. 1 byte and 2 32-bit "longs" in perl pack format.

# Savings: roughly halves size of toks db, at the cost of a ~10% slowdown.

use constant FORMAT_FLAG        => 0xc0; # 11000000
use constant ONE_BYTE_FORMAT    => 0xc0; # 11000000
use constant TWO_LONGS_FORMAT   => 0x00; # 00000000

use constant ONE_BYTE_SSS_BITS  => 0x38; # 00111000
use constant ONE_BYTE_HHH_BITS  => 0x07; # 00000111

sub _unpack_token {
  my $value = shift || 0;

  my($packed, $ts, $th, $atime) = unpack("CVVV", $value);

  if (($packed & FORMAT_FLAG) == ONE_BYTE_FORMAT) {
    return (($packed & ONE_BYTE_SSS_BITS) >> 3,
            $packed & ONE_BYTE_HHH_BITS,
            $ts || 0);
            # The one-byte-format uses that first 32-bit long as atime
  } elsif (($packed & FORMAT_FLAG) == TWO_LONGS_FORMAT) {
    return ($ts || 0, $th || 0, $atime || 0);
  } else {
    warn "bayes: unknown packing format for bayes db, please re-learn: $packed";
    return (0, 0, 0);
  }
}

sub _pack_token {
  my($ts, $th, $atime) = @_;
  $ts ||= 0; $th ||= 0; $atime ||= 0;
  if ($ts < 8 && $th < 8) {
    return pack("CV", (ONE_BYTE_FORMAT | ($ts << 3) | $th) & 255, $atime);
  } else {
    return pack("CVVV", TWO_LONGS_FORMAT, $ts, $th, $atime);
  }
}

sub _get {
  my ($self, $table, $key, $flags) = @_;

  $flags |= 0;

  my $value = "";

  my $status = $self->{handles}->{$table}->db_get($key => $value, $flags);

  if ($status == 0) {
    return $value;
  } elsif ($status == DB_NOTFOUND) {
    return;
  } else {
    die "Couldn't get record: $BerkeleyDB::Error";
  }
}

sub _mget {
  my ($self, $table, $keys, $flags) = @_;
  my @results;

  $flags |= 0;
  my $handle = $self->{handles}->{$table};

  for my $key (@$keys) {
    my $value = "";
    my $status = $handle->db_get($key => $value, $flags);
    undef $value  if $status != 0;
    $status == 0 || $status == DB_NOTFOUND
      or die "Couldn't get record: $BerkeleyDB::Error";
    push(@results, $value);
  }
  return @results;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
