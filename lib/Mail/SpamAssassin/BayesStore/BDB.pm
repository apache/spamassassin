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
use Data::Dumper;
use Digest::SHA1 qw{sha1};
use File::Basename;
use File::Path;

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
  $self->{already_tied} = 0;
  $self->{is_locked} = 0;
  return $self;
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection is properly setup and
working.  It takes 'read-only' very seriously, and will not try to
initialize anything.

=cut

sub tie_db_readonly {
  my($self) = @_;
  #dbg("BDB: tie_db_readonly");
  my $result = ($self->{already_tied} and $self->{is_locked} == 0) || $self->_tie_db(0);
  #dbg("BDB: tie_db_readonly result is $result");
  return $result;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connetion is properly setup and
working. If necessary it will initialize the database so that they can
begin using the database immediately.

=cut

sub tie_db_writable {
  my($self) = @_;
  #dbg("BDB: tie_db_writable");
  my $result = ($self->{already_tied} and $self->{is_locked} == 1) || $self->_tie_db(1);
  #dbg("BDB: tie_db_writable result is $result");
  return $result;
}

=head2 _tie_db

private instance (Boolean) _tie_db (Boolean $writeable)

Description:
This method ensures that the database connetion is properly setup and
working.  If it will initialize a users bayes variables so that they
can begin using the database immediately.

=cut

sub _tie_db {
  my($self, $writeable) = @_;

  #dbg("BDB: _tie_db($writeable)");

  # Always notice state changes
  $self->{is_locked} = $writeable;

  return 1 if($self->{already_tied});

  #dbg("BDB: not already tied");

  my $main = $self->{bayes}->{main};

  if (!defined($main->{conf}->{bayes_path})) {
    #dbg("BDB: bayes_path not defined");
    return 0;
  }

  #dbg("BDB: Reading db configs");
  $self->read_db_configs();

  my $path = dirname $main->sed_path($main->{conf}->{bayes_path});

  #dbg("BDB: Path is $path");
  # Path must exist or we must be in writeable mode
  if (-d $path) {
    # All is cool
  } elsif ($writeable) {
    # Create the path
    eval {
      mkpath($path, 0, (oct($main->{conf}->{bayes_file_mode}) & 0777));
    };
    warn("BDB: Couldn't create path: $@") if ($@);
  } else {
    # FAIL
    warn("BDB: bayes_path doesn't exist and can't create: $path");
    return 0;
  }

  # Now we can set up our environment
  my $flags = DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN;
  $flags |= DB_CREATE if($writeable);
  # DB_REGISTER|DB_RECOVER|

  #dbg("BDB: Creating environment: $path, $flags, $main->{conf}->{bayes_file_mode}");
  unless ($self->{env} = BerkeleyDB::Env->new(-Cachesize => 67108864, -Home => $path, -Flags => $flags, -Mode =>(oct($main->{conf}->{bayes_file_mode}) & 0666), -SetFlags => DB_LOG_AUTOREMOVE)) {
    #dbg("BDB: berkeleydb environment couldn't initialize: $BerkeleyDB::Error");
    return 0;
  }

  $flags = $writeable ? DB_CREATE : 0;

  #dbg("BDB: Opening vars");
  unless ($self->{handles}->{vars} = BerkeleyDB::Btree->new(-Env => $self->{env}, -Filename => "vars.db", -Flags => $flags)) {
    warn("BDB: couldn't open vars.db: $BerkeleyDB::Error");
    $self->untie_db;
    return 0;
  }

  #dbg("BDB: Looking for db_version");
  unless ($self->{db_version} = $self->_get(vars => "DB_VERSION")) {
    if ($writeable) {
      $self->{db_version} = $self->DB_VERSION;
      $self->{handles}->{vars}->db_put(DB_VERSION => $self->{db_version}) and die "Couldn't put record: $BerkeleyDB::Error";
      $self->{handles}->{vars}->db_put(NTOKENS => 0) and die "Couldn't put record: $BerkeleyDB::Error";
      #dbg("BDB: new db, set db version " . $self->{db_version} . " and 0 tokens");
    } else {
      warn("BDB: vars.db not intialized: $BerkeleyDB::Error");
      $self->untie_db;
      return 0;
    }
  } elsif ($self->{db_version}) {
    #dbg("BDB: found bayes db version $self->{db_version}");
    if ($self->{db_version} != $self->DB_VERSION) {
      warn("BDB: bayes db version $self->{db_version} is not able to be used, aborting: $BerkeleyDB::Error");
      $self->untie_db();
      return 0;
    }
  }

  #dbg("BDB: Opening tokens");
  unless ($self->{handles}->{tokens} = BerkeleyDB::Btree->new(-Env => $self->{env}, -Filename => "tokens.db", -Flags => $flags, -Property => DB_REVSPLITOFF)) {
    warn("BDB: couldn't open tokens.db: $BerkeleyDB::Error");
    $self->untie_db;
    return 0;
  }

  #dbg("BDB: Opening atime secondary DB");
  unless ($self->{handles}->{atime} = BerkeleyDB::Btree->new(-Env => $self->{env}, -Filename => "atime.db", -Flags => $flags, -Property => DB_DUP|DB_DUPSORT)) {
    warn("BDB: couldn't open atime.db: $BerkeleyDB::Error");
    $self->untie_db;
    return 0;
  }

  #dbg("BDB: Opening seen DB");
  unless ($self->{handles}->{seen} = BerkeleyDB::Btree->new(-Env => $self->{env}, -Filename => "seen.db", -Flags => $flags)) {
    warn("BDB: couldn't open tokens.db: $BerkeleyDB::Error");
    $self->untie_db;
    return 0;
  }

  # This MUST be outside the transaction that opens the DB, or it just doesn't work.  Dunno Why.
  $self->{handles}->{tokens}->associate($self->{handles}->{atime}, \&_extract_atime) and die "Couldn't associate DBs: $BerkeleyDB::Error";

  $self->{already_tied} = 1;

  return 1;
}

=head2 untie_db

public instance () untie_db ()

Description:
Closes any open db handles.  You can safely call this at any time.

=cut

sub untie_db {
  my $self = shift;

  $self->{is_locked} = 0;
  $self->{already_tied} = 0;
  $self->{db_version} = undef;

  for my $handle (keys %{$self->{handles}}) {
    # Since we are using transactions, this should be fine
    $self->{handles}->{$handle}->db_close (DB_NOSYNC);
    delete $self->{handles}->{$handle};
  }

  $self->{env}->txn_checkpoint (128, 1) if $self->{env};

  delete $self->{env};
  return undef;
}

=head2 calculate_expire_delta

public instance (%) calculate_expire_delta (Integer $newest_atime,
                                            Integer $start,
                                            Integer $max_expire_mult)

Description:
This method performs a calculation on the data to determine the
optimum atime for token expiration.

=cut

sub calculate_expire_delta {
  #dbg("BDB: calculate_expire_delta starting");
  my($self, $newest_atime, $start, $max_expire_mult) = @_;

  my %delta;    # use a hash since an array is going to be very sparse

  my $cursor = $self->{handles}->{atime}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

  my($atime, $value) = ("", "");

  # Do the first pass, figure out atime delta by iterating over our
  # *secondary* index, avoiding the decoding overhead
  while ($cursor->c_get($atime, $value, $next) == 0) {

    # Go through from $start * 1 to $start * 512, mark how many tokens we would expire
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

  $cursor->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $cursor;

  #dbg("BDB: calculate_expire_delta done");
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
  #dbg("BDB: Entering token_expiration");
  my($self, $opts, $newdelta, @vars) = @_;

  my($kept, $deleted, $hapaxes, $lowfreq) = (0, 0, 0, 0);

  # Reset stray too-new tokens
  {
    my $cursor = $self->{handles}->{atime}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

    # Grab the token for a tight RWM loop
    my($atime, $flag) = ($vars[10], DB_SET_RANGE|$rmw);
    # Find the first token eq or gt the current newest
    while ($cursor->c_pget($atime, my $token, my $value, $flag) == 0) {
      my($ts, $th, $current) = _unpack_token($value);
      $self->{handles}->{tokens}->db_put($token, _pack_token($ts, $th, $atime)) and die "Couldn't put record: $BerkeleyDB::Error";
      $flag = $next|$rmw; # We need to adjust our flag to continue on from the first rec
    }

    $cursor->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
    undef $cursor;
  }

  # Figure out how old is too old...
  my $too_old = $vars[10] - $newdelta; # tooold = newest - delta
  #dbg("BDB: Too old is $too_old");

  #dbg("BDB: Getting db stats");
  my $count;

  # Estimate the number of keys to be deleted
  {
    my $stats = $self->{handles}->{atime}->db_stat(DB_FAST_STAT);
    #dbg("DBD: Stats: " . Dumper $stats);
    # Scan if we've never gotten stats before 
    $stats = $self->{handles}->{atime}->db_stat if($stats->{bt_ndata} == 0);
    #dbg("DBD: Stats: " . Dumper $stats);
    if ($self->{handles}->{atime}->db_key_range($too_old, my $less, my $equal, my $greater) == 0) {
      #dbg("DBD: less is $less, equal is $equal, greater is $greater");
      $count = $stats->{bt_ndata} - $stats->{bt_ndata} * $greater;
    }
  }

  #dbg("BDB: Considering deleting $vars[3], $count");

  # As long as too many tokens wouldn't be deleted
  if ($vars[3] - $count >= 100000) {

    #dbg("BDB: Preparing to iterate");

    my $cursor = $self->{handles}->{atime}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

    my ($atime, $oldest, $token, $value);

    $atime = 0;

    while ($cursor->c_pget($atime, $token, $value, $next) == 0) {
      # We're traversing in order, so done
      $oldest = $atime, last if($atime >= $too_old);
      #dbg("BDB: Deleting record");
      $cursor->c_del;
      $deleted++;
      my($ts, $th, $atime) = _unpack_token($value);
      if ($ts + $th == 1) {
        $hapaxes++;
      } elsif ($ts < 8 && $th < 8) {
        $lowfreq++;
      }
    }

    #dbg("BDB: Done with cursor");
    $cursor->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
    undef $cursor;

    $kept = $self->_get (vars => "NTOKENS", $rmw) - $deleted;
    $self->{handles}->{vars}->db_put(NTOKENS => $kept) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE => time) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $oldest) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE_REDUCE =>  $deleted) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_ATIME_DELTA => $newdelta) and die "Couldn't put record: $BerkeleyDB::Error";

    #$self->{handles}->{atime}->compact;
    #$self->{handles}->{tokens}->compact;
    #$self->{handles}->{vars}->compact;

  } else {
    #dbg("BDB: Update vars to regenerate histogram");
    # Make sure we regenerate our histogramn
    $kept = $self->_get(vars => "NTOKENS");
    $self->{handles}->{vars}->db_put(LAST_EXPIRE => time) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_ATIME_DELTA => 0) and die "Couldn't put record: $BerkeleyDB::Error";
    $self->{handles}->{vars}->db_put(LAST_EXPIRE_REDUCE => 0) and die "Couldn't put record: $BerkeleyDB::Error";
  }

  #dbg("BDB: token_expiration done");
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
This method retrieves the stored value, if any, for C<$msgid>.  The return value
is the stored string ('s' for spam and 'h' for ham) or undef if C<$msgid> is not
found.

=cut

sub seen_get {
  #dbg("BDB: Entering seen_get");
  my($self, $msgid) = @_;

  my $value = $self->_get(seen => $msgid);

  return $value;
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is one of
two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  #dbg("BDB: Entering seen_put");
  my($self, $msgid, $flag) = @_;

  $self->{handles}->{seen}->db_put($msgid, $flag) and die "Couldn't put record: $BerkeleyDB::Error";

  return 1;
}

=head2 seen_delete

public instance (Boolean) seen_delete (string $msgid)

Description:
This method removes C<$msgid> from the database.

=cut

sub seen_delete {
  #dbg("BDB: Entering seen_delete");
  my($self, $msgid) = @_;

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
  #dbg("BDB: get_storage_variables starting");
  my($self) = @_;

  my @values;
  for my $token (qw{LAST_JOURNAL_SYNC NSPAM NHAM NTOKENS LAST_EXPIRE OLDEST_TOKEN_AGE DB_VERSION LAST_JOURNAL_SYNC LAST_ATIME_DELTA LAST_EXPIRE_REDUCE NEWEST_TOKEN_AGE}) {
    my $value = $self->_get (vars => $token);
    $value = 0 unless($value and $value =~ /\d+/);
    push @values, $value;
  }

  #dbg("BDB: get_storage_variables done");
  return @values;
}

=head2 dump_tokens

public instance () dump_tokens (String $template, String $regex, Array @vars)

Description:
This method loops over all tokens, computing the probability for the token and then
printing it out according to the passed in token.

=cut

sub dump_tokens {
  #dbg("BDB: dump_tokens starting");
  my($self, $template, $regex, @vars) = @_;

  my $cursor = $self->{handles}->{tokens}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";
  my ($token, $value) = ("", "");
  while ($cursor->c_get($token, $value, $next) == 0) {
    next if(defined $regex && ($token !~ /$regex/o));
    my($ts, $th, $atime) = _unpack_token($value);
    my $prob = $self->{bayes}->compute_prob_for_token($token, $vars[1], $vars[2], $ts, $th) || 0.5;
    my $encoded = unpack("H*",$token);
    printf $template, $prob, $ts, $th, $atime, $encoded;
  }

  $cursor->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $cursor;

  #dbg("BDB: dump_tokens done");
  return 1;
}

=head2 set_last_expire

public instance (Boolean) set_last_expire (Integer $time)

Description:
This method sets the last expire time.

=cut

sub set_last_expire {
  #dbg("BDB: Entering set_last_expire");
  my($self, $time) = @_;
  $self->{handles}->{vars}->db_put(LAST_EXPIRE => $time) and die "Couldn't put record: $BerkeleyDB::Error";
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
  #dbg("BDB: Entering get_running_expire_tok");
  my($self) = @_;

  my $value = $self->_get (vars => "RUNNING_EXPIRE") || "";
  my $result = $value if $value =~ /^\d+$/;

  #dbg("BDB: get_running_expire_tok exiting with $result");
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
  $self->{handles}->{vars}->db_put(RUNNING_EXPIRE => $time) and die "Couldn't put record: $BerkeleyDB::Error";

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
and returns it's spam_count, ham_count and last access time.

=cut

sub tok_get {
  #dbg("BDB: Entering tok_get");
  my($self, $token) = @_;
  my $array = $self->tok_get_all ([$token]);
  return !@$array ? () : @{$array->[0]};
}

=head2 tok_get_all

public instance (\@) tok_get (@ $tokens)

Description:
This method retrieves the specified tokens (C<$tokens>) from storage and returns
an array ref of arrays spam count, ham acount and last access time.

=cut

sub tok_get_all {
  #dbg("BDB: Entering tok_get_all");
  my($self, @keys) = @_;

  my @values;
  for my $token (@keys) {
    if (my $value = $self->_get(seen => $token)) {
      push(@values, [$token, _unpack_token($value)]);
    }
  }

  # #dbg("BDB: tok_get_all returning with " . Dump \@values);
  return \@values;
}

=head2 tok_count_change

public instance (Boolean) tok_count_change (Integer $dspam,
					    Integer $dham,
					    String $token,
					    String $newatime)

Description:
This method takes a C<$spam_count> and C<$ham_count> and adds it to
C<$tok> along with updating C<$tok>s atime with C<$atime>.

=cut

sub tok_count_change {
  #dbg("BDB: Entering tok_count_change");
  my($self, $dspam, $dham, $token, $newatime) = @_;
  $self->multi_tok_count_change ($dspam, $dham, {$token => 1}, $newatime);
}

=head2 multi_tok_count_change

public instance (Boolean) multi_tok_count_change (Integer $dspam,
 					          Integer $dham,
				 	          \% $tokens,
					          String $newatime)

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
    my $status = $self->{handles}->{tokens}->db_get($token => my $value, $rmw);

    if ($status == 0) {
      my ($spam, $ham, $oldatime) = _unpack_token ($value);
      $spam += $dspam;
      $spam = 0 if ($spam < 0);
      $ham += $dham;
      $ham = 0 if ($ham < 0);
      my $newvalue = _pack_token($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) and die "Couldn't put record: $BerkeleyDB::Error";
    }

    elsif ($status == DB_NOTFOUND) {
      my $spam = $dspam;
      $spam = 0 if ($spam < 0);
      my $ham = $dham;
      $ham = 0 if ($ham < 0);
      my $newvalue = _pack_token($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) and die "Couldn't put record: $BerkeleyDB::Error";
      $newtokens++;
    }

    else {
      die "Couldn't get record: $BerkeleyDB::Error";
    }
  }

  if ($newtokens) {
    my $ntokens = $self->_get(vars => "NTOKENS", $rmw) || 0;
    $ntokens += $newtokens;
    $ntokens = 0 if ($ntokens < 0);
    $self->{handles}->{vars}->db_put(NTOKENS => $ntokens) and die "Couldn't put record: $BerkeleyDB::Error";
  }

  my $newmagic = $self->_get(vars => "NEWEST_TOKEN_AGE", $rmw) || 0;
  if ($newatime > $newmagic) {
    $self->{handles}->{vars}->db_put(NEWEST_TOKEN_AGE => $newatime) and die "Couldn't put record: $BerkeleyDB::Error";
  }

  my $oldmagic = $self->_get(vars => "OLDEST_TOKEN_AGE", $rmw) || time;
  if ($newatime and $newatime < $oldmagic) {
    $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $newatime) and die "Couldn't put record: $BerkeleyDB::Error";
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
  #dbg("BDB: Entering nspam_nham_get");
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

  my $nspam = $self->_get(vars => "NSPAM", $rmw) || 0;
  $nspam += ($ds || 0);
  $nspam = 0 if ($nspam < 0);
  $self->{handles}->{vars}->db_put(NSPAM => $nspam) and die "Couldn't put record: $BerkeleyDB::Error";

  my $nham = $self->_get(vars => "NHAM", $rmw) || 0;
  $nham += ($dh || 0);
  $nham = 0 if ($nham < 0);
  $self->{handles}->{vars}->db_put(NHAM => $nham) and die "Couldn't put record: $BerkeleyDB::Error";

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
  return $self->tok_touch_all ([$token], $atime);
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
      my ($spam, $ham, $oldatime) = _unpack_token ($value);
      my $newvalue = _pack_token ($spam, $ham, $newatime);
      $self->{handles}->{tokens}->db_put($token => $newvalue) and die "Couldn't put record: $BerkeleyDB::Error";
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
This method peroms any cleanup necessary before moving onto the next
operation.

=cut

sub cleanup {
  my ($self) = @_;
  #dbg("Running cleanup");
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
  #dbg("Running sync");
  return 1;
}

=head2 perform_upgrade

public instance (Boolean) perform_upgrade (\% $opts);

Description:
Performs an upgrade of the database from one version to another, not
currently used in this implementation.

=cut

sub perform_upgrade {
  #dbg("BDB: Entering perform_upgrade");
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
  #dbg("BDB: Entering clear_database");
  my($self) = @_;

  $self->untie_db();
  #dbg("BDB: removing db.");
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
  #dbg("BDB: Entering backup_database");
  my($self) = @_;
  return 0 unless $self->tie_db_writable;
  my @vars = $self->get_storage_variables;

  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  my $tokens = $self->{handles}->{tokens}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

  my($token, $value) = ("", "");
  while ($tokens->c_get($token, $value, $next) == 0) {
    my($ts, $th, $atime) = _unpack_token($value);
    my $encoded = unpack("H*", $token);
    print "t\t$ts\t$th\t$atime\t$encoded\n";
  }

  $tokens->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
  undef $tokens;

  my $seen = $self->{handles}->{seen}->db_cursor or die "Couldn't get cursor: $BerkeleyDB::Error";

  $token = "";
  while ($seen->c_get($token, $value, $next) == 0) {
    print "s\t$token\t$value\n";
  }

  $seen->c_close and die "Couldn't close cursor: $BerkeleyDB::Error";
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
  #dbg("BDB: Entering restore_database");
  my ($self, $filename, $showdots) = @_;

  local *DUMPFILE;
  if (!open(DUMPFILE, '<', $filename)) {
    #dbg("BDB: unable to open backup file $filename: $!");
    return 0;
  }

  # This is the critical phase (moving sql around), so don't allow it
  # to be interrupted.
  local $SIG{'INT'} = 'IGNORE';
  local $SIG{'HUP'} = 'IGNORE' if (!Mail::SpamAssassin::Util::am_running_on_windows());
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
    #dbg("BDB: database version must be the first line in the backup file, correct and re-run");
    return 0;
  }

  unless ($db_version == 2 || $db_version == 3) {
    warn("BDB: database version $db_version is unsupported, must be version 2 or 3");
    return 0;
  }

  my $token_error_count = 0;
  my $seen_error_count = 0;

  for ($!=0; defined($line=<DUMPFILE>); $!=0) {
    chomp($line);
    $line_count++;

    if ($line_count % 1000 == 0) {
      print STDERR "." if ($showdots);
    }

    if ($line =~ /^v\s+/) {     # variable line
      my @parsed_line = split(/\s+/, $line, 3);
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
	$num_spam = $value;
      } elsif ($parsed_line[2] eq 'num_nonspam') {
	$num_ham = $value;
      } else {
	#dbg("BDB: restore_database: skipping unknown line: $line");
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
	#dbg("BDB: token has zero spam and ham count, skipping");
	next;
      }

      if ($atime > time()) {
	$atime = time();
	push(@warnings, 'atime > current time, resetting');
	$token_warn_p = 1;
      }

      if ($token_warn_p) {
	#dbg("BDB: token ($token) has the following warnings:\n".join("\n",@warnings));
      }

      if ($db_version < 3) {
	# versions < 3 use plain text tokens, so we need to convert to hash
	$token = substr(sha1($token), -5);
      } else {
	# turn unpacked binary token back into binary value
	$token = pack("H*",$token);
      }

      unless ($self->_put_token($token, $spam_count, $ham_count, $atime)) {
	#dbg("BDB: error inserting token for line: $line");
	$token_error_count++;
      }
      $token_count++;
    } elsif ($line =~ /^s\s+/) { # seen line
      my @parsed_line = split(/\s+/, $line, 3);
      my $flag = $parsed_line[1];
      my $msgid = $parsed_line[2];

      unless ($flag eq 'h' || $flag eq 's') {
	#dbg("BDB: unknown seen flag ($flag) for line: $line, skipping");
	next;
      }

      unless ($msgid) {
	#dbg("BDB: blank msgid for line: $line, skipping");
	next;
      }

      unless ($self->seen_put($msgid, $flag)) {
	#dbg("BDB: error inserting msgid in seen table for line: $line");
	$seen_error_count++;
      }
    } else {
      #dbg("BDB: skipping unknown line: $line");
      next;
    }

    if ($token_error_count >= 20) {
      warn "BDB: encountered too many errors (20) while parsing token line, reverting to empty database and exiting\n";
      $self->clear_database();
      return 0;
    }

    if ($seen_error_count >= 20) {
      warn "BDB: encountered too many errors (20) while parsing seen lines, reverting to empty database and exiting\n";
      $self->clear_database();
      return 0;
    }
  }
  defined $line || $!==0  or
    $!==EBADF ? dbg("BDB: error reading dump file: $!")
      : die "error reading dump file: $!";
  close(DUMPFILE) or die "Can't close dump file: $!";

  print STDERR "\n" if ($showdots);

  unless (defined($num_spam)) {
    #dbg("BDB: unable to find num spam, please check file");
    $error_p = 1;
  }

  unless (defined($num_ham)) {
    #dbg("BDB: unable to find num ham, please check file");
    $error_p = 1;
  }

  if ($error_p) {
    #dbg("BDB: error(s) while attempting to load $filename, clearing database, correct and re-run");
    $self->clear_database();
    return 0;
  }

  if ($num_spam || $num_ham) {
    unless ($self->nspam_nham_change($num_spam, $num_ham)) {
      #dbg("BDB: error updating num spam and num ham, clearing database");
      $self->clear_database();
      return 0;
    }
  }

  #dbg("BDB: parsed $line_count lines");
  #dbg("BDB: created database with $token_count tokens based on $num_spam spam messages and $num_ham ham messages");

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
  #dbg("BDB: Entering db_readable");
  my($self) = @_;
  return $self->{already_tied};
}

=head2 db_writable

public instance (Boolean) db_writeable()

Description:
This method returns a boolean value indicating if the database is in a
writable state.

=cut

sub db_writable {
  #dbg("BDB: Entering db_writeable");
  my($self) = @_;
  return($self->{already_tied} and $self->{is_locked});
}

=head2 _extract_atime

private instance () _extract_atime (String $token,
                                    String $value,
                                    String $index)

Description:
This method ensures that the database connetion is properly setup and
working. If appropriate it will initialize a users bayes variables so
that they can begin using the database immediately.

=cut

sub _extract_atime {
  #dbg("BDB: Entering _extract_atime");
  my ($token, $value) = @_;
  my($ts, $th, $atime) = _unpack_token($value);
  #dbg("BDB: _extract_atime found $atime for $token");
  $_[2] = $atime;
  #dbg("BDB: Leaving db_writeable");
  return 0;
}

=head2 _put_token

FIXME: This is rarely a good interface, because of the churn that will
often happen in the "magic" tokens.  Open-code this stuff in the
presence of loops.

=cut

sub _put_token {
  #dbg("BDB: Entering _put_token");
  my($self, $token, $ts, $th, $atime) = @_;

  $ts ||= 0;
  $th ||= 0;

  #dbg("BDB: $token has spam $ts, ham $th, atime $atime");

  my $value = $self->_get(tokens => $token, $rmw);

  my $exists_already = defined $value ? 1 : 0;

  #dbg("BDB: $token exists: $exists_already");
  if ($ts == 0 && $th == 0) {
    return unless($exists_already); # If the token doesn't exist, just return
    my $ntokens = $self->_get(vars => "NTOKENS", $rmw);
    $self->{handles}->{vars}->db_put(NTOKENS => --$ntokens) and die "Couldn't put record: $BerkeleyDB::Error";
    #dbg("BDB: ntokens is $ntokens");

    my $status = $self->{handles}->{tokens}->db_del($token);

    die "Couldn't delete record: $BerkeleyDB::Error" unless ($status == 0 or $status == DB_NOTFOUND);
    #dbg("BDB: $token deleted");
  } else {
    unless($exists_already) { # If the token doesn't exist, raise the token count
      my $ntokens = $self->_get(vars => "NTOKENS", $rmw);
      $self->{handles}->{vars}->db_put(NTOKENS => ++$ntokens) and die "Couldn't put record: $BerkeleyDB::Error";
      #dbg("BDB: ntokens is $ntokens");
    }

    my $newmagic = $self->_get(vars => "NEWEST_TOKEN_AGE", $rmw) || 0;
    #dbg("BDB: NEWEST_TOKEN_AGE is $newmagic");

    if ($atime > $newmagic) {
      #dbg("BDB: Updating NEWEST_TOKEN_AGE");
      $self->{handles}->{vars}->db_put(NEWEST_TOKEN_AGE => $atime) and die "Couldn't put record: $BerkeleyDB::Error";
    }

    my $oldmagic = $self->_get(vars => "OLDEST_TOKEN_AGE", $rmw) || time;
    #dbg("BDB: OLDEST_TOKEN_AGE is $oldmagic");
    if ($atime and $atime < $oldmagic) {
      #dbg("BDB: Updating OLDEST_TOKEN_AGE to $atime");
      $self->{handles}->{vars}->db_put(OLDEST_TOKEN_AGE => $atime) and die "Couldn't put record: $BerkeleyDB::Error";
    }

    my $value = _pack_token($ts, $th, $atime);

    #dbg("BDB: Setting $token to $value");
    #dbg("BDB: Handle is $self->{handles}->{tokens}");

    $self->{handles}->{tokens}->db_put($token, $value) and die "Couldn't put record: $BerkeleyDB::Error";
  }

  #dbg("BDB: Leaving _put_token");
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

use constant FORMAT_FLAG	=> 0xc0; # 11000000
use constant ONE_BYTE_FORMAT	=> 0xc0; # 11000000
use constant TWO_LONGS_FORMAT	=> 0x00; # 00000000

use constant ONE_BYTE_SSS_BITS	=> 0x38; # 00111000
use constant ONE_BYTE_HHH_BITS	=> 0x07; # 00000111

sub _unpack_token {
  my $value = shift || 0;

  my($packed, $ts, $th, $atime) = unpack("CVVV", $value);

  if (($packed & FORMAT_FLAG) == ONE_BYTE_FORMAT) {
    return (($packed & ONE_BYTE_SSS_BITS) >> 3,
            $packed & ONE_BYTE_HHH_BITS,
            $ts || 0); # The one-byte-format uses that first 32-bit long as atime
  } elsif (($packed & FORMAT_FLAG) == TWO_LONGS_FORMAT) {
    return ($ts || 0, $th || 0, $atime || 0);
  } else {
    warn "BDB: unknown packing format for bayes db, please re-learn: $packed";
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
    return undef;
  } else {
    die "Couldn't get record: $BerkeleyDB::Error";
  }
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
