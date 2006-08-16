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

Mail::SpamAssassin::BayesStore::PgSQL - PostgreSQL Specific Bayesian Storage Module Implementation

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implementes a PostgresSQL specific bayesian storage module.

It subclasses Mail::SpamAssassin::BayesStore::SQL and overrides any methods
which makes SQL calls involving the token column.  Since PostgreSQL uses BYTEA
for the token column type you must make sure that the DBD driver does the proper
quoting.  You can accomplish this by binding the token column to a specific type.

=cut

package Mail::SpamAssassin::BayesStore::PgSQL;

use strict;
use warnings;
use bytes;

use Mail::SpamAssassin::BayesStore::SQL;
use Mail::SpamAssassin::Logger;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore::SQL );

use constant HAS_DBI => eval { require DBI; };

# We need this so we can import the pg_types, since this is a DBD::Pg specific module it should be ok
# YUCK! This little require/import trick is required for the rpm stuff
BEGIN { require DBD::Pg; import DBD::Pg qw(:pg_types); }

=head1 METHODS

=head2 token_expiration

public instance (Integer, Integer,
                 Integer, Integer) token_expiration(\% $opts,
                                                    Integer $newdelta,
                                                    @ @vars)

Description:
This method performs the database specific expiration of tokens based on
the passed in C<$newdelta> and C<@vars>.

=cut

sub token_expiration {
  my ($self, $opts, $newdelta, @vars) = @_;

  my $num_hapaxes;
  my $num_lowfreq;
  my $deleted;

  # Figure out how old is too old...
  my $too_old = $vars[10] - $newdelta; # tooold = newest - delta

  # if token atime > newest, reset to newest ...
  my $sql = "UPDATE bayes_token SET atime = ?
              WHERE id  = ?
                AND atime > ?";

  my $rows = $self->{_dbh}->do($sql, undef, $vars[10], $self->{_userid}, $vars[10]);

  unless (defined($rows)) {
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    $deleted = 0;
    $self->{_dbh}->rollback();
    goto token_expiration_final;
  }

  # Check to make sure the expire won't remove too many tokens
  $sql = "SELECT count(token) FROM bayes_token
           WHERE id = ?
             AND atime < ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    $deleted = 0;
    $self->{_dbh}->rollback();
    goto token_expiration_final;
  }

  my $rc = $sth->execute($self->{_userid}, $too_old);
  
  unless ($rc) {
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    $deleted = 0;
    $self->{_dbh}->rollback();
    goto token_expiration_final;
  }

  my ($count) = $sth->fetchrow_array();

  $sth->finish();

  # Sanity check: if we expired too many tokens, abort!
  if ($vars[3] - $count < 100000) {
    dbg("bayes: token expiration would expire too many tokens, aborting");
    # set these appropriately so the next expire pass does the first pass
    $deleted = 0;
    $newdelta = 0;
  }
  else {
    # Do the expire
    $sql = "DELETE from bayes_token
             WHERE id = ?
               AND atime < ?";

    $rows = $self->{_dbh}->do($sql, undef, $self->{_userid}, $too_old);

    unless (defined($rows)) {
      dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
      $deleted = 0;
      $self->{_dbh}->rollback();
      goto token_expiration_final;
    }

    $deleted = $rows;
  }

  # Update the magic tokens as appropriate
  $sql = "UPDATE bayes_vars SET token_count = token_count - ?,
                                last_expire = ?,
                                last_atime_delta = ?,
                                last_expire_reduce = ?,
                                oldest_token_age = (SELECT min(atime)
                                                      FROM bayes_token
                                                     WHERE id = ?)
				WHERE id = ?";

  $rows = $self->{_dbh}->do($sql, undef, $deleted, time(), $newdelta, $deleted, $self->{_userid}, $self->{_userid});

  unless (defined($rows)) {
    # Very bad, we actually deleted the tokens, but were unable to update
    # bayes_vars with the new data.
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    $deleted = 0;
    goto token_expiration_final;
  }

  $self->{_dbh}->commit();

token_expiration_final:
  my $kept = $vars[3] - $deleted;

  $num_hapaxes = $self->_get_num_hapaxes() if ($opts->{verbose});
  $num_lowfreq = $self->_get_num_lowfreq() if ($opts->{verbose});

  # Call untie_db() first so we unlock correctly etc. first
  $self->untie_db();

  return ($kept, $deleted, $num_hapaxes, $num_lowfreq);
}

=head2 seen_put

public (Boolean) seen_put (string $msgid, char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is one of
two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my ($self, $msgid, $flag) = @_;

  return 0 if (!$msgid);
  return 0 if (!$flag);
  
  return 0 unless (defined($self->{_dbh}));

  my $sql = "INSERT INTO bayes_seen (id, msgid, flag)
             VALUES (?,?,?)";
  
  my $rows = $self->{_dbh}->do($sql,
			       undef,
			       $self->{_userid}, $msgid, $flag);
  
  unless (defined($rows)) {
    dbg("bayes: seen_put: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  dbg("bayes: seen ($msgid) put");
  $self->{_dbh}->commit();
  return 1;
}

=head2 seen_delete

public instance (Boolean) seen_delete (string $msgid)

Description:
This method removes C<$msgid> from the database.

=cut

sub seen_delete {
  my ($self, $msgid) = @_;

  return 0 if (!$msgid);

  return 0 unless (defined($self->{_dbh}));

  my $sql = "DELETE FROM bayes_seen
              WHERE id = ?
                AND msgid = ?";
  
  my $rows = $self->{_dbh}->do($sql,
			       undef,
			       $self->{_userid}, $msgid);

  unless (defined($rows)) {
    dbg("bayes: seen_delete: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();
  return 1;
}

=head2 set_last_expire

public instance (Boolean) set_last_expire (Integer $time)

Description:
This method sets the last expire time.

=cut

sub set_last_expire {
  my ($self, $time) = @_;

  return 0 unless (defined($time));

  return 0 unless (defined($self->{_dbh}));

  my $sql = "UPDATE bayes_vars SET last_expire = ? WHERE id = ?";
 
  my $rows = $self->{_dbh}->do($sql,
			       undef,
			       $time,
			       $self->{_userid});

  unless (defined($rows)) {
    dbg("bayes: set_last_expire: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();
  return 1;
}

=head2 set_running_expire_tok

public instance (String $time) set_running_expire_tok ()

Description:
This method sets the time that an expire starts running.

=cut

sub set_running_expire_tok {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "INSERT INTO bayes_expire (id,runtime) VALUES (?,?)";

  my $time = time();

  my $rows = $self->{_dbh}->do($sql,
			       undef,
			       $self->{_userid}, $time);
  unless (defined($rows)) {
    dbg("bayes: set_running_expire_tok: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return undef;
  }

  $self->{_dbh}->commit();
  return $time;
}

=head2 remove_running_expire_tok

public instance (Boolean) remove_running_expire_tok ()

Description:
This method removes the row in the database that indicates that
and expire is currently running.

=cut

sub remove_running_expire_tok {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "DELETE from bayes_expire
              WHERE id = ?";

  my $rows = $self->{_dbh}->do($sql, undef, $self->{_userid});

  unless (defined($rows)) {
    dbg("bayes: remove_running_expire_tok: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();

  return 1;
}

=head2 tok_get

public instance (Integer, Integer, Integer) tok_get (String $token)

Description:
This method retrieves a specificed token (C<$token>) from the database
and returns it's spam_count, ham_count and last access time.

=cut

sub tok_get {
  my ($self, $token) = @_;

  return (0,0,0) unless (defined($self->{_dbh}));

  my $sql = "SELECT spam_count, ham_count, atime
               FROM bayes_token
              WHERE id = ?
                AND token = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: tok_get: SQL error: ".$self->{_dbh}->errstr());
    return (0,0,0);
  }

  $sth->bind_param(1, $self->{_userid});
  $sth->bind_param(2, $token, { pg_type => DBD::Pg::PG_BYTEA });

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: tok_get: SQL error: ".$self->{_dbh}->errstr());
    return (0,0,0);
  }

  my ($spam_count, $ham_count, $atime) = $sth->fetchrow_array();

  $sth->finish();

  $spam_count = 0 if (!$spam_count || $spam_count < 0);
  $ham_count = 0 if (!$ham_count || $ham_count < 0);
  $atime = 0 if (!$atime);

  return ($spam_count, $ham_count, $atime)
}

=head2 tok_get_all

public instance (\@) tok_get (@ $tokens)

Description:
This method retrieves the specified tokens (C<$tokens>) from storage and returns
an array ref of arrays spam count, ham acount and last access time.

=cut

sub tok_get_all {
  my ($self, @tokens) = @_;

  return [] unless (defined($self->{_dbh}));

  my $token_list_size = scalar(@tokens);
  dbg("bayes: tok_get_all: token count: $token_list_size");
  my @tok_results;

  my @bunch_sizes = (100, 50, 25, 5); # XXX - need to benchmark to tweak
  my $search_index = 0;
  my $results_index = 0;
  my $bunch_end;

  my $multi_sql = "SELECT token, spam_count, ham_count, atime
                     FROM bayes_token
                    WHERE id = ?
                      AND token IN ";

  # fetch tokens in bunches of 100 until there are <= 100 left, then just fetch the rest
  while ($token_list_size > $search_index) {
    my $bunch_size;
    if ($token_list_size - $search_index > 100) {
      $bunch_size = 100;
    }
    else {
      $bunch_size = $token_list_size - $search_index;
    }
    while ($token_list_size - $search_index >= $bunch_size) {
      my @bindings;
      my $in_str = '(';

      $bunch_end = $search_index + $bunch_size;
      for ( ; $search_index < $bunch_end; $search_index++) {
	$in_str .= '?,';
	push(@bindings, $tokens[$search_index]);
      }
      chop $in_str;
      $in_str .= ')';

      my $dynamic_sql = $multi_sql . $in_str;

      my $sth = $self->{_dbh}->prepare_cached($dynamic_sql);

      unless (defined($sth)) {
	dbg("bayes: tok_get_all: SQL error: ".$self->{_dbh}->errstr());
	return [];
      }

      my $bindcount = 1;

      $sth->bind_param($bindcount++, $self->{_userid});

      foreach my $binding (@bindings) {
	$sth->bind_param($bindcount++, $binding, { pg_type => DBD::Pg::PG_BYTEA });
      }

      my $rc = $sth->execute();

      unless ($rc) {
	dbg("bayes: tok_get_all: SQL error: ".$self->{_dbh}->errstr());
	return [];
      }

      my $results = $sth->fetchall_arrayref();

      $sth->finish();

      foreach my $result (@{$results}) {
	# Make sure that spam_count and ham_count are not negative
	$result->[1] = 0 if (!$result->[1] || $result->[1] < 0);
	$result->[2] = 0 if (!$result->[2] || $result->[2] < 0);
	# Make sure that atime has a value
	$result->[3] = 0 if (!$result->[3]);
	$tok_results[$results_index++] = $result;
      }
    }
  }

  return \@tok_results;
}

=head2 nspam_nham_change

public instance (Boolean) nspam_nham_change (Integer $num_spam,
                                             Integer $num_ham)

Description:
This method updates the number of spam and the number of ham in the database.

=cut

sub nspam_nham_change {
  my ($self, $num_spam, $num_ham) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql;
  my @bindings;

  if ($num_spam != 0 && $num_ham != 0) {
    $sql = "UPDATE bayes_vars
               SET spam_count = spam_count + ?,
                   ham_count = ham_count + ?
             WHERE id = ?";
    @bindings = ($num_spam, $num_ham, $self->{_userid});
  }
  elsif ($num_spam != 0) {
    $sql = "UPDATE bayes_vars
              SET spam_count = spam_count + ?
             WHERE id = ?";
    @bindings = ($num_spam, $self->{_userid});
  }
  elsif ($num_ham != 0) {
    $sql = "UPDATE bayes_vars
               SET ham_count = ham_count + ?
            WHERE id = ?";
    @bindings = ($num_ham, $self->{_userid});
  }
  else {
    # For some reason called with no delta, it's ok though so just return
    dbg("bayes: nspam_nham_change: Called with no delta on spam or ham");
    return 1;
  }

  my $rows = $self->{_dbh}->do($sql,
			       undef,
			       @bindings);

  unless (defined($rows)) {
    dbg("bayes: nspam_nham_change: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();
  return 1;
}

=head2 tok_touch

public instance (Boolean) tok_touch (String $token,
                                     String $atime)

Description:
This method updates the given tokens (C<$token>) atime.

The assumption is that the token already exists in the database.

=cut

sub tok_touch {
  my ($self, $token, $atime) = @_;

  return 0 unless (defined($self->{_dbh}));

  # shortcut, will only update atime for the token if the atime is less than
  # what we are updating to
  my $sql = "UPDATE bayes_token
                SET atime = ?
              WHERE id = ?
                AND token = ?
                AND atime < ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }
  
  $sth->bind_param(1, $atime);
  $sth->bind_param(2, $self->{_userid});
  $sth->bind_param(3, $token, { pg_type => DBD::Pg::PG_BYTEA });
  $sth->bind_param(4, $atime);

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $rows = $sth->rows;

  unless (defined($rows)) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  # if we didn't update a row then no need to update newest_token_age
  if ($rows eq '0E0') {
    $self->{_dbh}->commit();
    return 1;
  }

  # need to check newest_token_age
  # no need to check oldest_token_age since we would only update if the
  # atime was newer than what is in the database
  $sql = "UPDATE bayes_vars
             SET newest_token_age = ?
           WHERE id = ?
             AND newest_token_age < ?";

  $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

  unless (defined($rows)) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();

  return 1;
}

=head2 tok_touch_all

public instance (Boolean) tok_touch (\@ $tokens
                                     String $atime)

Description:
This method does a mass update of the given list of tokens C<$tokens>, if the existing token
atime is < C<$atime>.

The assumption is that the tokens already exist in the database.

We should never be touching more than N_SIGNIFICANT_TOKENS, so we can make
some assumptions about how to handle the data (ie no need to batch like we
do in tok_get_all)

=cut

sub tok_touch_all {
  my ($self, $tokens, $atime) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 1 unless (scalar(@{$tokens}));

  my $sql = "UPDATE bayes_token SET atime = ? WHERE id = ? AND token IN (";

  my @bindings;
  foreach my $token (sort @{$tokens}) {
    $sql .= "?,";
    push(@bindings, $token);
  }
  chop($sql); # get rid of trailing ,

  $sql .= ") AND atime < ?";

  $self->{_dbh}->begin_work();

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $bindcount = 1;

  $sth->bind_param($bindcount++, $atime);
  $sth->bind_param($bindcount++, $self->{_userid});

  foreach my $binding (@bindings) {
    $sth->bind_param($bindcount++, $binding, { pg_type => DBD::Pg::PG_BYTEA });
  }

  $sth->bind_param($bindcount, $atime);

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $rows = $sth->rows;

  unless (defined($rows)) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  # if we didn't update a row then no need to update newest_token_age
  if ($rows eq '0E0') {
    $self->{_dbh}->commit();
    return 1;
  }

  # need to check newest_token_age
  # no need to check oldest_token_age since we would only update if the
  # atime was newer than what is in the database
  $sql = "UPDATE bayes_vars
             SET newest_token_age = ?
           WHERE id = ?
             AND newest_token_age < ?";

  $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

  unless (defined($rows)) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();

  return 1;
}


sub tok_touch_allold {
  my ($self, $tokens, $atime) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 1 unless (scalar(@{$tokens}));

  my $tokenarray = join(",", map { '"' . _quote_bytea($_) . '"' } sort @{$tokens});

  my $sth = $self->{_dbh}->prepare("select touch_tokens($self->{_userid}, '{$tokenarray}', $atime)");

  unless (defined($sth)) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $sth->finish();

  $self->{_dbh}->commit();

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

  return 1 unless ($self->{needs_cleanup});

  # cleanup was needed, go ahead and clear the cleanup flag
  $self->{needs_cleanup} = 0;

  my $sql = "DELETE from bayes_token
              WHERE id = ?
                AND spam_count <= 0
                AND ham_count <= 0";

  my $toks_deleted = $self->{_dbh}->do($sql, undef, $self->{_userid});

  unless (defined($toks_deleted)) {
    dbg("bayes: cleanup: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }       

  # check to see if any tokens where deleted
  return 1 if ($toks_deleted eq '0E0');

  $sql = "UPDATE bayes_vars SET token_count = token_count - ? WHERE id = ?";

  my $rows = $self->{_dbh}->do($sql, undef, $toks_deleted, $self->{_userid});

  unless (defined($rows)) {
    dbg("bayes: cleanup: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }       

  $self->{_dbh}->commit();

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
  my ($self) = @_;

  # We want to open readonly first, because if they don't already have
  # a db entry, we want to avoid creating one, just to delete it in a few secs
  if ($self->tie_db_readonly()) {
    # Ok, they must have had a db entry, so now make the connection writable
    $self->tie_db_writable();
  }
  else {
    # If we were unable to create a readonly connection then they must
    # not have a db entry, so no need to clear.
    # But it should be considered a success.
    return 1;
  }

  return 0 unless (defined($self->{_dbh}));

  my $rows = $self->{_dbh}->do("DELETE FROM bayes_vars WHERE id = ?",
			       undef,
			       $self->{_userid});
  unless (defined($rows)) {
    dbg("bayes: SQL error removing user (bayes_vars) data: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_seen WHERE id = ?",
			    undef,
			    $self->{_userid});
  unless (defined($rows)) {
    dbg("bayes: SQL error removing seen data: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_token WHERE id = ?",
			    undef,
			    $self->{_userid});
  unless (defined($rows)) {
    dbg("bayes: SQL error removing token data: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $self->{_dbh}->commit();
  return 1;
}

=head1 Private Methods

=head2 _connect_db

private instance (Boolean) _connect_db ()

Description:
This method connects to the SQL database.

=cut

sub _connect_db {
  my ($self) = @_;

  $self->{_dbh} = undef;

  # Turn off PrintError and explicitly set AutoCommit to off
  my $dbh = DBI->connect($self->{_dsn}, $self->{_dbuser}, $self->{_dbpass},
			 {'PrintError' => 0, 'AutoCommit' => 0});

  if (!$dbh) {
    dbg("bayes: unable to connect to database: ".DBI->errstr());
    return 0;
  }
  else {
    dbg("bayes: database connection established");
  }

  $self->{_dbh} = $dbh;

 return 1;
}

=head2 _put_token

private instance (Boolean) _put_token (string $token,
                                       integer $spam_count,
                                       integer $ham_count,
				       string $atime)

Description:
This method performs the work of either inserting or updating a token in
the database.

=cut

sub _put_token {
  my ($self, $token, $spam_count, $ham_count, $atime) = @_;

  return 0 unless (defined($self->{_dbh}));

  $spam_count ||= 0;
  $ham_count ||= 0;

  if ($spam_count == 0 && $ham_count == 0) {
    return 1;
  }

  if ($spam_count < 0 || $ham_count < 0) {
    # we only need to cleanup when we subtract counts for a token and the
    # counts may have both reached 0
    # XXX - future optimization, since we have the existing spam/ham counts
    # we can make an educated guess on if the count would reach 0, for
    # instance, if we are decreasing spam_count but spam_count is currently
    # > 1000, then there is no possible why this update or any others that
    # might currently be happening could reduce that value to 0, so there
    # would be no need to set the needs_cleanup flag
    $self->{needs_cleanup} = 1;
  }

  my $escaped_token = _quote_bytea($token);
  my $sth = $self->{_dbh}->prepare("select put_tokens($self->{_userid},'{$escaped_token}',
                                                      $spam_count,$ham_count,$atime)");

  unless (defined($sth)) {
    dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $sth->finish();

  $self->{_dbh}->commit();

  return 1;
}


=head2 _put_tokens

private instance (Boolean) _put_tokens (\% $token,
                                        integer $spam_count,
                                        integer $ham_count,
	 			        string $atime)

Description:
This method performs the work of either inserting or updating tokens in
the database.

=cut

sub _put_tokens {
  my ($self, $tokens, $spam_count, $ham_count, $atime) = @_;

  return 0 unless (defined($self->{_dbh}));

  $spam_count ||= 0;
  $ham_count ||= 0;

  if ($spam_count == 0 && $ham_count == 0) {
    return 1;
  }

  if ($spam_count < 0 || $ham_count < 0) {
    # we only need to cleanup when we subtract counts for a token and the
    # counts may have both reached 0
    # XXX - future optimization, since we have the existing spam/ham counts
    # we can make an educated guess on if the count would reach 0, for
    # instance, if we are decreasing spam_count but spam_count is currently
    # > 1000, then there is no possible why this update or any others that
    # might currently be happening could reduce that value to 0, so there
    # would be no need to set the needs_cleanup flag
    $self->{needs_cleanup} = 1;
  }

  my $tokenarray = join(",", map { '"' . _quote_bytea($_) . '"' } sort keys %{$tokens});

  my $sth = $self->{_dbh}->prepare("select put_tokens($self->{_userid}, '{$tokenarray}',
                                                     $spam_count, $ham_count, $atime)");

  unless (defined($sth)) {
    dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $sth->finish();

  $self->{_dbh}->commit();

  return 1;
}

=head2 _token_select_string

private instance (String) _token_select_string

Description:
This method returns the string to be used in SELECT statements to represent
the token column.

=cut

sub _token_select_string {
  return "token";
}

sub _quote_bytea {
  my ($str) = @_;
  my $buf = "";
  foreach my $char (split(//,$str)) {
    my $oct = sprintf ("%lo", ord($char));
    if (length( $oct ) < 2 ) { $oct = '0' . $oct; }
    if (length( $oct ) < 3 ) { $oct = '0' . $oct; }
    $buf .= '\\\\\\\\' . $oct;
  }
  return $buf;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
