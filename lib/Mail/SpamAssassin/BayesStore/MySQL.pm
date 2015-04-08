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

Mail::SpamAssassin::BayesStore::MySQL - MySQL Specific Bayesian Storage Module Implementation

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implements a MySQL specific based bayesian storage module.  It
requires that you are running at least version 4.1 of MySQL, if you are running
a version of MySQL < 4.1 then several aspects of this module will fail and
possibly corrupt your bayes database data.

In addition, this module will support rollback on error, if you are
using the InnoDB database table type in MySQL.  For more information
please review the instructions in sql/README.bayes.

=cut

package Mail::SpamAssassin::BayesStore::MySQL;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::BayesStore::SQL;
use Mail::SpamAssassin::Logger;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore::SQL );

use constant HAS_DBI => eval { require DBI; };

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

    $deleted = ($rows eq '0E0') ? 0 : $rows;
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
             VALUES (?,?,?)
	     ON DUPLICATE KEY UPDATE flag=VALUES(flag)"; 

  #added ON DUPLICATE KEY UPDATE flag=VALUES(flag) per bug 5998 on 4/8/2015
  
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
    return;
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

  my $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid},
			       $token, $atime);

  unless (defined($rows)) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  # if we didn't update a row then no need to update newest_token_age
  return 1 if ($rows eq '0E0');

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

  my @bindings = ($atime, $self->{_userid});
  foreach my $token (@{$tokens}) {
    $sql .= "?,";
    push(@bindings, $token);
  }
  chop($sql); # get rid of trailing ,

  $sql .= ") AND atime < ?";
  push(@bindings, $atime);

  my $rows = $self->{_dbh}->do($sql, undef, @bindings);

  unless (defined($rows)) {
    dbg("bayes: tok_touch_all: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  # if we didn't update a row then no need to update newest_token_age
  return 1 if ($rows eq '0E0');

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

=head2 cleanup

public instance (Boolean) cleanup ()

Description:
This method perfoms any cleanup necessary before moving onto the next
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

=head2 _initialize_db

private instance (Boolean) _initialize_db ()

Description:
This method will check to see if a user has had their bayes variables
initialized. If not then it will perform this initialization.

=cut

sub _initialize_db {
  my ($self, $create_entry_p) = @_;

  return 0 if !defined $self->{_dbh};
  return 0 if !defined $self->{_username} || $self->{_username} eq '';

  # Check to see if we should call the services_authorized_for_username plugin
  # hook to see if this user is allowed/able to use bayes.  If not, do nothing
  # and return 0.
  if ($self->{bayes}->{conf}->{bayes_sql_username_authorized}) {
    my $services = { 'bayessql' => 0 };
    $self->{bayes}->{main}->call_plugins("services_allowed_for_username",
					 { services => $services,
					   username => $self->{_username},
					   conf => $self->{bayes}->{conf},
					 });
    
    unless ($services->{bayessql}) {
      dbg("bayes: username not allowed by services_allowed_for_username plugin call");
      return 0;
    }
  }

  my $sqlselect = "SELECT id FROM bayes_vars WHERE username = ?";

  my $sthselect = $self->{_dbh}->prepare_cached($sqlselect);

  unless (defined($sthselect)) {
    dbg("bayes: _initialize_db: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sthselect->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _initialize_db: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($id) = $sthselect->fetchrow_array();

  if ($id) {
    $self->{_userid} = $id;
    dbg("bayes: Using userid: ".$self->{_userid});
    $sthselect->finish();
    return 1;
  }

  # Do not create an entry for this user unless we were specifically asked to
  return 0 unless ($create_entry_p);

  # For now let the database setup the other variables as defaults
  my $sqlinsert = "INSERT INTO bayes_vars (username) VALUES (?)";

  my $rows = $self->{_dbh}->do($sqlinsert,
			       undef,
			       $self->{_username});
  unless (defined($rows)) {
    dbg("bayes: _initialize_db: SQL error: ".$self->{_dbh}->errstr());
    $self->{_dbh}->rollback();
    return 0;
  }

  $id = $self->{_dbh}->{'mysql_insertid'};

  $self->{_dbh}->commit();

  if ($id) {
    $self->{_userid} = $id;
    dbg("bayes: using userid: ".$self->{_userid});
    return 1;
  }

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

  # the case where spam_count of ham_count is < 0 is special, it assumes
  # that there already exists a token (although there might actually not be
  # be one) that will be updated.  So we just do the update, being careful
  # to not allow the spam_count or ham_count to not drop below 0
  # In addition, when lowering the spam_count or ham_count we will not be
  # updating the atime value
  if ($spam_count < 0 || $ham_count < 0) {
    # we only need to cleanup when we subtract counts for a token and the
    # counts may have both reached 0
    $self->{needs_cleanup} = 1;

    my $sql = "UPDATE bayes_token SET spam_count = GREATEST(spam_count + ?, 0),
                                      ham_count = GREATEST(ham_count + ?, 0)
                WHERE id = ?
                  AND token = ?";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }

    my $rc = $sth->execute($spam_count,
			   $ham_count,
			   $self->{_userid},
			   $token);

    unless ($rc) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }
  }
  else {
    my $sql = "INSERT INTO bayes_token
               (id, token, spam_count, ham_count, atime)
               VALUES (?,?,?,?,?)
               ON DUPLICATE KEY UPDATE spam_count = GREATEST(spam_count + ?, 0),
                                       ham_count = GREATEST(ham_count + ?, 0),
                                       atime = GREATEST(atime, ?)";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }

    my $rc = $sth->execute($self->{_userid},
			   $token,
			   $spam_count,
			   $ham_count,
			   $atime,
			   $spam_count,
			   $ham_count,
			   $atime);

    unless ($rc) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }

    # With ON DUPLICATE KEY UPDATE, the affected-rows value per row is 1 if
    # the row is inserted as a new row and 2 if an existing row is updated.
    #
    # Due to a MySQL server bug a value of 3 can be seen.
    # See: http://bugs.mysql.com/bug.php?id=46675
    #   When executing the INSERT ... ON DUPLICATE KEY UPDATE statement
    #   and checking the rows return count:
    #   mysql_client_found_rows = 0: The second INSERT returns a row count
    #                                of 2 in all MySQL versions.
    #   mysql_client_found_rows = 1: The second INSERT returns this row count:
    #     Before MySQL 5.1.20: 2
    #     MySQL 5.1.20: undef on Mac OS X, 139775481 on Linux (garbage?)
    #     MySQL 5.1.21 and up: 3
    #
    my $num_rows = $rc;

    $sth->finish();

    if ($num_rows == 1 || $num_rows == 2 || $num_rows == 3) {
      my $token_count_update = '';
      
      $token_count_update = "token_count = token_count + 1," if $num_rows == 1;
      $sql = "UPDATE bayes_vars SET
                     $token_count_update
                     newest_token_age = GREATEST(newest_token_age, ?),
                     oldest_token_age = LEAST(oldest_token_age, ?)
               WHERE id = ?";

      $sth = $self->{_dbh}->prepare_cached($sql);

      unless (defined($sth)) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	$self->{_dbh}->rollback();
	return 0;
      }

      my $rc = $sth->execute($atime, $atime, $self->{_userid});

      unless ($rc) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	$self->{_dbh}->rollback();
	return 0;
      }
    }
    else {
      # $num_rows was not what we expected
      my $token_displ = $token;
      $token_displ =~ s/(.)/sprintf('%02x',ord($1))/egs;
      dbg("bayes: _put_token: Updated an unexpected number of rows: %s, ".
          "id: %s, token (hex): %s",
          $num_rows, $self->{_userid}, $token_displ);
      $self->{_dbh}->rollback();
      return 0;
    }
  }

  $self->{_dbh}->commit();
  return 1;
}

=head2 _put_tokens

private instance (Boolean) _put_tokens (\% $tokens,
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

  # the case where spam_count of ham_count is < 0 is special, it assumes
  # that there already exists a token (although there might actually not be
  # be one) that will be updated.  So we just do the update, being careful
  # to not allow the spam_count or ham_count to not drop below 0
  # In addition, when lowering the spam_count or ham_count we will not be
  # updating the atime value
  if ($spam_count < 0 || $ham_count < 0) {
    # we only need to cleanup when we subtract counts for a token and the
    # counts may have both reached 0
    $self->{needs_cleanup} = 1;

    my $sql = "UPDATE bayes_token SET spam_count = GREATEST(spam_count + ?, 0),
                                      ham_count = GREATEST(ham_count + ?, 0)
                WHERE id = ?
                  AND token = ?";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }

    my $error_p = 0;
    foreach my $token (keys %{$tokens}) {
      my $rc = $sth->execute($spam_count,
			     $ham_count,
			     $self->{_userid},
			     $token);

      unless ($rc) {
	dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
	$error_p = 1;
      }
    }

    $sth->finish();

    if ($error_p) {
      $self->{_dbh}->rollback();
      return 0;
    }
  }
  else {
    my $sql = "INSERT INTO bayes_token
               (id, token, spam_count, ham_count, atime)
               VALUES (?,?,?,?,?)
               ON DUPLICATE KEY UPDATE spam_count = GREATEST(spam_count + ?, 0),
                                       ham_count = GREATEST(ham_count + ?, 0),
                                       atime = GREATEST(atime, ?)";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
      $self->{_dbh}->rollback();
      return 0;
    }

    my $error_p = 0;
    my $new_tokens = 0;
    my $need_atime_update_p = 0;
    foreach my $token (keys %{$tokens}) {
      my $rc = $sth->execute($self->{_userid},
			     $token,
			     $spam_count,
			     $ham_count,
			     $atime,
			     $spam_count,
			     $ham_count,
			     $atime);

      if (!$rc) {
	dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
	$error_p = 1;
      }
      else {
	my $num_rows = $rc;

        # With ON DUPLICATE KEY UPDATE, the affected-rows value per row is 1 if
        # the row is inserted as a new row and 2 if an existing row is updated.
        # But see MySQL bug (as above): http://bugs.mysql.com/bug.php?id=46675

        if ($num_rows == 1) {
          $new_tokens++;
          $need_atime_update_p = 1;
        } elsif ($num_rows == 2 || $num_rows == 3) {
          $need_atime_update_p = 1;
        } else {
          # $num_rows was not what we expected
          my $token_displ = $token;
          $token_displ =~ s/(.)/sprintf('%02x',ord($1))/egs;
          dbg("bayes: _put_tokens: Updated an unexpected number of rows: %s, ".
              "id: %s, token (hex): %s",
              $num_rows, $self->{_userid}, $token_displ);
          $error_p = 1;
        }
      }
    }

    $sth->finish();

    if ($error_p) {
      $self->{_dbh}->rollback();
      return 0;
    }

    if ($need_atime_update_p) {
      my $token_count_update = '';
      
      $token_count_update = "token_count = token_count + $new_tokens," if ($new_tokens);
      $sql = "UPDATE bayes_vars SET
                     $token_count_update
                     newest_token_age = GREATEST(newest_token_age, ?),
                     oldest_token_age = LEAST(oldest_token_age, ?)
               WHERE id = ?";

      $sth = $self->{_dbh}->prepare_cached($sql);

      unless (defined($sth)) {
	dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
	$self->{_dbh}->rollback();
	return 0;
      }

      my $rc = $sth->execute($atime, $atime, $self->{_userid});

      unless ($rc) {
	dbg("bayes: _put_tokens: SQL error: ".$self->{_dbh}->errstr());
	$self->{_dbh}->rollback();
	return 0;
      }
    }
    else {
      info("bayes: _put_tokens: no atime updates needed?  Num of tokens: %d",
           scalar keys %{$tokens});
#     $self->{_dbh}->rollback();
#     return 0;
    }
  }

  $self->{_dbh}->commit();
  return 1;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
