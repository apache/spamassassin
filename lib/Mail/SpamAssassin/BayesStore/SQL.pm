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

Mail::SpamAssassin::BayesStore::SQL - SQL Bayesian Storage Module Implementation

=head1 DESCRIPTION

This module implements a SQL based bayesian storage module.  It's compatible
with SQLite and possibly other standard SQL servers.

Do not use this for MySQL/MariaDB or PgSQL, they have their own specific
modules.

=cut

package Mail::SpamAssassin::BayesStore::SQL;

use strict;
use warnings;
# use bytes;
use re 'taint';
use Errno qw(EBADF);
use Digest::SHA qw(sha1);

use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;

our @ISA = qw( Mail::SpamAssassin::BayesStore );

use constant HAS_DBI => eval { require DBI; };

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::SQL) new (Mail::Spamassassin::Plugin::Bayes $bayes)

Description:
This methods creates a new instance of the Mail::SpamAssassin::BayesStore::SQL
object.  It expects to be passed an instance of the Mail::SpamAssassin:Bayes
object which is passed into the Mail::SpamAssassin::BayesStore parent object.

This method sets up the database connection and determines the username to
use in queries.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = $class->SUPER::new(@_);

  $self->{supported_db_version} = 3;
  $self->{db_writable_p} = 0;

  if (!$self->{bayes}->{conf}->{bayes_sql_dsn}) {
    dbg("bayes: invalid config, must set bayes_sql_dsn config variable\n");
    return;
  }

  $self->{_dsn} = $self->{bayes}->{conf}->{bayes_sql_dsn};
  $self->{_dbuser} = $self->{bayes}->{conf}->{bayes_sql_username};
  $self->{_dbpass} = $self->{bayes}->{conf}->{bayes_sql_password};

  $self->{_dbh} = undef;

  unless (HAS_DBI) {
    dbg("bayes: unable to connect to database: DBI module not available: $!");
  }

  if ($self->{bayes}->{conf}->{bayes_sql_override_username}) {
    $self->{_username} = $self->{bayes}->{conf}->{bayes_sql_override_username};
  }
  else {
    $self->{_username} = $self->{bayes}->{main}->{username};

    # Need to make sure that a username is set, so just in case there is
    # no username set in main, set one here.
    if (!defined $self->{_username} || $self->{_username} eq '') {
      $self->{_username} = "GLOBALBAYES";
    }
  }
  dbg("bayes: using username: ".$self->{_username});

  return $self;
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ();

Description:
This method ensures that the database connection is properly setup
and working.  If necessary it will initialize a user's bayes variables
so that they can begin using the database immediately.

=cut

sub tie_db_readonly {
  my ($self) = @_;

  return 0 unless (HAS_DBI);

  if ($self->{_dbh}) {
    # already connected, but connection has now become readonly
    $self->{db_writable_p} = 0;
    return 1;
  }

  my $main = $self->{bayes}->{main};
  my $timer_tie_ro = $main->time_method('b_tie_ro');

  $self->read_db_configs();

  return 0 unless ($self->_connect_db());

  my $db_ver = $self->_get_db_version();
  $self->{db_version} = $db_ver;
  dbg("bayes: found bayes db version ".$self->{db_version});

  if ( $db_ver != $self->DB_VERSION ) {
    warn("bayes: database version $db_ver is different than we understand (".$self->DB_VERSION."), aborting!");
    $self->untie_db();
    return 0;
  }

  unless ($self->_initialize_db(0)) {
    dbg("bayes: unable to initialize database for ".$self->{_username}." user, aborting!");
    $self->untie_db();
    return 0;
  }

  return 1;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connection is properly setup
and working. If necessary it will initialize a users bayes variables
so that they can begin using the database immediately.

=cut

sub tie_db_writable {
  my ($self) = @_;

  return 0 unless (HAS_DBI);

  if ($self->{_dbh}) {
    # already connected, but now it will be writable
    $self->{db_writable_p} = 1;
    return 1;
  }

  my $main = $self->{bayes}->{main};
  my $timer_tie_rw = $main->time_method('b_tie_rw');

  $self->read_db_configs();

  return 0 unless ($self->_connect_db());

  my $db_ver = $self->_get_db_version();
  $self->{db_version} = $db_ver;
  dbg("bayes: found bayes db version ".$self->{db_version});

  if ( $db_ver != $self->DB_VERSION ) {
    warn("bayes: database version $db_ver is different than we understand (".$self->DB_VERSION."), aborting!");
    $self->untie_db();
    return 0;
  }

  unless ($self->_initialize_db(1)) {
    dbg("bayes: unable to initialize database for ".$self->{_username}." user, aborting!");

    $self->untie_db();
    return 0;
  }

  $self->{db_writable_p} = 1;

  return 1;
}


=head2 untie_db

public instance () untie_db ()

Description:
Disconnects from an SQL server.

=cut

sub untie_db {
  my ($self) = @_;

  return unless (defined($self->{_dbh}));

  $self->{db_writable_p} = 0;

  $self->{_dbh}->disconnect();
  $self->{_dbh} = undef;
}

=head2 calculate_expire_delta

public instance (%) calculate_expire_delta (Integer $newest_atime,
                                             Integer $start,
                                             Integer $max_expire_mult)

Description:
This method performs a calculation on the data to determine the optimum
atime for token expiration.

=cut

sub calculate_expire_delta {
  my ($self, $newest_atime, $start, $max_expire_mult) = @_;

  my %delta;  # use a hash since an array is going to be very sparse

  return %delta unless (defined($self->{_dbh}));

  my $sql = "SELECT count(*)
               FROM bayes_token
              WHERE id = ?
                AND atime < ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);
    
  unless (defined($sth)) {
    dbg("bayes: calculate_expire_delta: SQL Error: ".$self->{_dbh}->errstr());
    return %delta;
  }

  for (my $i = 1; $i <= $max_expire_mult; $i<<=1) {
    my $rc = $sth->execute($self->{_userid}, $newest_atime - $start * $i);

    unless ($rc) {
      dbg("bayes: calculate_expire_delta: SQL error: ".$self->{_dbh}->errstr());
      return;
    }

    my ($count) = $sth->fetchrow_array();

    $delta{$i} = $count;
  }
  $sth->finish();

  return %delta;
}

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
    goto token_expiration_final;
  }

  my $rc = $sth->execute($self->{_userid}, $too_old);
  
  unless ($rc) {
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    $deleted = 0;
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
      goto token_expiration_final;
    }

    $deleted = ($rows eq '0E0') ? 0 : $rows;
  }

  # Update the magic tokens as appropriate
  $sql = "UPDATE bayes_vars SET token_count = token_count - ?,
                                last_expire = ?,
                                last_atime_delta = ?,
                                last_expire_reduce = ?
				WHERE id = ?";

  $rows = $self->{_dbh}->do($sql, undef, $deleted, time(), $newdelta, $deleted, $self->{_userid});

  unless (defined($rows)) {
    # Very bad, we actually deleted the tokens, but were unable to update
    # bayes_vars with the new data.
    dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
    dbg("bayes: bayes database now in inconsistent state, suggest a backup/restore");
    goto token_expiration_final;
  }

  # If we didn't remove any tokens, the oldest token age wouldn't have changed
  if ($deleted) {
    # Now let's update the oldest_token_age value, shouldn't need to worry
    # about newest_token_age. There is a slight race condition here, but the
    # chance is small that we'll insert a new token with such an old atime
    my $oldest_token_age = $self->_get_oldest_token_age();

    $sql = "UPDATE bayes_vars SET oldest_token_age = ? WHERE id = ?";

    $rows = $self->{_dbh}->do($sql, undef, $oldest_token_age, $self->{_userid});

    unless (defined($rows)) {
      # not much more we can do here, so just warn the user and bail out
      dbg("bayes: token_expiration: SQL error: ".$self->{_dbh}->errstr());
      # yeah I know it's the next thing anyway, but here in case someone adds
      # additional code below this block
      goto token_expiration_final; 
    }
  }

token_expiration_final:
  my $kept = $vars[3] - $deleted;

  $num_hapaxes = $self->_get_num_hapaxes() if ($opts->{verbose});
  $num_lowfreq = $self->_get_num_lowfreq() if ($opts->{verbose});

  # Call untie_db() first so we unlock correctly etc. first
  $self->untie_db();

  return ($kept, $deleted, $num_hapaxes, $num_lowfreq);
}

=head2 sync_due

public instance (Boolean) sync_due ()

Description:
This method determines if a database sync is currently required.

Unused for SQL based implementation.

=cut

sub sync_due {
  my ($self) = @_;

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
  my ($self, $msgid) = @_;

  return unless defined($self->{_dbh});
 
  my $sql = "SELECT flag FROM bayes_seen
              WHERE id = ?
                AND msgid = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: seen_get: SQL Error: ".$self->{_dbh}->errstr());
    return;
  }

  my $rc = $sth->execute($self->{_userid}, $msgid);
  
  unless ($rc) {
    dbg("bayes: seen_get: SQL error: ".$self->{_dbh}->errstr());
    return;
  }

  my ($flag) = $sth->fetchrow_array();

  $sth->finish();
  
  return $flag;
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
    return 0;
  }

  dbg("bayes: seen ($msgid) put");
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
    return 0;
  }

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

=cut

sub get_storage_variables {
  my ($self) = @_;
  my @values;

  return (0,0,0,0,0,0,0,0,0,0,0) unless (defined($self->{_dbh}));

  my $sql = "SELECT spam_count, ham_count, token_count, last_expire,
                    last_atime_delta, last_expire_reduce, oldest_token_age,
                    newest_token_age
               FROM bayes_vars
              WHERE id = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: get_storage_variables: SQL error: ".$self->{_dbh}->errstr());
    return (0,0,0,0,0,0,0,0,0,0,0);
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: get_storage_variables: SQL error: ".$self->{_dbh}->errstr());
    return (0,0,0,0,0,0,0,0,0,0,0);
  }

  my ($spam_count, $ham_count, $token_count,
      $last_expire, $last_atime_delta, $last_expire_reduce,
      $oldest_token_age, $newest_token_age) = $sth->fetchrow_array();

  $sth->finish();

  my $db_ver = $self->DB_VERSION;

  @values = (
             0,
             $spam_count,
             $ham_count,
             $token_count,
             $last_expire,
             $oldest_token_age,
             $db_ver,
             0, # we do not do journal syncs
             $last_atime_delta,
             $last_expire_reduce,
             $newest_token_age
             );

  return @values;
}

=head2 dump_db_toks

public instance () dump_db_toks (String $template, String $regex, Array @vars)

Description:
This method loops over all tokens, computing the probability for the token and then
printing it out according to the passed in token.

=cut

sub dump_db_toks {
  my ($self, $template, $regex, @vars) = @_;

  return unless (defined($self->{_dbh}));

  # 0/0 tokens don't count, but in theory we shouldn't have any
  my $token_select = $self->_token_select_string();

  my $sql = "SELECT $token_select, spam_count, ham_count, atime
               FROM bayes_token
              WHERE id = ?
                AND (spam_count > 0 OR ham_count > 0)";

  my $sth = $self->{_dbh}->prepare($sql);

  unless (defined($sth)) {
    dbg("bayes: dump_db_toks: SQL error: ".$self->{_dbh}->errstr());
    return;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: dump_db_toks: SQL error: ".$self->{_dbh}->errstr());
    return;
  }  

  while (my ($token, $spam_count, $ham_count, $atime) = $sth->fetchrow_array()) {
    my $prob = $self->{bayes}->_compute_prob_for_token($token, $vars[1], $vars[2],
						      $spam_count, $ham_count);
    $prob ||= 0.5;

    my $encoded_token = unpack("H*", $token);
    
    printf $template,$prob,$spam_count,$ham_count,$atime,$encoded_token
      or die "Error writing tokens: $!";
  }

  $sth->finish();

  return;
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
    return 0;
  }

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
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT max(runtime) from bayes_expire WHERE id = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: get_running_expire_tok: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: get_running_expire_tok: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($runtime) = $sth->fetchrow_array();

  $sth->finish();

  return $runtime;
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
    return;
  }

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
    return 0;
  }

  return 1;
}

=head2 tok_get

public instance (Integer, Integer, Integer) tok_get (String $token)

Description:
This method retrieves a specified token (C<$token>) from the database
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

  my $rc = $sth->execute($self->{_userid}, $token);

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
an array ref of arrays spam count, ham count and last access time.

=cut

sub tok_get_all {
  my ($self, @tokens) = @_;

  return [] unless (defined($self->{_dbh}));

  my $token_list_size = scalar(@tokens);
  dbg("bayes: tok_get_all: token count: $token_list_size");
  my @tok_results;

  my $search_index = 0;
  my $results_index = 0;
  my $bunch_end;

  my $token_select = $self->_token_select_string();

  my $multi_sql = "SELECT $token_select, spam_count, ham_count, atime
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
      my $bindcount;
      my $in_str = '(';

      $bunch_end = $search_index + $bunch_size;
      for ( ; $search_index < $bunch_end; $search_index++) {
	$in_str .= '?,';
	push(@bindings, $tokens[$search_index]);
      }
      chop $in_str;
      $in_str .= ')';

      my $dynamic_sql = $multi_sql . $in_str;

      my $sth = $self->{_dbh}->prepare($dynamic_sql);

      unless (defined($sth)) {
	dbg("bayes: tok_get_all: SQL error: ".$self->{_dbh}->errstr());
	return [];
      }

      my $rc = $sth->execute($self->{_userid}, @bindings);

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

=head2 tok_count_change

public instance (Boolean) tok_count_change (Integer $spam_count,
					    Integer $ham_count,
					    String $token,
					    String $atime)

Description:
This method takes a C<$spam_count> and C<$ham_count> and adds it to
C<$tok> along with updating C<$tok>s atime with C<$atime>.

=cut

sub tok_count_change {
  my ($self, $spam_count, $ham_count, $token, $atime) = @_;

  $atime = 0 unless defined $atime;

  $self->_put_token($token, $spam_count, $ham_count, $atime);
}

=head2 multi_tok_count_change

public instance (Boolean) multi_tok_count_change (Integer $spam_count,
 					          Integer $ham_count,
				 	          \% $tokens,
					          String $atime)

Description:
This method takes a C<$spam_count> and C<$ham_count> and adds it to all
of the tokens in the C<$tokens> hash ref along with updating each token's
atime with C<$atime>.

=cut

sub multi_tok_count_change {
  my ($self, $spam_count, $ham_count, $tokens, $atime) = @_;

  $atime = 0 unless defined $atime;

  $self->_put_tokens($tokens, $spam_count, $ham_count, $atime);
}

=head2 nspam_nham_get

public instance ($spam_count, $ham_count) nspam_nham_get ()

Description:
This method retrieves the total number of spam and the total number of
ham learned.

=cut
 
sub nspam_nham_get {
  my ($self) = @_;

  return (0,0) unless (defined($self->{_dbh}));

  my @vars = $self->get_storage_variables();

  return ($vars[1] || 0, $vars[2] || 0);
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
    return 0;
  }

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
    return 0;
  }

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
    return 0;
  }

  return 1;
}

=head2 cleanup

public instance (Boolean) cleanup ()

Description:
This method performs any cleanup necessary before moving onto the next
operation.

=cut

sub cleanup {
  my ($self) = @_;


  return 1 unless ($self->{needs_cleanup});

  # cleanup was needed, go ahead and clear the cleanup flag
  $self->{needs_cleanup} = 0;

  my $sql = "DELETE from bayes_token
              WHERE id = ?
                AND spam_count = 0
                AND ham_count = 0";

  my $toks_deleted = $self->{_dbh}->do($sql, undef, $self->{_userid});

  unless (defined($toks_deleted)) {
    dbg("bayes: cleanup: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }       

  # check to see if any tokens where deleted
  return 1 if ($toks_deleted eq '0E0');

  $sql = "UPDATE bayes_vars SET token_count = token_count - $toks_deleted
           WHERE id = ?";

  my $rows = $self->{_dbh}->do($sql, undef, $self->{_userid});

  unless (defined($rows)) {
    dbg("bayes: cleanup: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }       

  return 1;
}

=head2 get_magic_re

public instance get_magic_re (String)

Description:
This method returns a regexp which indicates a magic token.

Unused in SQL implementation.

=cut

sub get_magic_re {
  my ($self) = @_;
  undef;
}

=head2 sync

public instance (Boolean) sync (\% $opts)

Description:
This method performs a sync of the database

=cut

sub sync {
  my ($self, $opts) = @_;

  # Not used for this implementation

  return 1;
}

=head2 perform_upgrade

public instance (Boolean) perform_upgrade (\% $opts);

Description:
Performs an upgrade of the database from one version to another, not
currently used in this implementation.

=cut

sub perform_upgrade {
  my ($self) = @_;

  return 1;
}

=head2 clear_database

public instance (Boolean) clear_database ()

Description:
This method deletes all records for a particular user.

Callers should be aware that any errors returned by this method
could cause the database to be inconsistent for the given user.

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
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_seen WHERE id = ?",
			    undef,
			    $self->{_userid});
  unless (defined($rows)) {
    dbg("bayes: SQL error removing seen data: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_token WHERE id = ?",
			    undef,
			    $self->{_userid});
  unless (defined($rows)) {
    dbg("bayes: SQL error removing token data: ".$self->{_dbh}->errstr());
    return 0;
  }

  return 1;
}

=head2 backup_database

public instance (Boolean) backup_database ()

Description:
This method will dump the users database in a machine readable format.

=cut

sub backup_database {
  my ($self) = @_;

  return 0 unless ($self->tie_db_readonly());

  return 0 unless (defined($self->{_dbh}));

  my @vars = $self->get_storage_variables();

  my $num_spam = $vars[1] || 0;
  my $num_ham = $vars[2] || 0;

  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n"
                                      or die "Error writing: $!";
  print "v\t$num_spam\tnum_spam\n"    or die "Error writing: $!";
  print "v\t$num_ham\tnum_nonspam\n"  or die "Error writing: $!";

  my $token_select = $self->_token_select_string();

  my $token_sql = "SELECT spam_count, ham_count, atime, $token_select
                     FROM bayes_token
                    WHERE id = ?
                      AND (spam_count > 0 OR ham_count > 0)";

  my $seen_sql = "SELECT flag, msgid
                    FROM bayes_seen
                   WHERE id = ?";

  my $sth = $self->{_dbh}->prepare_cached($token_sql);

  unless (defined ($sth)) {
    dbg("bayes: backup_database: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: backup_database: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  while (my @values = $sth->fetchrow_array()) {
    $values[3] = unpack("H*", $values[3]);
    print "t\t" . join("\t", @values) . "\n"
      or die "Error writing: $!";
  }

  $sth->finish();

  $sth = $self->{_dbh}->prepare_cached($seen_sql);

  unless (defined ($sth)) {
    dbg("bayes: backup_database: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: backup_database: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  while (my @values = $sth->fetchrow_array()) {
    print "s\t" . join("\t",@values) . "\n"  or die "Error writing: $!";
  }

  $sth->finish();

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
    dbg("bayes: unable to open backup file $filename: $!");
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
  }
  else {
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
      print STDERR "." if ($showdots);
    }

    if ($line =~ /^v\s+/) { # variable line
      my @parsed_line = split(/\s+/, $line, 3);
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
	$num_spam = $value;
      }
      elsif ($parsed_line[2] eq 'num_nonspam') {
	$num_ham = $value;
      }
      else {
	dbg("bayes: restore_database: skipping unknown line: $line");
      }
    }
    elsif ($line =~ /^t\s+/) { # token line
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
	dbg("bayes: token ($token) has the following warnings:\n".join("\n",@warnings));
      }

      if ($db_version < 3) {
	# versions < 3 use plain text tokens, so we need to convert to hash
	$token = substr(sha1($token), -5);
      }
      else {
	# turn unpacked binary token back into binary value
	$token = pack("H*",$token);
      }

      unless ($self->_put_token($token, $spam_count, $ham_count, $atime)) {
	dbg("bayes: error inserting token for line: $line");
	$token_error_count++;
      }
      $token_count++;
    }
    elsif ($line =~ /^s\s+/) { # seen line
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
    }
    else {
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

  print STDERR "\n" if ($showdots);

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
  my ($self) = @_;

  # if there's a database handle, we can read...
  return defined $self->{_dbh};
}

=head2 db_writable

public instance (Boolean) db_writeable()

Description:
This method returns a boolean value indicating if the database is in a
writable state.

=cut

sub db_writable {
  my ($self) = @_;

  return (defined $self->{_dbh} && $self->{db_writable_p})
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
                        {'PrintError' => 0, 'AutoCommit' => 1});

  if (!$dbh) {
    dbg("bayes: unable to connect to database: ".DBI->errstr());
    return 0;
  }
  else {
    dbg("bayes: database connection established");
  }

  # SQLite PRAGMA attributes - here for tests, see bug 8033
  if ($self->{_dsn} =~ /^dbi:SQLite:.*?;(.+)/i) {
    foreach my $attr (split(/;/, $1)) {
      $dbh->do("PRAGMA $attr");
    }
  }
  
  $self->{_dbh} = $dbh;

 return 1;
}

=head2 _get_db_version

private instance (Integer) _get_db_version ()

Description:
Gets the current version of the database from the special global vars
tables.

=cut

sub _get_db_version {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  return ($self->{_db_version_cache}) if (defined($self->{_db_version_cache}));

  my $sql = "SELECT value FROM bayes_global_vars WHERE variable = 'VERSION'";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_db_version: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: _get_db_version: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($version) = $sth->fetchrow_array();

  $sth->finish();

  $self->{_db_version_cache} = $version;

  return $version;
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
    return 0;
  }

  # Now we need to figure out what id we inserted them at, in a perfect
  # world the database driver would handle this for us (ie mysql_insert_id)
  # but this is far from a perfect world, however since in theory we only
  # ever do this once it's ok to take the hit
  $rc = $sthselect->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _initialize_db: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  ($id) = $sthselect->fetchrow_array();

  $sthselect->finish();

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

  my ($existing_spam_count,
      $existing_ham_count,
      $existing_atime) = $self->tok_get($token);

  if (!$existing_atime) {

    # You can't create a new entry for a token with a negative count, so just return
    # if we are unable to find an entry.
    return 1 if ($spam_count < 0 || $ham_count < 0);

    my $sql = "INSERT INTO bayes_token
               (id, token, spam_count, ham_count, atime)
               VALUES (?,?,?,?,?)";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      return 0;
    }

    my $rc = $sth->execute($self->{_userid},
			   $token,
			   $spam_count,
			   $ham_count,
			   $atime);
    
    unless ($rc) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      return 0;
    }

    $sth->finish();

    $sql = "UPDATE bayes_vars SET token_count = token_count + 1
             WHERE id = ?";

    my $rows = $self->{_dbh}->do($sql, undef, $self->{_userid});
    
    unless (defined($rows)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      return 0;
    }

    $sql = "UPDATE bayes_vars SET newest_token_age = ?
             WHERE id = ? AND newest_token_age < ?";

    $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

    unless (defined($rows)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
      return 0;
    }

    if ($rows eq '0E0') {
      # no need to update oldest_token_age if we updated newest_token_age
      
      $sql = "UPDATE bayes_vars SET oldest_token_age = ?
               WHERE id = ? AND oldest_token_age > ?";

      $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);
      
      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }
  }
  else {

    if ($spam_count < 0 || $ham_count < 0) {
      # we only need to cleanup when we subtract counts for a token and the
      # counts may have both reached 0
      # XXX - future optimization, since we have the existing spam/ham counts
      # we can make an educated guess on if the count would reach 0, for
      # instance, if we are decreasing spam_count but spam_count is currently
      # > 1000, then there is no possible way this update or any others that
      # might currently be happening could reduce that value to 0, so there
      # would be no need to set the needs_cleanup flag
      $self->{needs_cleanup} = 1;
    }

    my $update_atime_p = 1;
    my $updated_atime_p = 0;

    # if the existing atime is already >= the one we are going to set, then
    # don't bother
    $update_atime_p = 0 if ($existing_atime >= $atime);

    # These SQL statements include as part of the WHERE clause something like
    # "AND spam_count + ? >= 0" or "AND ham_count + ? >= 0".  This is to keep
    # the count from going negative.

    if ($spam_count) {
      my $sql;
      my @args;
      if ($update_atime_p) {
	$sql = "UPDATE bayes_token
                   SET spam_count = spam_count + ?,
                       atime = ?
                 WHERE id = ?
                   AND token = ?
                   AND spam_count + ? >= 0";
	@args = ($spam_count, $atime, $self->{_userid}, $token, $spam_count);
	$updated_atime_p = 1; # note the fact that we did do it
      }
      else {
	$sql = "UPDATE bayes_token
                   SET spam_count = spam_count + ?
                 WHERE id = ?
                   AND token = ?
                   AND spam_count + ? >= 0";
	@args = ($spam_count, $self->{_userid}, $token, $spam_count);
      }

      my $rows = $self->{_dbh}->do($sql, undef, @args);

      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }

    if ($ham_count) {
      my $sql;
      my @args;
      if ($update_atime_p && !$updated_atime_p) {
	$sql = "UPDATE bayes_token
                   SET ham_count = ham_count + ?,
                       atime = ?
                 WHERE id = ?
                   AND token = ?
                   AND ham_count + ? >= 0";
	@args = ($ham_count, $atime, $self->{_userid}, $token, $ham_count);
	$updated_atime_p = 1; # note the fact that we did do it
      }
      else {
	$sql = "UPDATE bayes_token
                   SET ham_count = ham_count + ?
                 WHERE id = ?
                   AND token = ?
                   AND ham_count + ? >= 0";
	@args = ($ham_count, $self->{_userid}, $token, $ham_count);
      }

      my $rows = $self->{_dbh}->do($sql, undef, @args);

      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }

    if ($updated_atime_p) {
      # we updated the atime, so we need to check and update bayes_vars
      # we only need to worry about newest_token_age since we would have
      # only updated the atime if it was > the previous value
      my $sql = "UPDATE bayes_vars SET newest_token_age = ?
                  WHERE id = ? AND newest_token_age < ?";

      my $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }
  }

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

  my $atime_updated_p = 0;
  my $atime_inserted_p = 0;
  my $new_tokens = 0;

  my $insertsql = "INSERT INTO bayes_token
                   (id, token, spam_count, ham_count, atime)
                   VALUES (?,?,?,?,?)";

  my $insertsth = $self->{_dbh}->prepare_cached($insertsql);

  unless (defined($insertsth)) {
    dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  foreach my $token (keys %{$tokens}) {
    my ($existing_spam_count,
	$existing_ham_count,
	$existing_atime) = $self->tok_get($token);

    if (!$existing_atime) {

      # You can't create a new entry for a token with a negative count, so
      # just skip to the next one if we are unable to find an entry.
      next if ($spam_count < 0 || $ham_count < 0);


      my $rc = $insertsth->execute($self->{_userid},
				   $token,
				   $spam_count,
				   $ham_count,
				   $atime);
    
      unless ($rc) {
	dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	next;
      }

      $insertsth->finish();

      $atime_inserted_p = 1;
      $new_tokens++;
    }
    else {

      if ($spam_count < 0 || $ham_count < 0) {
	# we only need to cleanup when we subtract counts for a token and the
	# counts may have both reached 0
	# XXX - future optimization, since we have the existing spam/ham counts
	# we can make an educated guess on if the count would reach 0, for
	# instance, if we are decreasing spam_count but spam_count is currently
	# > 1000, then there is no possible way this update or any others that
	# might currently be happening could reduce that value to 0, so there
	# would be no need to set the needs_cleanup flag
	$self->{needs_cleanup} = 1;
      }

      my $update_atime_p = 1;

      # if the existing atime is already >= the one we are going to set, then
      # don't bother
      $update_atime_p = 0 if ($existing_atime >= $atime);
      
      # These SQL statements include as part of the WHERE clause something like
      # "AND spam_count + ? >= 0" or "AND ham_count + ? >= 0".  This is to keep
      # the count from going negative.
      
      if ($spam_count) {
	my $sql;
	my @args;
	if ($update_atime_p) {
	  $sql = "UPDATE bayes_token
                     SET spam_count = spam_count + ?,
                         atime = ?
                   WHERE id = ?
                     AND token = ?
                     AND spam_count + ? >= 0";
	  @args = ($spam_count, $atime, $self->{_userid}, $token, $spam_count);
	  $atime_updated_p = 1;
	}
	else {
	  $sql = "UPDATE bayes_token
                     SET spam_count = spam_count + ?
                   WHERE id = ?
                     AND token = ?
                     AND spam_count + ? >= 0";
	  @args = ($spam_count, $self->{_userid}, $token, $spam_count);
	}

	my $rows = $self->{_dbh}->do($sql, undef, @args);

	unless (defined($rows)) {
	  dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	}
      }

      if ($ham_count) {
	my $sql;
	my @args;
	# if $spam_count then we already updated the atime
	if ($update_atime_p && !$spam_count) { 
	  $sql = "UPDATE bayes_token
                     SET ham_count = ham_count + ?,
                         atime = ?
                   WHERE id = ?
                     AND token = ?
                     AND ham_count + ? >= 0";
	  @args = ($ham_count, $atime, $self->{_userid}, $token, $ham_count);
	  $atime_updated_p = 1;
	}
	else {
	  $sql = "UPDATE bayes_token
                     SET ham_count = ham_count + ?
                   WHERE id = ?
                     AND token = ?
                     AND ham_count + ? >= 0";
	  @args = ($ham_count, $self->{_userid}, $token, $ham_count);
	}
	
	my $rows = $self->{_dbh}->do($sql, undef, @args);

	unless (defined($rows)) {
	  dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
	}
      }
    }
  }

  if ($new_tokens) {
    my $sql = "UPDATE bayes_vars SET token_count = token_count + ?
                WHERE id = ?";

    my $rows = $self->{_dbh}->do($sql, undef, $new_tokens, $self->{_userid});

    unless (defined($rows)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    }
  }

  if ($atime_updated_p || $atime_inserted_p) {
    # we updated the atime, so we need to check and update bayes_vars
    # we only need to worry about newest_token_age since we would have
    # only updated the atime if it was > the previous value
    my $sql = "UPDATE bayes_vars SET newest_token_age = ?
                WHERE id = ? AND newest_token_age < ?";

    my $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

    unless (defined($rows)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    }
  }


  # If we inserted then we might need to update oldest_token_age
  # but if we already updated newest_token_age then there is no need

  if ($atime_inserted_p) {
    my $sql = "UPDATE bayes_vars SET oldest_token_age = ?
                WHERE id = ? AND oldest_token_age > ?";

    my $rows = $self->{_dbh}->do($sql, undef, $atime, $self->{_userid}, $atime);

    unless (defined($rows)) {
      dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    }
  }

  return 1;
}

=head2 _get_oldest_token_age

private instance (Integer) _get_oldest_token_age ()

Description:
This method finds the atime of the oldest token in the database.

The use of min(atime) in the SQL is ugly and but really the most efficient
way of getting the oldest_token_age after we've done a mass expire.  It should
only be called at expire time.

=cut

sub _get_oldest_token_age {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT min(atime) FROM bayes_token
              WHERE id = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_oldest_token_age: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: _get_oldest_token_age: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($atime) = $sth->fetchrow_array();

  $sth->finish();

  return $atime;
}


=head2 _get_num_hapaxes

private instance (Integer) _get_num_hapaxes ()

Description:
This method gets the total number of hapaxes (spam_count + ham_count == 1) in
the token database for a user.

=cut

sub _get_num_hapaxes {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT count(*)
               FROM bayes_token
              WHERE id = ?
                AND spam_count + ham_count = 1";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_num_hapaxes: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: _get_num_hapaxes: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  
  my ($num_hapaxes) = $sth->fetchrow_array();

  $sth->finish();

  return $num_hapaxes;
}

=head2 _get_num_lowfreq

private instance (Integer) _get_num_lowfreq ()

Description:
This method gets the total number of lowfreq tokens (spam_count < 8 and
ham_count < 8) in the token database for a user

=cut

sub _get_num_lowfreq {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT count(*)
               FROM bayes_token
              WHERE id = ?
                AND (spam_count >= 0 AND spam_count < 8)
                AND (ham_count >= 0 AND ham_count < 8)
                AND spam_count + ham_count != 1";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_num_lowfreq: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_userid});

  unless ($rc) {
    dbg("bayes: _get_num_lowfreq: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($num_lowfreq) = $sth->fetchrow_array();

  $sth->finish();

  return $num_lowfreq;
}

=head2 _token_select_string

private instance (String) _token_select_string

Description:
This method returns the string to be used in SELECT statements to represent
the token column.

The default is to use the SUBSTR function to pad the token out to 5 characters.

=cut

sub _token_select_string {
  # Use SQLite compatible RPAD alternative
  return "SUBSTR(token || '     ', 1, 5)";
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
