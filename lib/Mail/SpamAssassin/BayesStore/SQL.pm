# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

=head1 SYNOPSIS

=head1 DESCRIPTION

This module implementes a SQL based bayesian storage module.

=cut

package Mail::SpamAssassin::BayesStore::SQL;

use strict;
use bytes;

use Mail::SpamAssassin::BayesStore;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore );

use constant HAS_DBI => eval { require DBI; };

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore::SQL) new (Mail::Spamassassin::Bayes $bayes)

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

  $self->{supported_db_version} = 2;

  if (!$self->{bayes}->{conf}->{bayes_sql_dsn}) {
    dbg("bayes: invalid config, must set bayes_sql_dsn config variable.\n");
    return undef;
  }

  $self->{_dsn} = $self->{bayes}->{conf}->{bayes_sql_dsn};
  $self->{_dbuser} = $self->{bayes}->{conf}->{bayes_sql_username};
  $self->{_dbpass} = $self->{bayes}->{conf}->{bayes_sql_password};

  $self->{_dbh} = undef;

  unless (HAS_DBI) {
    dbg("bayes: Unable to connect to database: DBI module not available: $!");
  }

  if ($self->{bayes}->{conf}->{bayes_sql_override_username}) {
    $self->{_username} = $self->{bayes}->{conf}->{bayes_sql_override_username};
  }
  else {
    $self->{_username} = $self->{bayes}->{main}->{username};

    # Need to make sure that a username is set, so just in case there is
    # no username set in main, set one here.
    unless ($self->{_username}) {
      $self->{_username} = "GLOBALBAYES";
    }
  }
  dbg("bayes: Using username: ".$self->{_username});
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

  my $ret = $self->tie_db_writable();

  return $ret;
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method ensures that the database connetion is properly setup
and working. If necessary it will initialize a users bayes variables
so that they can begin using the database immediately.

=cut

sub tie_db_writable {
  my ($self) = @_;

  return 0 unless (HAS_DBI);

  return 1 if ($self->{_dbh}); # already connected

  my $main = $self->{bayes}->{main};

  $self->read_db_configs();

  # Turn off PrintError and explicitly set AutoCommit to off
  my $dbh = DBI->connect($self->{_dsn}, $self->{_dbuser}, $self->{_dbpass},
			 {'PrintError' => 0, 'AutoCommit' => 1});

  if (!$dbh) {
    dbg("bayes: Unable to connect to database: ".DBI->errstr());
    return 0;
  }
  else {
    dbg("bayes: Database connection established");
  }

  $self->{_dbh} = $dbh;

  # If the DB version is one we don't understand, abort!
  my $db_ver = $self->_get_db_version();
  $self->{db_version} = $db_ver;
  dbg("bayes: found bayes db version ".$self->{db_version});

  if ( $db_ver != $self->DB_VERSION ) {
    dbg("bayes: Database version $db_ver is different than we understand (".$self->DB_VERSION."), aborting!");
    $self->untie_db();
    return 0;
  }

  unless ($self->_initialize_db()) {
    dbg("bayes: unable to initialize database for ".$self->{_username}." user, aborting!");
    $self->untie_db();
    return 0;
  }

  return 1;
}


=head2 untie_db

public instance () untie_db ()

Description:
This method is unused for the SQL based implementation.

=cut

sub untie_db {
  my ($self) = @_;

  return unless (defined($self->{_dbh}));

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

  my %delta = (); # use a hash since an array is going to be very sparse

  return %delta unless (defined($self->{_dbh}));
  
  my $sql = "SELECT count(*)
               FROM bayes_token
              WHERE username = ?
                AND (? - atime) > ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);
    
  for (my $i = 1; $i <= $max_expire_mult; $i<<=1) {
    my $rc = $sth->execute($self->{_username}, $newest_atime, $start * $i);

    unless ($rc) {
      dbg("bayes: calculate_expire_delta: SQL Error: ".$self->{_dbh}->errstr());
      return undef;
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

  # Figure out how old is too old...
  my $too_old = $vars[10] - $newdelta; # tooold = newest - delta

  # if token atime > newest, reset to newest ...
  my $sql = "UPDATE bayes_token SET atime=? WHERE username = ? and atime > ?";
  my $rows = $self->{_dbh}->do($sql, undef, $vars[10], $self->{_username}, $vars[10]);
  unless (defined($rows)) {
    dbg("bayes: reset tokens in future: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  # Do the expire
  $sql = "DELETE from bayes_token WHERE username = ? and atime < ?";

  $rows = $self->{_dbh}->do($sql, undef, $self->{_username}, $too_old);

  unless (defined($rows)) {
    dbg("bayes: actual_expire: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $deleted = $rows;

  # We've chosen a new atime delta if we've gotten here, so record it for posterity.
  $self->_set_last_atime_delta($newdelta);

  # The rest of these have been modified, so replace as necessary.
  $self->set_last_expire(time());
  $self->_set_last_expire_reduce($deleted);

  my $kept = $self->_get_token_count();

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

  return undef unless (defined($self->{_dbh}));
 
  my $sql = "SELECT flag FROM bayes_seen WHERE username = ? AND msgid = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: seen_get: SQL Error: ".$self->{_dbh}->errstr());
    return undef;
  }

  my $rc = $sth->execute($self->{_username}, $msgid);
  
  unless ($rc) {
    dbg("bayes: seen_get: SQL Error: ".$self->{_dbh}->errstr());
    return undef;
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

  my $sql = "INSERT INTO bayes_seen (username, msgid, flag) VALUES (?,?,?)";
  
  my $sth = $self->{_dbh}->prepare_cached($sql);
  
  unless (defined($sth)) {
      dbg("bayes: seen_put: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
  }

  my $rc = $sth->execute($self->{_username}, $msgid, $flag);
  
  unless ($rc) {
      dbg("bayes: seen_put: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
  }
  
  $sth->finish();

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

  my $sql = "DELETE FROM bayes_seen WHERE username = ? AND msgid = ?";
  
  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
      dbg("bayes: seen_delete: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
  }

  my $rc = $sth->execute($self->{_username}, $msgid);

  unless ($rc) {
      dbg("bayes: seen_delete: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
  }

  $sth->finish();

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

  my $sql = "SELECT spam_count, ham_count, last_expire,
                    last_atime_delta, last_expire_reduce
               FROM bayes_vars
              WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: get_storage_variables: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0,0,0,0,0,0,0,0,0,0);
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: get_storage_variables: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0,0,0,0,0,0,0,0,0,0);
  }

  my ($spam_count, $ham_count, $last_expire,
      $last_atime_delta, $last_expire_reduce) = $sth->fetchrow_array();

  $sth->finish();

  my $token_count = $self->_get_token_count();
  my $oldest_token_age = $self->_get_oldest_token_age();
  my $newest_token_age = $self->_get_newest_token_age();
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

  foreach ( @values ) {
    if ( !$_ || $_ =~ /\D/ ) { $_ = 0; }
  }

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

  # 0/0 tokens don't count
  # since ordering is check here, order the tokens
  my $sql = "SELECT token, spam_count, ham_count, atime
               FROM bayes_token
              WHERE username = ?
                AND (spam_count > 0 OR ham_count > 0)
             ORDER BY token";

  my $sth = $self->{_dbh}->prepare($sql);

  unless (defined($sth)) {
    dbg("bayes: dump_db_toks: SQL Error: ".$self->{_dbh}->errstr());
    return;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: dump_db_toks: SQL Error: ".$self->{_dbh}->errstr());
    return;
  }  

  while (my ($token, $spam_count, $ham_count, $atime) = $sth->fetchrow_array()) {
    my $prob = $self->{bayes}->compute_prob_for_token($token, $vars[1], $vars[2],
						      $spam_count, $ham_count,
						      $atime);
    $prob ||= 0.5;
    
    printf $template,$prob,$spam_count,$ham_count,$atime,$token;
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

  my $sql = "UPDATE bayes_vars SET last_expire = ? WHERE username = ?";
 
  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: set_last_expire: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($time, $self->{_username});

  unless ($rc) {
    dbg("bayes: set_last_expire: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

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

  my $sql = "SELECT max(runtime) from bayes_expire WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: get_running_expire_tok: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: get_running_expire_tok: SQL Error: ".$self->{_dbh}->errstr());
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

  my $sql = "INSERT INTO bayes_expire (username,runtime) VALUES (?,?)";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  my $time = time();

  my $rc = $sth->execute($self->{_username}, $time);

  unless ($rc) {
      dbg("bayes: set_running_expire_tok: SQL Error: ".$self->{_dbh}->errstr());
      return undef;
  }
  $sth->finish();
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

  my $sql = "DELETE from bayes_expire WHERE username = ?";

  my $rows = $self->{_dbh}->do($sql, undef, $self->{_username});

  if (!defined($rows)) {
    dbg("bayes: remove_running_expire_tok: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

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
              WHERE username = ?
                AND token = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: tok_get: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0,0);
  }

  my $rc = $sth->execute($self->{_username}, $token);

  unless ($rc) {
    dbg("bayes: tok_get: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0,0);
  }

  my ($spam_count, $ham_count, $atime) = $sth->fetchrow_array();

  $sth->finish();

  $spam_count = 0 if (!$spam_count || $spam_count < 0);
  $ham_count = 0 if (!$ham_count || $ham_count < 0);
  $atime = 0 if (!$atime);

  return ($spam_count, $ham_count, $atime)
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

  $self->_put_token ($token, $spam_count, $ham_count, $atime);
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

  my $sql = "SELECT ham_count, spam_count FROM bayes_vars WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: nspam_nham_get: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0);
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: nspam_nham_get: SQL Error: ".$self->{_dbh}->errstr());
    return (0,0);
  }

  my ($ham_count, $spam_count) = $sth->fetchrow_array();

  $sth->finish();
  
  return ($spam_count || 0, $ham_count || 0);
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

  my $sql = "UPDATE bayes_vars
                SET spam_count = spam_count + ?,
                    ham_count = ham_count + ?
              WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: nspam_nham_change: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($num_spam, $num_ham, $self->{_username});

  unless ($rc) {
    dbg("bayes: nspam_nham_change: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

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
              WHERE username = ?
                AND token = ?
                AND atime < ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: tok_touch: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($atime, $self->{_username}, $token, $atime);

  unless ($rc) {
    dbg("bayes: tok_touch: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

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

  # Not used for this implementation
	       
  return 1;
}

=head2 get_magic_re

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
could causes the database to be inconsistent for the given user.

=cut

sub clear_database {
  my ($self) = @_;

  $self->tie_db_writable();

  return 0 unless (defined($self->{_dbh}));

  my $rows = $self->{_dbh}->do("DELETE FROM bayes_vars WHERE username = ?",
			       undef,
			       $self->{_username});
  unless (defined($rows)) {
    dbg("SQL Error removing user (bayes_vars) data: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_seen WHERE username = ?",
			    undef,
			    $self->{_username});
  unless (defined($rows)) {
    dbg("SQL Error removing seen data: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rows = $self->{_dbh}->do("DELETE FROM bayes_token WHERE username = ?",
			    undef,
			    $self->{_username});
  unless (defined($rows)) {
    dbg("SQL Error removing token data: ".$self->{_dbh}->errstr());
    return 0;
  }

  return 1;
}

=head2 backup_database

public instance (Boolean) backup_database ()

Description:
This method will dump the users database in a marchine readable format.

=cut

sub backup_database {
  my ($self) = @_;

  return 0 unless ($self->tie_db_readonly());

  return 0 unless (defined($self->{_dbh}));

  my @vars = $self->get_storage_variables();

  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  my $token_sql = "SELECT spam_count, ham_count, atime, token
                     FROM bayes_token
                    WHERE username = ?
                      AND (spam_count > 0 OR ham_count > 0)
                    ORDER BY token";

  my $seen_sql = "SELECT flag, msgid
                    FROM bayes_seen
                   WHERE username = ?";

  my $sth = $self->{_dbh}->prepare($token_sql);

  unless (defined ($sth)) {
    dbg("bayes: backup_database: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: backup_database: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  while (my @values = $sth->fetchrow_array()) {
    print "t\t" . join("\t",@values) . "\n";
  }

  $sth->finish();

  $sth = $self->{_dbh}->prepare($seen_sql);

  unless (defined ($sth)) {
    dbg("bayes: backup_database: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: backup_database: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  while (my @values = $sth->fetchrow_array()) {
    print "s\t" . join("\t",@values) . "\n";
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

  if (!open(DUMPFILE, '<', $filename)) {
    dbg("bayes: Unable to open backup file $filename: $!");
    return 0;
  }

  return 0 unless ($self->tie_db_writable());

  return 0 unless (defined($self->{_dbh}));

  # This is the critical phase (moving sql around), so don't allow it
  # to be interrupted.
  local $SIG{'INT'} = 'IGNORE';
  local $SIG{'HUP'} = 'IGNORE' if (!Mail::SpamAssassin::Util::am_running_on_windows());
  local $SIG{'TERM'} = 'IGNORE';

  unless ($self->clear_database()) {
    dbg("bayes: Database now in inconsistent state for ".$self->{_username});
    return 0;
  }

  my $token_count = 0;
  my $db_version;
  my $num_spam = 0;
  my $num_ham = 0;
  my $error_p = 0;
  my $line_count = 0;

  my $line = <DUMPFILE>;
  $line_count++;
  # We require the database version line to be the first in the file so we can figure out how
  # to properly deal with the file.  If it is not the first line then fail
  if ($line =~ m/^v\s+(\d+)\s+db_version/) {
    $db_version = $1;
  }
  else {
    dbg("bayes: Database Version must be the first line in the backup file, correct and re-run.");
    return 0;
  }

  my $tokensql = "INSERT INTO bayes_token
                    (username, token, spam_count, ham_count, atime)
                  VALUES (?,?,?,?,?)";

  my $tokensth = $self->{_dbh}->prepare_cached($tokensql);

  my $seensql = "INSERT INTO bayes_seen (username, msgid, flag)
                   VALUES (?, ?, ?)";

  my $seensth = $self->{_dbh}->prepare_cached($seensql);

  unless (defined($seensth)) {
    dbg("SQL Error: ".$self->{_dbh}->errstr());
    dbg("bayes: Database now in inconsistent state for ".$self->{_username});
    return 0;
  }

  while (my $line = <DUMPFILE>) {
    chomp($line);
    $line_count++;

    if ($line_count % 1000 == 0) {
      print STDERR "." if ($showdots);
    }

    my @parsed_line = split(/\s+/, $line, 5);

    if ($parsed_line[0] eq 'v') { # variable line
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
	$num_spam = $value;
      }
      elsif ($parsed_line[2] eq 'num_nonspam') {
	$num_ham = $value;
      }
      else {
	dbg("bayes: restore_database: Skipping unknown line: $line");
      }
    }
    elsif ($parsed_line[0] eq 't') { # token line
      my $spam_count = $parsed_line[1] + 0;
      my $ham_count = $parsed_line[2] + 0;
      my $atime = $parsed_line[3] + 0;
      my $token = $parsed_line[4];

      my $token_warn_p = 0;
      my @warnings;

      if ($spam_count < 0) {
	$spam_count = 0;
	push(@warnings,'Spam Count < 0, resetting');
	$token_warn_p = 1;
      }
      if ($ham_count < 0) {
	$ham_count = 0;
	push(@warnings,'Ham Count < 0, resetting');
	$token_warn_p = 1;
      }

      if ($spam_count == 0 && $ham_count == 0) {
	dbg("bayes: Token has zero spam and ham count, skipping.");
	next;
      }

      if ($atime > time()) {
	$atime = time();
	push(@warnings,'atime > current time, resetting');
	$token_warn_p = 1;
      }

      if ($token_warn_p) {
	dbg("bayes: Token ($token) has the following warnings:\n".join("\n",@warnings));
      }

      my $rc = $tokensth->execute($self->{_username},
				  $token,
				  $spam_count,
				  $ham_count,
				  $atime);
      unless ($rc) {
	dbg("bayes: Error inserting token for line: $line\nSQL Error: ".$self->errstr());
	$error_p = 1;
      }
      $token_count++;
    }
    elsif ($parsed_line[0] eq 's') { # seen line
      my $flag = $parsed_line[1];
      my $msgid = $parsed_line[2];

      unless ($flag eq 'h' || $flag eq 's') {
	dbg("bayes: Unknown seen flag ($flag) for line: $line, skipping");
	next;
      }

      my $rc = $seensth->execute($self->{_username},
				 $msgid,
				 $flag);
      unless ($rc) {
	dbg("bayes: Error inserting msgid in seen table for line: $line\nSQL Error: ".$self->errstr());
	$error_p = 1;
      }
    }
    else {
      dbg("bayes: Skipping unknown line: $line");
      next;
    }
  }
  close(DUMPFILE);

  print STDERR "\n" if ($showdots);

  unless ($num_spam) {
    dbg("bayes: Unable to find num spam, please check file.");
    $error_p = 1;
  }

  unless ($num_ham) {
    dbg("bayes: Unable to find num ham, please check file.");
    $error_p = 1;
  }

  if ($error_p) {
    dbg("bayes: Error(s) while attempting to load $filename, correct and Re-Run");

    $self->clear_database();

    dbg("bayes: Database now in inconsistent state for ".$self->{_username});
    return 0;
  }

  # There is a race condition here which is why we suggest that the user
  # turn off SA for the duration of a restore operation.  If something comes
  # along and calls initialize_db() before this little bit of code runs then
  # this insert will fail, but at least we'll now wipe out the bayes_token
  # entries for this user so that we are in a somewhat ok state.
  my $varsupdatesql = "INSERT INTO bayes_vars (username, spam_count, ham_count)
                       VALUES(?,?,?)";
  
  my $rows = $self->{_dbh}->do($varsupdatesql,
			       undef,
			       $self->{_username}, $num_spam, $num_ham);
  
  unless (defined($rows)) {
    dbg("bayes: Error inserting user variables (bayes_vars).");
    dbg("bayes: SQL Error:".$self->{_dbh}->errstr());
    $self->clear_database();
    dbg("bayes; Database now in inconsistent state for ".$self->{_username});
    return 0;
  }

  dbg("bayes: Parsed $line_count lines.");
  dbg("bayes: Created database with $token_count tokens based on $num_spam Spam Messages and $num_ham Ham Messages.");

  $self->untie_db();

  return 1;
}


=head1 Private Methods

=head2 _get_db_version

private instance (Integer) _get_db_version ()

Description:
Gets the current version of the database from the special global vars
tables.

=cut

sub _get_db_version {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT value FROM bayes_global_vars WHERE variable = 'VERSION'";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_db_version: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: _get_db_version: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($version) = $sth->fetchrow_array();

  $sth->finish();

  return $version;
}
 
=head2 _initialize_db

private instance (Boolean) _initialize_db ()

Description:
This method will check to see if a user has had their bayes variables
initialized. If not then it will perform this initialization.

=cut

sub _initialize_db {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 0 if (!$self->{_username});

  my $sql = "SELECT count(*) FROM bayes_vars WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _initialize_db: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _initialize_db: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($count) = $sth->fetchrow_array();

  $sth->finish();

  if ($count) {
    return 1;
  }

  # For now let the database setup the other variables as defaults
  $sql = "INSERT INTO bayes_vars (username) VALUES (?)";

  $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _initialize_db: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _initialize_db: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

  return 1;
}

=head2 _token_atime

private instance (Boolean) _token_atime (String $token)

Description:
This method returns a given tokens atime, it also serves to tell us
if the token exists or not since the atime will be undefined if it
does not exist.

=cut

sub _token_atime {
  my ($self, $token) = @_;

  return 0 unless (defined($self->{_dbh}));

  return undef unless (defined($token));

  my $sql = "SELECT atime
               FROM bayes_token
              WHERE username = ?
                AND token = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _token_atime: SQL Error: ".$self->{_dbh}->errstr());
    return undef;
  }

  my $rc = $sth->execute($self->{_username}, $token);

  unless ($rc) {
    dbg("bayes: _token_atime: SQL Error: ".$self->{_dbh}->errstr());
    return undef;
  }

  my ($token_atime) = $sth->fetchrow_array();

  $sth->finish();

  return $token_atime;
}

=head2 _delete_token

private instance (Boolean) _delete_token (String $token)

Description:
This method deletes the given token from the database.

=cut

sub _delete_token {
  my ($self, $token) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 0 unless (defined($token));

  my $sql = "DELETE FROM bayes_token WHERE username = ? AND token = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _delete_token: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username}, $token);

  unless ($rc) {
    dbg("bayes: _delete_token: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

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

  my $existing_atime = $self->_token_atime($token);

  if ($spam_count == 0 && $ham_count == 0) {
    return 1;
  }

  if (!defined($existing_atime)) {

    # You can't create a new entry for a token with a negative count, so just return
    # if we are unable to find an entry.
    return 1 if ($spam_count < 0 || $ham_count < 0);

    my $sql = "INSERT INTO bayes_token
               (username, token, spam_count, ham_count, atime)
               VALUES (?,?,?,?,?)";

    my $sth = $self->{_dbh}->prepare_cached($sql);

    unless (defined($sth)) {
      dbg("bayes: _put_token: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
    }

    my $rc = $sth->execute($self->{_username},
			   $token,
			   $spam_count,
			   $ham_count,
			   $atime);
    
    unless ($rc) {
      dbg("bayes: _put_token: SQL Error: ".$self->{_dbh}->errstr());
      return 0;
    }

    $sth->finish();
    dbg("bayes: new token ($token) inserted");
  }
  else {
    my $update_atime_p = 1;

    # if the existing atime is already >= the one we are going to set, then don't bother
    $update_atime_p = 0 if ($existing_atime >= $atime);

    if ($spam_count) {
      my $sql;
      my @args;
      if ($update_atime_p) {
	$sql = "UPDATE bayes_token
                   SET spam_count = spam_count + ?,
                       atime = ?
                 WHERE username = ?
                   AND token = ?
                   AND spam_count + ? >= 0";
	@args = ($spam_count, $atime, $self->{_username}, $token, $spam_count);
	$update_atime_p = 0;
      }
      else {
	$sql = "UPDATE bayes_token
                   SET spam_count = spam_count + ?
                 WHERE username = ?
                   AND token = ?
                   AND spam_count + ? >= 0";
	@args = ($spam_count, $self->{_username}, $token, $spam_count);
      }

      my $rows = $self->{_dbh}->do($sql, undef, @args);

      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL Error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }

    if ($ham_count) {
      my $sql;
      my @args;
      if ($update_atime_p) {
	$sql = "UPDATE bayes_token
                   SET ham_count = ham_count + ?,
                       atime = ?
                 WHERE username = ?
                   AND token = ?
                   AND ham_count + ? >= 0";
	@args = ($ham_count, $atime, $self->{_username}, $token, $ham_count);
      }
      else {
	$sql = "UPDATE bayes_token
                   SET ham_count = ham_count + ?
                 WHERE username = ?
                   AND token = ?
                   AND ham_count + ? >= 0";
	@args = ($ham_count, $self->{_username}, $token, $ham_count);
      }

      my $rows = $self->{_dbh}->do($sql, undef, @args);

      unless (defined($rows)) {
	dbg("bayes: _put_token: SQL Error: ".$self->{_dbh}->errstr());
	return 0;
      }
    }

    dbg("bayes: token ($token) updated");
  }
  return 1;
}

=head2 _get_token_count

private instance (Integer) _get_token_count ()

Description:
This method returns the total number of tokens present in the token database
for a user.

=cut

sub _get_token_count {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT count(*)
               FROM bayes_token
              WHERE username = ?
                AND (spam_count > 0 OR ham_count > 0)";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_token_count: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless (defined($sth)) {
    dbg("bayes: _get_token_count: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($token_count) = $sth->fetchrow_array();

  $sth->finish();

  return $token_count
}

=head2 _get_oldest_token_age

private instance (Integer) _get_oldest_token_age ()

Description:
This method finds the atime of the oldest token in the database.

=cut

sub _get_oldest_token_age {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT min(atime) FROM bayes_token WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_oldest_token_age: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _get_oldest_token_age: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($atime) = $sth->fetchrow_array();

  $sth->finish();

  return $atime;
}

=head2 _get_newest_token_age

private instance (Integer) _get_newest_token_age ()

Description:
This method finds the atime of the newest token in the database.

=cut

sub _get_newest_token_age {
  my ($self) = @_;

  return 0 unless (defined($self->{_dbh}));

  my $sql = "SELECT max(atime) FROM bayes_token WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_newest_token_age: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _get_newest_token_age: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($atime) = $sth->fetchrow_array();

  $sth->finish();

  return $atime;
}

=head2 _set_last_atime_delta

private instance (Boolean) _set_last_atime_delta (Integer $newdelta)

Description:
This method sets the last_atime_delta variable in the variable table.

=cut

sub _set_last_atime_delta {
  my ($self, $newdelta) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 0 unless (defined($newdelta));

  my $sql = "UPDATE bayes_vars SET last_atime_delta = ? WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _set_last_atime_delta: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($newdelta, $self->{_username});

  unless ($rc) {
    dbg("bayes: _set_last_atime_delta: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

  return 1;
}

=head2 _set_last_expire_reduce

private instance (Boolean) _set_last_expire_reduce (Integer $deleted)

Description:
This method sets the last_expire_reduce values in the variable table.

=cut

sub _set_last_expire_reduce {
  my ($self, $deleted) = @_;

  return 0 unless (defined($self->{_dbh}));

  return 0 unless (defined($deleted));

  my $sql = "UPDATE bayes_vars SET last_expire_reduce = ? WHERE username = ?";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _set_last_expire_reduce: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($deleted, $self->{_username});

  unless ($rc) {
    dbg("bayes: _set_last_expire_reduce: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

  return 1;
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
              WHERE username = ?
                AND spam_count + ham_count = 1";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_num_hapaxes: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _get_num_hapaxes: SQL Error: ".$self->{_dbh}->errstr());
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
              WHERE username = ? 
                AND (spam_count >= 0 AND spam_count < 8)
                AND (ham_count >= 0 AND ham_count < 8)
                AND spam_count + ham_count != 1";

  my $sth = $self->{_dbh}->prepare_cached($sql);

  unless (defined($sth)) {
    dbg("bayes: _get_num_lowfreq: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rc = $sth->execute($self->{_username});

  unless ($rc) {
    dbg("bayes: _get_num_lowfreq: SQL Error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my ($num_lowfreq) = $sth->fetchrow_array();

  $sth->finish();

  return $num_lowfreq;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

1;
