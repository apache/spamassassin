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

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::dbg;

use strict;
use warnings;
use bytes;

use Mail::SpamAssassin::BayesStore::SQL;

use vars qw( @ISA );

@ISA = qw( Mail::SpamAssassin::BayesStore::SQL );

# We need this so we can import the pg_types, since this is a DBD::Pg specific module it should be ok
use DBD::Pg qw(:pg_types);

=head1 METHODS

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

  my $single_sql = "SELECT token, spam_count, ham_count, atime
                      FROM bayes_token
                     WHERE id = ?
                       AND token = ?";

  foreach my $bunch_size (@bunch_sizes) {
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

  while ($search_index < $token_list_size) {
    my $sth = $self->{_dbh}->prepare_cached($single_sql);

    unless (defined($sth)) {
      dbg("bayes: tok_get_all: SQL error: ".$self->{_dbh}->errstr());
      return [];
    }

    $sth->bind_param(1, $self->{_userid});
    $sth->bind_param(2, $tokens[$search_index++], { pg_type => DBD::Pg::PG_BYTEA });

    my $rc = $sth->execute();

    unless ($rc) {
      dbg("bayes: tok_get_all: SQL error: ".$self->{_dbh}->errstr());
      return [];
    }

    my $result = $sth->fetchrow_arrayref();

    $sth->finish();

    if (defined($result)) {
      # Make sure that spam_count and ham_count are not negative
      $result->[1] = 0 if (!$result->[1] || $result->[1] < 0);
      $result->[2] = 0 if (!$result->[2] || $result->[2] < 0);
      # Make sure that atime has a value
      $result->[3] = 0 if (!$result->[3]);
      $tok_results[$results_index++] = $result 
    }
  }

  return \@tok_results;
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
    return 0;
  }
  
  $sth->bind_param(1, $atime);
  $sth->bind_param(2, $self->{_userid});
  $sth->bind_param(3, $token, { pg_type => DBD::Pg::PG_BYTEA });
  $sth->bind_param(4, $atime);

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: tok_touch: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  my $rows = $sth->rows;

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

  my @bindings;
  foreach my $token (@{$tokens}) {
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

=head1 Private Methods

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

  my $sth = $self->{_dbh}->prepare("select put_token(?,?,?,?,?)");

  unless (defined($sth)) {
    dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->bind_param(1, $self->{_userid});
  $sth->bind_param(2, $token, { pg_type => DBD::Pg::PG_BYTEA });
  $sth->bind_param(3, $spam_count);
  $sth->bind_param(4, $ham_count);
  $sth->bind_param(5, $atime);

  my $rc = $sth->execute();

  unless ($rc) {
    dbg("bayes: _put_token: SQL error: ".$self->{_dbh}->errstr());
    return 0;
  }

  $sth->finish();

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

1;
