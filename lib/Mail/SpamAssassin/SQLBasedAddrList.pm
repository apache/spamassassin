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

Mail::SpamAssassin::SQLBasedAddrList - SpamAssassin SQL Based Auto Whitelist

=head1 SYNOPSIS

    my $factory = Mail::SpamAssassin::SQLBasedAddrList->new()
    $spamtest->set_persistent_addr_list_factory ($factory);
  ... call into SpamAssassin classes...

SpamAssassin will call:

    my $addrlist = $factory->new_checker($spamtest);
    $entry = $addrlist->get_addr_entry ($addr, $origip);
  ...

=head1 DESCRIPTION

A SQL based persistent address list implementation.

See C<Mail::SpamAssassin::PersistentAddrList> for more information.

Uses DBI::DBD module access to your favorite database (tested with
MySQL, SQLite and PostgreSQL) to store user auto-whitelists.

The default table structure looks like this:
CREATE TABLE awl (
  username varchar(100) NOT NULL default '',
  email varchar(255) NOT NULL default '',
  ip varchar(40) NOT NULL default '',
  count int(11) NOT NULL default '0',
  totscore float NOT NULL default '0',
  signedby varchar(255) NOT NULL default '',
  PRIMARY KEY (username,email,signedby,ip)
) TYPE=MyISAM;

Your table definition may change depending on which database driver
you choose.  There is a config option to override the table name.

This module introduces several new config variables:

user_awl_dsn

user_awl_sql_username

user_awl_sql_password

user_awl_sql_table

user_awl_sql_override_username

see C<Mail::SpamAssassin::Conf> for more information.


=cut

package Mail::SpamAssassin::SQLBasedAddrList;

use strict;
use warnings;
use bytes;
use re 'taint';

# Do this silliness to stop RPM from finding DBI as required
BEGIN { require DBI;  import DBI; }

use Mail::SpamAssassin::PersistentAddrList;
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);

@ISA = qw(Mail::SpamAssassin::PersistentAddrList);

=head2 new

public class (Mail::SpamAssassin::SQLBasedAddrList) new ()

Description:
This method creates a new instance of the SQLBasedAddrList factory and calls
the parent's (PersistentAddrList) new method.

=cut

sub new {
  my ($proto) = @_;
  my $class = ref($proto) || $proto;
  my $self = $class->SUPER::new(@_);
  $self->{class} = $class;
  bless ($self, $class);
  $self;
}

=head2 new_checker

public instance (Mail::SpamAssassin::SQLBasedAddrList) new_checker (\% $main)

Description:
This method is called to setup a new checker interface and return a blessed
copy of itself.  Here is where we setup the SQL database connection based
on the config values.

=cut

sub new_checker {
  my ($self, $main) = @_;

  my $class = $self->{class};

  if (!$main->{conf}->{user_awl_dsn} ||
      !$main->{conf}->{user_awl_sql_table}) {
    dbg("auto-whitelist: sql-based invalid config");
    return;
  }

  my $dsn    = $main->{conf}->{user_awl_dsn};
  my $dbuser = $main->{conf}->{user_awl_sql_username};
  my $dbpass = $main->{conf}->{user_awl_sql_password};

  my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

  if(!$dbh) {
    info("auto-whitelist: sql-based unable to connect to database (%s) : %s",
         $dsn, DBI::errstr);
    return;
  }

  dbg("auto-whitelist: sql-based connected to $dsn");

  $self = { 'main'      => $main,
            'dsn'       => $dsn,
            'dbh'       => $dbh,
            'tablename' => $main->{conf}->{user_awl_sql_table},
          };

  my $override_username = $main->{conf}->{user_awl_sql_override_username};
  if (defined $override_username && $override_username ne '') {
    $self->{_username} = $override_username;
  }
  else {
    $self->{_username} = $main->{username};

    # Need to make sure that a username is set, so just in case there is
    # no username set in main, set one here.
    if (!defined $self->{_username} || $self->{_username} eq '') {
      $self->{_username} = "GLOBAL";
    }
  }
  $self->{_with_awl_signer} =
    $main->{conf}->{auto_whitelist_distinguish_signed};

  dbg("auto-whitelist: sql-based using username: ".$self->{_username});

  return bless ($self, $class);
}

=head2 get_addr_entry

public instance (\%) get_addr_entry (String $addr, String $signedby)

Description:
This method takes a given C<$addr> and splits it between the email address
component and the ip component and performs a lookup in the database. If
nothing is found in the database then a blank entry hash is created and
returned, otherwise an entry containing the found information is returned.
If a with_awl_signer configuration option is enabled only addresses signed
by the given signing identity are taken into account, or, if $signedby is
undefined (or empty) only unsigned entries are considered.

A key, C<exists_p>, is set to 1 if an entry already exists in the database,
otherwise it is set to 0.

=cut

sub get_addr_entry {
  my ($self, $addr, $signedby) = @_;

  my $entry = { addr     => $addr,
                exists_p => 0,
                count    => 0,
                totscore => 0,
                signedby => $signedby,
              };

  my ($email, $ip) = $self->_unpack_addr($addr);

  return $entry  unless $email ne '' && (defined $ip || defined $signedby);

  my $sql = "SELECT count, totscore FROM $self->{tablename} " .
            "WHERE username = ? AND email = ?";
  my @args = ( $email );
  if (!$self->{_with_awl_signer}) {
    $sql .= " AND ip = ?";
    push(@args, $ip);
  } else {
    my @signedby = !defined $signedby ? () : split(' ', lc $signedby);
    if (!@signedby) {
      $sql .= " AND signedby = '' AND ip = ?";
      push(@args, $ip);
    } elsif (@signedby == 1) {
      $sql .= " AND signedby = ?";
    } elsif (@signedby > 1) {
      $sql .= " AND signedby IN (" . join(',', ('?') x @signedby) . ")";
    }
    push(@args, @signedby);
  }
  my $sth = $self->{dbh}->prepare($sql);
  my $rc = $sth->execute($self->{_username}, @args);

  if (!$rc) { # there was an error, but try to go on
    info("auto-whitelist: sql-based get_addr_entry %s: SQL error: %s",
         join('|',@args), $sth->errstr);
    $entry->{count} = 0;
    $entry->{totscore} = 0;
  }
  else {
    my $cnt = 0;
    my $aryref;
    # how to combine data if there are several entries (like signed by
    # an author domain and by a remailer)?  for now just take an average
    while ( defined($aryref = $sth->fetchrow_arrayref()) ) {
      if (defined $entry->{count} && defined $aryref->[1]) {
        $entry->{count} += $aryref->[0];
        $entry->{totscore} += $aryref->[1];
      }
      $entry->{exists_p} = 1;
      $cnt++;
    }
    dbg("auto-whitelist: sql-based get_addr_entry: %s for %s",
        $cnt ? "found $cnt entries" : 'no entries found',
        join('|',@args) );
  }
  $sth->finish();

  dbg("auto-whitelist: sql-based %s scores %s, count %s",
      join('|',@args), $entry->{totscore}, $entry->{count});

  return $entry;
}

=head2 add_score

public instance (\%) add_score (\% $entry, Integer $score)

Description:
This method adds a given C<$score> to a given C<$entry>.  If the entry was
marked as not existing in the database then an entry will be inserted,
otherwise a simple update will be performed.

NOTE: This code uses a self referential SQL call (ie set foo = foo + 1) which
is supported by most modern database backends, but not everything calling
itself a SQL database.

=cut

sub add_score {
  my($self, $entry, $score) = @_;

  return if (!$entry->{addr});
  
  my ($email, $ip) = $self->_unpack_addr($entry->{addr});

  $entry->{count} += 1;
  $entry->{totscore} += $score;
  my $signedby = $entry->{signedby};
  
  return $entry  unless $email ne '' && (defined $ip || defined $signedby);

  # try inserting first, and if that fails we'll do the update; this way
  # we avoid to large extent a race condition between multiple processes

  my $inserted = 0;

  { my @fields = qw(username email ip count totscore);
    my @signedby;
    if ($self->{_with_awl_signer}) {
      push(@fields, 'signedby');
      @signedby = !defined $signedby ? () : split(' ', lc $signedby);
      @signedby = ( '' )  if !@signedby;
    }
    my @args = ($self->{_username}, $email, $ip, 1, $score);
    my $sql = sprintf("INSERT INTO %s (%s) VALUES (%s)", $self->{tablename},
                      join(',', @fields),  join(',', ('?') x @fields));
    my $sth = $self->{dbh}->prepare($sql);

    if (!$self->{_with_awl_signer}) {
      my $rc = $sth->execute(@args);
      if (!$rc) {
        dbg("auto-whitelist: sql-based add_score/insert %s: SQL error: %s",
             join('|',@args), $sth->errstr);
      } else {
        dbg("auto-whitelist: sql-based add_score/insert ".
            "score %s: %s", $score, join('|',@args));
        $inserted = 1; $entry->{exists_p} = 1;
      }
    } else {
      for my $s (@signedby) {
        my $rc = $sth->execute(@args, $s);
        if (!$rc) {
          dbg("auto-whitelist: sql-based add_score/insert %s: SQL error: %s",
              join('|',@args,$s), $sth->errstr);
        } else {
          dbg("auto-whitelist: sql-based add_score/insert ".
              "score %s: %s", $score, join('|',@args,$s));
          $inserted = 1; $entry->{exists_p} = 1;
        }
      }
    }
  }

  if (!$inserted) {
    # insert failed, assume primary key constraint, so try the update

    my $sql = "UPDATE $self->{tablename} ".
              "SET count = ?, totscore = totscore + ? ".
              "WHERE username = ? AND email = ?";
    my(@args) = ($entry->{count}, $score, $self->{_username}, $email);
    if ($self->{_with_awl_signer}) {
      my @signedby = !defined $signedby ? () : split(' ', lc $signedby);
      if (!@signedby) {
        $sql .= " AND signedby = ''";
      } elsif (@signedby == 1) {
        $sql .= " AND signedby = ?";
      } elsif (@signedby > 1) {
        $sql .= " AND signedby IN (" . join(',', ('?') x @signedby) . ")";
      }
      push(@args, @signedby);
    }
    $sql .= " AND ip = ?";
    push(@args, $ip);

    my $sth = $self->{dbh}->prepare($sql);
    my $rc = $sth->execute(@args);
    
    if (!$rc) {
      info("auto-whitelist: sql-based add_score/update %s: SQL error: %s",
           join('|',@args), $sth->errstr);
    } else {
      dbg("auto-whitelist: sql-based add_score/update ".
          "new count: %s, new totscore: %s for %s",
          $entry->{count}, $entry->{totscore}, join('|',@args));
      $entry->{exists_p} = 1;
    }
  }
  
  return $entry;
}

=head2 remove_entry

public instance () remove_entry (\% $entry)

Description:
This method removes a given C<$entry> from the database.  If the
ip portion of the entry address is equal to "none" then remove any
perl-IP entries for this address as well.

=cut

sub remove_entry {
  my ($self, $entry) = @_;

  my ($email, $ip) = $self->_unpack_addr($entry->{addr});

  return unless ($email && $ip);

  my $sql = "DELETE FROM $self->{tablename} WHERE username = ? AND email = ?";
  my @args = ($self->{_username}, $email);

  # when $ip is equal to none then attempt to delete all entries
  # associated with address
  if ($ip eq 'none') {
    dbg("auto-whitelist: sql-based remove_entry: removing all entries matching $email");
  }
  else {
    $sql .= " AND ip = ?";
    push(@args, $ip);
    dbg("auto-whitelist: sql-based remove_entry: removing single entry matching ".$entry->{addr});
  }
  # if a key 'signedby' exists in the $entry, be selective on its value too
  my $signedby = $entry->{signedby};
  if ($self->{_with_awl_signer} && defined $signedby) {
    my @signedby = split(' ', lc $signedby);
    if (@signedby == 1) {
      $sql .= " AND signedby = ?";
    } elsif (@signedby > 1) {
      $sql .= " AND signedby IN (" . join(',', ('?') x @signedby) . ")";
    }
    push(@args, @signedby);
  }

  my $sth = $self->{dbh}->prepare($sql);
  my $rc = $sth->execute(@args);

  if (!$rc) {
    info("auto-whitelist: sql-based remove_entry %s: SQL error: %s",
         join('|',@args), $sth->errstr);
  }
  else {
    # We might normally have a dbg saying we removed the address
    # but the common codepath already provides this in SpamAssassin.pm
  }
  $entry = undef; # slight cleanup since it is now gone
}

=head2 finish

public instance () finish ()

Description:
This method provides the necessary cleanup for the address list.

=cut

sub finish {
  my ($self) = @_;
  dbg("auto-whitelist: sql-based finish: disconnected from " . $self->{dsn});
  $self->{dbh}->disconnect();
}

=head2 _unpack_addr

private instance (String, String) _unpack_addr(string $addr)

Description:
This method splits an autowhitelist address into it's two components,
email and ip address.

=cut

sub _unpack_addr {
  my ($self, $addr) = @_;

  my ($email, $ip) = split(/\|ip=/, $addr);

  unless ($email && $ip) {
    dbg("auto-whitelist: sql-based _unpack_addr: unable to decode $addr");
  }

  return ($email, $ip);
}

1;
