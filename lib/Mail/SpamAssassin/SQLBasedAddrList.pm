# <@LICENSE>
# ====================================================================
# The Apache Software License, Version 1.1
# 
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
# 
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
# 
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
# 
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
# 
# Portions of this software are based upon public domain software
# originally written at the National Center for Supercomputing Applications,
# University of Illinois, Urbana-Champaign.
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
  username VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  ip VARCHAR NOT NULL,
  count INT NOT NULL,
  totscore FLOAT NOT NULL,
  PRIMARY KEY (username, email, ip)
)

You're table definition may change depending on which database driver
you choose.  There is a config option to override the table name.

This module introduces several new config variables:

user_awl_dsn

user_awl_sql_username

user_awl_sql_password

user_awl_sql_table

see C<Mail::SpamAssassin::Conf> for more information.


=cut

package Mail::SpamAssassin::SQLBasedAddrList;

use strict;
use bytes;

use DBI;

use Mail::SpamAssassin::PersistentAddrList;

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
    dbg("auto-whitelist (sql-based): invalid config");
    return undef;
  }

  my $dsn    = $main->{conf}->{user_awl_dsn};
  my $dbuser = $main->{conf}->{user_awl_sql_username};
  my $dbpass = $main->{conf}->{user_awl_sql_password};

  my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

  if(!$dbh) {
    dbg("auto-whitelist (sql-based): Unable to Connect to DB");
    return undef;
  }

  $self = { 'main'      => $main,
            'dsn'       => $dsn,
            'dbh'       => $dbh,
            'tablename' => $main->{conf}->{user_awl_sql_table},
          };

  dbg("SQL Based AWL: Connected to $dsn");

  return bless ($self, $class);
}

=head2 get_addr_entry

public instance (\%) get_addr_entry (String $addr)

Description:
This method takes a given C<$addr> and splits it between the email address
component and the ip component and performs a lookup in the database. If
nothing is found in the database then a blank entry hash is created and
returned, otherwise an entry containing the found information is returned.

A key, C<exists_p>, is set to 1 if an entry already exists in the database,
otherwise it is set to 0.

=cut

sub get_addr_entry {
  my ($self, $addr) = @_;

  my $entry = { addr     => $addr,
                exists_p => 0,
                count    => 0,
                totscore => 0,
              };

  my ($email, $ip) = $self->_unpack_addr($addr);

  return $entry unless ($email && $ip);

  my $username = $self->{main}->{username};

  my $sql = "SELECT count, totscore FROM $self->{tablename}
              WHERE username = ? AND email = ? AND ip = ?";
  my $sth = $self->{dbh}->prepare($sql);
  my $rc = $sth->execute($username, $email, $ip);

  if (!$rc) { # there was an error, but try to go on
    my $err = $self->{dbh}->errstr;
    dbg("auto-whitelist (sql-based) get_addr_entry: SQL Error: $err");
    $entry->{count} = 0;
    $entry->{totscore} = 0;
  }
  else {
    my $aryref = $sth->fetchrow_arrayref();

    if (defined($aryref)) { # we got some data back
      $entry->{count} = $aryref->[0] || 0;
      $entry->{totscore} = $aryref->[1] || 0;
      $entry->{exists_p} = 1;
      dbg("auto-whitelist (sql-based) get_addr_entry: Found existing entry for $addr");
    }
    else {
      dbg("auto-whitelist (sql-based) get_addr_entry: No entry found for $addr");
    }
  }
  $sth->finish();

  dbg ("auto-whitelist (sql-based): $addr scores ".$entry->{count}.'/'.$entry->{totscore});

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
  
  return $entry unless ($email && $ip);

  my $username = $self->{main}->{username};
  
  if ($entry->{exists_p}) { # entry already exists, so just update
    my $sql = "UPDATE $self->{tablename} SET count = count + 1,
                                             totscore = totscore + ?
                WHERE username = ? AND email = ? AND ip = ?";
    
    my $sth = $self->{dbh}->prepare($sql);
    my $rc = $sth->execute($score, $username, $email, $ip);
    
    if (!$rc) {
      my $err = $self->{dbh}->errstr;
      dbg("auto-whitelist (sql-based) add_score: SQL Error: $err");
    }
    else {
      dbg("auto-whitelist (sql-based) add_score: New count: ". $entry->{count} .", new totscore: ".$entry->{totscore}." for ".$entry->{addr});
    }
    $sth->finish();
  }
  else { # no entry yet, so insert a new entry
    my $sql = "INSERT INTO $self->{tablename} (username,email,ip,count,totscore) VALUES (?,?,?,?,?)";
    my $sth = $self->{dbh}->prepare($sql);
    my $rc = $sth->execute($username,$email,$ip,1,$score);
    if (!$rc) {
      my $err = $self->{dbh}->errstr;
      dbg("auto-whitelist (sql-based) add_score: SQL Error: $err");
    }
    $entry->{exists_p} = 1;
    dbg("auto-whitelist (sql-based) add_score: Created new entry for ".$entry->{addr}." with totscore: $score");
    $sth->finish();
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

  my $username = $self->{main}->{username};

  my $sql;
  my @args;

  # when $ip is equal to none then attempt to delete all entries
  # associated with address
  if ($ip eq 'none') {
    $sql = "DELETE FROM $self->{tablename} WHERE username = ? AND email = ?";
    @args = ($username, $email);
    dbg("auto-whitelist (sql-based) remove_entry: Removing all entries matching $email");
  }
  else {
    $sql = "DELETE FROM $self->{tablename}
             WHERE username = ? AND email = ? AND ip = ?";
    @args = ($username, $email, $ip);
    dbg("auto-whitelist (sql-based) remove_entry: Removing single entry matching ".$entry->{addr});
  }

  my $sth = $self->{dbh}->prepare($sql);
  my $rc = $sth->execute(@args);

  if (!$rc) {
    my $err = $self->{dbh}->errstr;
    dbg("auto-whitelist (sql-based) remove_entry: SQL Error: $err");
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
  dbg("auto-whitelist (sql-based) finish: Disconnected from " . $self->{dsn});
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
    dbg("auto-whitelist (sql-based): _unpack_addr: Unable to decode $addr");
  }

  return ($email, $ip);
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
