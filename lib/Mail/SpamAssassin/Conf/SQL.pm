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

Mail::SpamAssassin::Conf::SQL - load SpamAssassin scores from SQL database

=head1 SYNOPSIS

  (see Mail::SpamAssassin)


=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blocklists.

This class is used internally by SpamAssassin to load scores from an SQL
database.  Please refer to the C<Mail::SpamAssassin> documentation for public
interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Conf::SQL;

use Mail::SpamAssassin::Logger;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main) = @_;

  my $self = {
    'main'              => $main
  };

  bless ($self, $class);
  $self;
}

###########################################################################

sub load_modules {		# static
  eval {
    require DBI;
  };

  # do any other preloading that will speed up operation
}

###########################################################################

=item $f-E<gt>load ($username)

Read configuration parameters from SQL database and parse scores from it.

=back

=cut

sub load {
   my ($self, $username) = @_;

   my $conf = $self->{main}->{conf};
   my $dsn = $conf->{user_scores_dsn};
   if (!defined($dsn) || $dsn eq '') {
     dbg("config: no DSN defined; skipping sql");
     return 1;
   }

   eval {
     # make sure we can see croak messages from DBI
     local $SIG{'__DIE__'} = sub { die "$_[0]"; };
     require DBI;
     load_with_dbi($self, $username, $dsn);
     1;
   } or do {
     my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
     if ($conf->{user_scores_fail_to_global}) {
       info("config: failed to load user (%s) scores from SQL database, ".
            "using a global default: %s", $username, $eval_stat);
       return 1;
     } else {
       warn sprintf(
            "config: failed to load user (%s) scores from SQL database: %s\n",
            $username, $eval_stat);
       return 0;
     }
   };
   return 1;
}

sub load_with_dbi {
   my ($self, $username, $dsn) = @_;

   my $main = $self->{main};
   my $conf = $main->{conf};
   my $dbuser = $conf->{user_scores_sql_username};
   my $dbpass = $conf->{user_scores_sql_password};
   my $custom_query = $conf->{user_scores_sql_custom_query};

   my $f_preference = 'preference';
   my $f_value = 'value';
   my $f_username = 'username';
   my $f_table = 'userpref';

   my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

   if ($dbh) {
     my $sql;
     if (defined($custom_query)) {
       $sql = $custom_query;
       my $quoted_username = $dbh->quote($username);
       my ($mailbox, $domain) = split('@', $username);
       my $quoted_mailbox = $dbh->quote($mailbox);
       my $quoted_domain = $dbh->quote($domain);

       $sql =~ s/_USERNAME_/$quoted_username/g;
       $sql =~ s/_TABLE_/$f_table/g;
       $sql =~ s/_MAILBOX_/$quoted_mailbox/g;
       $sql =~ s/_DOMAIN_/$quoted_domain/g;
     }
     else {
       $sql = "select $f_preference, $f_value  from $f_table where ". 
        "$f_username = ".$dbh->quote($username).
        " or $f_username = '\@GLOBAL' order by $f_username asc";
     }
     dbg("config: Conf::SQL: executing SQL: $sql");
     my $sth = $dbh->prepare($sql);
     if ($sth) {
       my $rv  = $sth->execute();
       if ($rv) {
	 dbg("config: retrieving prefs for $username from SQL server");
	 my @row;
	 my $config_text = '';
	 while (@row = $sth->fetchrow_array()) {
	   $config_text .= (defined($row[0]) ? $row[0] : '') . "\t" .
	       (defined($row[1]) ? $row[1] : '')  . "\n";
	 }
	 if ($config_text ne '') {
	   $conf->{main} = $main;
	   $config_text = "file start (sql config)\n".
	                  $config_text.
	                  "file end (sql config)\n";
	   $conf->parse_scores_only($config_text);
	   delete $conf->{main};
	 }
	 $sth->finish();
	 undef $sth;
       }
       else {
	 die "config: SQL error: $sql\n".$sth->errstr."\n";
       }
     }
     else {
       die "config: SQL error: " . $dbh->errstr . "\n";
     }
     $dbh->disconnect();
   }
   else {
     die "config: SQL error: " . DBI->errstr . "\n";
   }
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

1;
