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

Mail::SpamAssassin::ConfSourceSQL - load SpamAssassin scores from SQL database

=head1 SYNOPSIS

  (see Mail::SpamAssassin)
  

=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists.

This class is used internally by SpamAssassin to load scores from an SQL
database.  Please refer to the C<Mail::SpamAssassin> documentation for public
interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::ConfSourceSQL;

use strict;
use bytes;
use Carp;

use vars qw{
  @ISA
};

@ISA = qw();

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

=item $f->load ($username)

Read configuration paramaters from SQL database and parse scores from it.

=cut

sub load {
   my ($self, $username) = @_;

   my $dsn = $self->{main}->{conf}->{user_scores_dsn};
   if(!defined($dsn) || $dsn eq '') {
     dbg ("No DSN defined; skipping sql");
     return;
   }

   eval {
     # make sure we can see croak messages from DBI
     local $SIG{'__DIE__'} = sub { warn "$_[0]"; };
     require DBI;
     load_with_dbi($self, $username, $dsn);
   };

   if ($@) {
     warn "failed to load user scores from SQL database, ignored\n";
   }
}

sub load_with_dbi {
   my ($self, $username, $dsn) = @_;

   my $main = $self->{main};
   my $dbuser = $main->{conf}->{user_scores_sql_username};
   my $dbpass = $main->{conf}->{user_scores_sql_password};

   # REIMPLEMENT: use settings from $main->{conf} here
   my $f_preference = 'preference';
   my $f_value = 'value';
   my $f_username = 'username';
   my $f_table = 'userpref';

   my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

   if($dbh) {
      my $sql = "select $f_preference, $f_value  from $f_table where ". 
        "$f_username = ".$dbh->quote($username).
        " or $f_username = 'GLOBAL'".
        " or $f_username = '\@GLOBAL' order by $f_username asc";

      my $sth = $dbh->prepare($sql);
      if($sth) {
         my $rv  = $sth->execute();
         if($rv) {
            dbg("retrieving prefs for $username from SQL server");
            my @row;
            my $text = '';
            while(@row = $sth->fetchrow_array()) {
               $text .= "$row[0]\t$row[1]\n";
            }
            if($text ne '') {
            	$main->{conf}->parse_scores_only(join('',$text));
            }
            $sth->finish();
         } else { warn "SQL Error: $sql\n".$sth->errstr."\n"; }
      } else { warn "SQL Error: " . $dbh->errstr . "\n"; }
   $dbh->disconnect();
   } else { warn "SQL Error: " . DBI->errstr . "\n"; }
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
