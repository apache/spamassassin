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

Mail::SpamAssassin::Conf::LDAP - load SpamAssassin scores from LDAP database

=head1 SYNOPSIS

  (see Mail::SpamAssassin)


=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blacklists.

This class is used internally by SpamAssassin to load scores from an LDAP
database.  Please refer to the C<Mail::SpamAssassin> documentation for public
interfaces.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::Conf::LDAP;

use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;

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
  dbg("ldap: loading Net::LDAP and URI");
  eval {
    require Net::LDAP; # actual server connection
    require URI;       # parse server connection dsn
  };

  # do any other preloading that will speed up operation
}

###########################################################################

=item $f->load ($username)

Read configuration paramaters from LDAP server and parse scores from it.

=cut

sub load {
   my ($self, $username) = @_;

   my $url = $self->{main}->{conf}->{user_scores_dsn}; # an ldap URI
   dbg("ldap: URL is $url");
   if(!defined($url) || $url eq '') {
     dbg("ldap: No URL defined; skipping LDAP");
     return;
   }

   eval {
     # make sure we can see croak messages from DBI
     local $SIG{'__DIE__'} = sub { warn "$_[0]"; };
     require Net::LDAP;
     require URI;
     load_with_ldap($self, $username, $url);
   };

   if ($@) {
     warn "ldap: failed to load user scores from LDAP server, ignored ($@)\n";
   }
}

sub load_with_ldap {
  my ($self, $username, $url) = @_;

#       ldapurl    = scheme "://" [hostport] ["/"
#                    [dn ["?" [attributes] ["?" [scope]
#                    ["?" [filter] ["?" extensions]]]]]]

  my $uri = URI->new("$url");

  my $host   = $uri->host;
  if (!defined($host) || $host eq '') {
    dbg("ldap: No server specified, assuming localhost");
    $host = "localhost";
  }
  my $port   = $uri->port;
  my $base   = $uri->dn;
  my @attr   = $uri->attributes;
  my $scope  = $uri->scope;
  my $filter = $uri->filter;
  my $schema = $uri->schema;
  my %extn   = $uri->extensions; # unused

  $filter =~ s/__USERNAME__/$username/g;
  dbg("ldap: host=$host, port=$port, base='$base', attr=${attr[0]}, scope=$scope, filter='$filter'");

  my $main = $self->{main};
  my $ldapuser = $main->{conf}->{user_scores_ldap_username};
  my $ldappass = $main->{conf}->{user_scores_ldap_password};

  if(!$ldapuser) {
      undef($ldapuser);
  } else {
      dbg("ldap: user='$ldapuser'");
  }

  if(!$ldappass) {
      undef($ldappass);
  } else {
      # don't log this to avoid leaking sensitive info
      # dbg("ldap: pass='$ldappass'");
  }

  my $f_attribute = $attr[0];

  my $ldap = Net::LDAP->new ("$host:$port",
                onerror => "warn",
                schema => $schema);

  if (!defined($ldapuser) && !defined($ldappass)) {
    $ldap->bind;
  } else {
    $ldap->bind($ldapuser, password => $ldappass);
  }

  my $result = $ldap->search( base => $base,
			      filter => $filter,
			      scope => $scope,
			      attrs => \@attr
                            );

  my $conf = '';
  foreach my $entry ($result->all_entries) {
    my @v = $entry->get_value($f_attribute);
    foreach my $v (@v) {
      dbg("ldap: retrieving prefs for $username: $v");
      $conf .= $v."\n";
    }
  }
  $main->{conf}->{main} = $main;
  $main->{conf}->parse_scores_only($conf);
  delete $main->{conf}->{main};
  return;
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

1;
