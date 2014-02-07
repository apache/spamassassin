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
use re 'taint';

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

=back

=cut

sub load {
   my ($self, $username) = @_;

   my $conf = $self->{main}->{conf};
   my $url = $conf->{user_scores_dsn}; # an ldap URI
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
     1;
   } or do {
     my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
     if ($conf->{user_scores_fail_to_global}) {
       info("ldap: failed to load user (%s) scores from LDAP server, ".
            "using a global default: %s", $username, $eval_stat);
       return 1;
     } else {
       warn sprintf(
              "ldap: failed to load user (%s) scores from LDAP server: %s\n",
               $username, $eval_stat);
       return 0;
     }
   };
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
  my $scheme = $uri->scheme;
  my %extn   = $uri->extensions; # unused

  $filter =~ s/__USERNAME__/$username/g;
  dbg("ldap: host=$host, port=$port, base='$base', attr=${attr[0]}, scope=$scope, filter='$filter'");

  my $main = $self->{main};
  my $conf = $main->{conf};
  my $ldapuser = $conf->{user_scores_ldap_username};
  my $ldappass = $conf->{user_scores_ldap_password};

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
                scheme => $scheme);

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

  my $config_text = '';
  foreach my $entry ($result->all_entries) {
    my @v = $entry->get_value($f_attribute);
    foreach my $v (@v) {
      dbg("ldap: retrieving prefs for $username: $v");
      $config_text .= $v."\n";
    }
  }
  if ($config_text ne '') {
    $conf->{main} = $main;
    $conf->parse_scores_only($config_text);
    delete $conf->{main};
  }
  return;
}

###########################################################################

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

###########################################################################

1;
