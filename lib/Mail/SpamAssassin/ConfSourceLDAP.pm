=head1 NAME

Mail::SpamAssassin::ConfSourceLDAP - load SpamAssassin scores from LDAP database

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

package Mail::SpamAssassin::ConfSourceLDAP;

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
  dbg("LDAP: loading Net::LDAP and URI");
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
   dbg("LDAP: URL is $url");
   if(!defined($url) || $url eq '') {
     dbg ("LDAP: No URL defined; skipping LDAP");
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
     warn "failed to load user scores from LDAP server, ignored\n";
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
    dbg("LDAP: No server specified, assuming localhost");
    $host = "localhost";
  }
  my $port   = $uri->port;
  my $base   = $uri->dn;
  my @attr   = $uri->attributes;
  my $scope  = $uri->scope;
  my $filter = $uri->filter;
  my %extn   = $uri->extensions; # unused
  dbg("LDAP: host=$host, port=$port, base='$base', attr=${attr[0]}, scope=$scope, filter='$filter'");

  my $main = $self->{main};
  my $ldapuser = $main->{conf}->{user_scores_ldap_username};
  my $ldappass = $main->{conf}->{user_scores_ldap_password};
  dbg("LDAP: user=".$main->{conf}->{user_scores_ldap_username});
  #dbg("LDAP: pass=".$main->{conf}->{user_scores_ldap_password});

  my $f_attribute = $attr[0];

  my $ldap = Net::LDAP->new ("$host:$port", onerror => "warn");
  if (!defined($ldapuser) || !defined($ldappass)) {
    $ldap->bind;
  } else {
    $ldap->bind($ldapuser, password => $ldappass);
  }

  $filter =~ s/__USERNAME__/$username/g;
  my $result = $ldap->search( base => $base,
			      filter => $filter,
			      scope => $scope,
			      attrs => \@attr
                            );

  my $conf = '';
  foreach my $entry ($result->all_entries) {
    my @v = $entry->get_value($f_attribute);
    foreach my $v (@v) {
      dbg("LDAP: retrieving prefs for $username: $v");
      $conf .= $v."\n";
    }
  }
  $main->{conf}->parse_scores_only($conf);
  return;
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
