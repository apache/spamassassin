# Mail::SpamAssassin::ConfSourceSQL - load scores from SQL database

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
   my $table = $main->{conf}->{user_scores_sql_table};

   my $dbh = DBI->connect($dsn, $dbuser, $dbpass, {'PrintError' => 0});

   if($dbh) {
      my $sql = "select preference, value  from $table where ". 
        "username = ".$dbh->quote($username).
        " or username = 'GLOBAL'".
        " or username = '\@GLOBAL' order by username asc";

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

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

###########################################################################

1;
