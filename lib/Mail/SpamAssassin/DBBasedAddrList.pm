
package Mail::SpamAssassin::DBBasedAddrList;

use strict;

use Mail::SpamAssassin::PersistentAddrList;
use AnyDBM_File;
use Fcntl ':DEFAULT',':flock';

use vars	qw{
  	@ISA
};

@ISA = qw(Mail::SpamAssassin::PersistentAddrList);

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new(@_);
  $self->{class} = $class;
  bless ($self, $class);
  $self;
}

###########################################################################

sub new_checker {
  my ($factory, $main) = @_;
  my $class = $factory->{class};

  my $self = {
    'main'		=> $main,
    'accum'             => { },
  };

  if(defined($main->{conf}->{auto_whitelist_path})) # if undef then don't worry -- empty hash!
  {
      my $path = $main->sed_path ($main->{conf}->{auto_whitelist_path});
      my $lock_file = $path.'.lock';

      open(LOCKFILE,">>$lock_file") or die "Can't open lockfile $lock_file: $!\n";
      flock(LOCKFILE, LOCK_EX) or die "Can't acquire lock: $!\n";

      dbg("Tie-ing to DB file in ",$path);
      tie %{$self->{accum}},"AnyDBM_File",$path, O_RDWR|O_CREAT,
		    (oct ($main->{conf}->{auto_whitelist_file_mode}) & 0666)
	  or die "Cannot open auto_whitelist_path $path: $!\n";
  }

   bless ($self, $class);
  $self;
}

###########################################################################

sub finish {
    my $self = shift;
    untie %{$self->{accum}};
    flock(LOCKFILE, LOCK_UN);
    close(LOCKFILE);
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr) = @_;

  my $entry = {
	addr			=> $addr,
  };

  $entry->{count} = $self->{accum}->{$addr} || 0;

  dbg ("auto-whitelist (db-based): $addr scores ".$entry->{count});
  return $entry;
}

###########################################################################

sub increment_accumulator_for_entry {
  my ($self, $entry) = @_;

  $self->{accum}->{$entry->{addr}} = $entry->{count}+1;
}

###########################################################################

sub add_permanent_entry {
  my ($self, $entry) = @_;

  $self->{accum}->{$entry->{addr}} = 999;
}

sub remove_entry {
  my ($self, $entry) = @_;
  delete $self->{accum}->{$entry->{addr}};
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
