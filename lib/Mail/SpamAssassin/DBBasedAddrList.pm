
package Mail::SpamAssassin::DBBasedAddrList;

use strict;

use Mail::SpamAssassin::PersistentAddrList;
use AnyDBM_File;
use Fcntl;

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

  tie %{$self->{accum}},"AnyDBM_File",$main->{conf}->{auto_whitelist_path}.'.accum',O_RDWR|O_CREAT|O_EXCL, oct ($main->{conf}->{auto_whitelist_file_mode})
      or die "Cannot open auto_whitelist_path.accum: $!\n";

   bless ($self, $class);
  $self;
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr) = @_;

  $addr = lc $addr;
  $addr =~ s/\000/_/gs;		# paranoia

  my $entry = {
	addr			=> $addr,
  };

  $entry->{count} = $self->{accum}->{$addr}+0;

  dbg ("auto-whitelist (dir-based): $addr scores ".$entry->{count});
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

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
