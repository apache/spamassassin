
package Mail::SpamAssassin::DirBasedAddrList;

use strict;

use Mail::SpamAssassin;
use File::Basename;
use File::Path;

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
  };

  $self->{dir} = $main->{conf}->{auto_whitelist_dir};

  bless ($self, $class);
  $self;
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr) = @_;

  $addr = lc $addr;
  $addr =~ s/\000/_/gs;		# paranoia

  my $safe = $addr;
  $safe =~ s/[^-_a-z0-9]+/_/gs;
  $safe =~ s/^(.{0,255}).*$/$1/gs;

  my $sub1 = '_';
  my $sub2 = '_';
  my $sub3 = '_';
  $safe =~ s/^(..)// and $sub1 = $1;
  $safe =~ s/^(..)// and $sub2 = $1;
  $safe =~ s/^(..)// and $sub3 = $1;
  $safe ||= '_';		# ensure non-empty

  my $permfile = $self->{dir}."/permanent/$sub1/$sub2/$sub3";
  my $accumfile = $self->{dir}."/accumulator/$sub1/$sub2/$sub3/$safe";

  my $entry = {
	addr			=> $addr
	permanent_path		=> $permfile
	accumulator_path	=> $accumfile
  };

  my $count = 0;
  if (open (IN, "<$permfile")) {
    while (<IN>) {
      chomp;
      if ($_ eq $addr) { close IN; $count = 999; goto gotit; }
    }
    close IN;
  }

  if (open (IN, "<$accumfile")) {
    while (<IN>) {
      $count++;		# count the lines, easiest
    }
    close IN;
  }

gotit:
  $entry->{count} = $count;
  return $entry;
}

###########################################################################

sub increment_accumulator_for_entry {
  my ($self, $entry) = @_;

  my $path = $entry->{accumulator_path};
  my $dir = dirname ($path);

  if (!-d $dir) {
    mkpath ($dir, 0, 0700) or warn "mkpath $dir failed";
  }

  open (OUT, ">>$path") or warn "cannot append to $path failed";
  print OUT time()."\n";
  close OUT or warn "close append to $path failed";
}

###########################################################################

sub add_permanent_entry {
  my ($self, $entry) = @_;

  my $path = $entry->{permanent_path};
  my $dir = dirname ($path);

  if (!-d $dir) {
    mkpath ($dir, 0, 0700) or warn "mkpath $dir failed";
  }

  open (OUT, ">>$path") or warn "cannot append to $path failed";
  print OUT $entry->{addr};
  close OUT or warn "close append to $path failed";

  unlink ($entry->{accumulator_path})
  		or warn "unlink $entry->{accumulator_path} failed";
}

###########################################################################

1;
