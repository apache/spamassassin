# A very safe persistent address list implementation.  Uses filesystem
# operations that are known to be 100% safe on UNIX systems against
# concurrency issues and races.
#
package Mail::SpamAssassin::DirBasedAddrList;

use strict;

use Mail::SpamAssassin::PersistentAddrList;
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

  my $path = $main->sed_path ($main->{conf}->{auto_whitelist_path});
  if(!defined $path) {
    die "auto_whitelist_path not set";
  }

  $self->{dir} = $path;
  $self->{mode} = oct ($main->{conf}->{auto_whitelist_file_mode});

  bless ($self, $class);
  $self;
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr) = @_;

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

  dbg ("auto-whitelist (dir-based): permanent=$permfile, accumulator=$accumfile");

  my $entry = {
	addr			=> $addr,
	permanent_path		=> $permfile,
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
  dbg ("auto-whitelist (dir-based): $addr scores $count");
  $entry->{count} = $count;
  return $entry;
}

###########################################################################

sub increment_accumulator_for_entry {
  my ($self, $entry) = @_;

  my $path = $entry->{accumulator_path};
  my $dir = dirname ($path);

  if (-f $dir) {
    warn "auto-whitelist: $dir is a file, not dir: deleting\n";
    unlink ($dir);
  }

  if (!-d $dir) {
    if (!mkpath ($dir, 0, $self->{mode})) {
      warn "auto-whitelist: mkpath $dir failed\n";
      return;
    }
  }

  my $oldmask = umask ($self->{mode} ^ 0777);
  open (OUT, ">>$path") or warn "cannot append to $path failed";
  print OUT $entry->{addr}."\n";
  close OUT or warn "close append to $path failed";
  umask $oldmask;
}

###########################################################################

sub add_permanent_entry {
  my ($self, $entry) = @_;

  my $path = $entry->{permanent_path};
  my $dir = dirname ($path);

  if (!-d $dir) {
    if (!mkpath ($dir, 0, $self->{mode})) {
      warn "auto-whitelist: mkpath $dir failed\n";
      return;
    }
  }

  my $oldmask = umask ($self->{mode} ^ 0777);
  open (OUT, ">>$path") or warn "cannot append to $path failed";
  print OUT $entry->{addr}."\n";
  close OUT or warn "close append to $path failed";
  umask $oldmask;

  my $old = $entry->{accumulator_path};
  if (-f $old) { unlink ($old) or warn "unlink $old failed"; }
}

###########################################################################

sub remove_entry {
  my ($self, $entry) = @_;

  my $path = $entry->{accumulator_path};
  if (-f $path) {
    unlink ($path) or warn "unlink $path failed: $!\n";
  }

  my $addr = $entry->{addr};
  $path = $entry->{permanent_path};
  if (open (IN, "<$path")) {
    my $new = "$path.new.$$";
    my $bak = "$path.bak.$$";

    if (!open (OUT, ">$new")) {
      warn "cannot write to $new: $!\n"; goto failed;
    }
    while (<IN>) {
      chomp; ($_ eq $addr) and next;
      print OUT;
    }
    close IN;
    if (!close OUT) { warn "write failed to $new: $!\n"; goto failed; }

    if (!rename ($path, $bak)) { warn "rename failed for $path: $!"; goto failed; }
    if (!rename ($new, $path)) { warn "rename failed for $new: $!"; goto failed; }

failed:
    unlink ($bak);
  }
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
