
package Mail::SpamAssassin::DBBasedAddrList;

use strict;

# tell AnyDBM_File to prefer DB_File, if possible.
# BEGIN { @AnyDBM_File::ISA = qw(DB_File GDBM_File NDBM_File SDBM_File); }
# off until 3.0; there's lots of existing AWLs out there this breaks.

use AnyDBM_File;

use Mail::SpamAssassin::PersistentAddrList;
use Fcntl ':DEFAULT',':flock';
use Sys::Hostname;

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
    'is_locked'		=> 0,
    'lock_file'		=> '',
    'hostname'		=> hostname,
  };

  my $path;

  if(defined($main->{conf}->{auto_whitelist_path})) # if undef then don't worry -- empty hash!
  {
      $path = $main->sed_path ($main->{conf}->{auto_whitelist_path});

      #NFS Safe Lockng (I hope!)
      #Attempt to lock the dbfile, using NFS safe locking 
      #Locking code adapted from code by Alexis Rosen <alexis@panix.com>
      #Kelsey Cummings <kgc@sonic.net>
      my $lock_file = $self->{lock_file} = $path.'.lock';
      my $lock_tmp = $lock_file . '.' . $self->{hostname} . '.'. $$;
      my $max_lock_age = 300; #seconds 
      my $lock_tries = 30;

      open(LTMP, ">$lock_tmp") || die "Cannot create tmp lockfile $lock_file : $!\n";
      my $old_fh = select(LTMP);
      $|=1;
      select($old_fh);


      for (my $i = 0; $i < $lock_tries; $i++) #try $lock_tries (seconds) times to get lock
      {
         dbg("$$ Trying to get lock on $path pass $i");
	 print LTMP $self->{hostname}.".$$\n"; #updates tmp lockfile to current time
	 if ( link ($lock_tmp,$lock_file) )
	 {
	    
	    $self->{is_locked} = 1;
	    last;
	 } 
	 else
	 {
	    #link _may_ return false even if the link _is_ created

	    if ( (stat($lock_tmp))[3] > 1 ) {
	       $self->{is_locked} = 1;
	       last;
	    }
	       
	    #check to see how old the lockfile is
	    my $lock_age = (stat($lock_file))[10];
	    my $now = (stat($lock_tmp))[10];
	    if ($lock_age < $now - $max_lock_age) {
	       #we got a stale lock, break it
	       dbg("$$ Breaking Stale Lockfile!");
	       unlink "$lock_file";
	    }
	    sleep(1);
	 }
      }

      # TODO: trap signals to unlock the db file here on SIGINT and SIGTERM

      close(LTMP);
      unlink($lock_tmp);

      if ($self->{is_locked})
      {
	 dbg("Tie-ing to DB file R/W in $path");
	 tie %{$self->{accum}},"AnyDBM_File",$path, O_RDWR|O_CREAT,   #open rw w/lock
		       (oct ($main->{conf}->{auto_whitelist_file_mode}) & 0666)
	     or goto failed_to_tie;
      } 
      else 
      {
	 dbg("Tie-ing to DB file R/O in $path");
	 tie %{$self->{accum}},"AnyDBM_File",$path, O_RDONLY,         #open ro w/o lock
		       (oct ($main->{conf}->{auto_whitelist_file_mode}) & 0666)
	     or goto failed_to_tie;
      } 
  }

  bless ($self, $class);
  return $self;

failed_to_tie:
  unlink($self->{lock_file}) ||
     dbg ("Couldn't unlink " . $self->{lock_file} . ": $!\n");
  die "Cannot open auto_whitelist_path $path: $!\n";
}

###########################################################################

sub finish {
    my $self = shift;
    dbg("DB addr list: untie-ing and destroying lockfile.");
    untie %{$self->{accum}};
    if ($self->{is_locked}) {
       dbg ("DB addr list: file locked, breaking lock.");
       unlink($self->{lock_file}) ||
          dbg ("Couldn't unlink " . $self->{lock_file} . ": $!\n");
    }
    # TODO: untrap signals to unlock the db file here
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr) = @_;

  my $entry = {
	addr			=> $addr,
  };

  $entry->{count} = $self->{accum}->{$addr} || 0;
  $entry->{totscore} = $self->{accum}->{$addr.'|totscore'};

  # if we had old-style AWL DB, ie no totscore, then just pretend we never saw this address before
  if(!defined($entry->{totscore}))
  {
      $entry->{totscore} = 0;
      $entry->{count} = 0;
  }

  dbg ("auto-whitelist (db-based): $addr scores ".$entry->{count}.'/'.$entry->{totscore});
  return $entry;
}

###########################################################################

sub add_score {
    my($self, $entry, $score) = @_;

    $entry->{count}++;
    $entry->{totscore} += $score;

    dbg("add_score: New count: ".$entry->{count}.", new totscore: ".$entry->{totscore});

    $self->{accum}->{$entry->{addr}} = $entry->{count};
    $self->{accum}->{$entry->{addr}.'|totscore'} = $entry->{totscore};
    return $entry;
}

###########################################################################

sub remove_entry {
  my ($self, $entry) = @_;

  my $addr = $entry->{addr};
  delete $self->{accum}->{$addr};
  delete $self->{accum}->{$addr.'|totscore'};

  # try to delete any per-IP entries for this addr as well.
  # could be slow...
  my @keys = grep { /^\Q$addr\E\|ip=/ } keys %{$self->{accum}};
  foreach my $key (@keys) {
    delete $self->{accum}->{$key};
    delete $self->{accum}->{$key.'|totscore'};
  }
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
