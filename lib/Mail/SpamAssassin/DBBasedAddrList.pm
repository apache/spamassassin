# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::DBBasedAddrList;

use strict;
use bytes;
use Fcntl;

use Mail::SpamAssassin::PersistentAddrList;
use Mail::SpamAssassin::Util;

use vars qw{
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
    'locked_file'	=> ''
  };

  my $path;

  my $dbm_module = Mail::SpamAssassin::Util::first_available_module
			(qw(DB_File GDBM_File NDBM_File SDBM_File));

  my $umask = umask 0;
  if(defined($main->{conf}->{auto_whitelist_path})) # if undef then don't worry -- empty hash!
  {
    $path = $main->sed_path ($main->{conf}->{auto_whitelist_path});

    if ($main->{locker}->safe_lock
			($path, 30))
    {
      $self->{locked_file} = $path;
      $self->{is_locked} = 1;
      dbg("Tie-ing to DB file R/W in $path");
      tie %{$self->{accum}},$dbm_module,$path,
		  O_RDWR|O_CREAT,   #open rw w/lock
		  (oct ($main->{conf}->{auto_whitelist_file_mode}) & 0666)
	 or goto failed_to_tie;

    } else {
      $self->{is_locked} = 0;
      dbg("Tie-ing to DB file R/O in $path");
      tie %{$self->{accum}},$dbm_module,$path,
		  O_RDONLY,         #open ro w/o lock
		  (oct ($main->{conf}->{auto_whitelist_file_mode}) & 0666)
	 or goto failed_to_tie;
    }
  }
  umask $umask;

  bless ($self, $class);
  return $self;

failed_to_tie:
  umask $umask;
  if ($self->{is_locked}) {
    $self->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
  }
  die "Cannot open auto_whitelist_path $path: $!\n";
}

###########################################################################

sub finish {
  my $self = shift;
  dbg("DB addr list: untie-ing and unlocking.");
  untie %{$self->{accum}};
  if ($self->{is_locked}) {
    dbg ("DB addr list: file locked, breaking lock.");
    $self->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
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
  $entry->{totscore} = $self->{accum}->{$addr.'|totscore'} || 0;

  dbg ("auto-whitelist (db-based): $addr scores ".$entry->{count}.'/'.$entry->{totscore});
  return $entry;
}

###########################################################################

sub add_score {
    my($self, $entry, $score) = @_;

    $entry->{count} ||= 0;
    $entry->{addr}  ||= '';

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

  if ($addr =~ /^(.*)\|ip=none$/) {
    # it doesn't have an IP attached.
    # try to delete any per-IP entries for this addr as well.
    # could be slow...
    my $mailaddr = $1;
    my @keys = grep { /^\Q${mailaddr}\E\|ip=\d+\.\d+$/ }
					keys %{$self->{accum}};
    foreach my $key (@keys) {
      delete $self->{accum}->{$key};
      delete $self->{accum}->{$key.'|totscore'};
    }
  }
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
