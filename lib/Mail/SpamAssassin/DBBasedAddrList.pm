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

package Mail::SpamAssassin::DBBasedAddrList;

use strict;
use warnings;
# use bytes;
use re 'taint';
use Fcntl;

use Mail::SpamAssassin::PersistentAddrList;
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::PersistentAddrList);

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

  my @order = split(/\s+/, $main->{conf}->{auto_welcomelist_db_modules});
  untaint_var(\@order);
  my $dbm_module = Mail::SpamAssassin::Util::first_available_module (@order);
  if (!$dbm_module) {
    die "auto-welcomelist: cannot find a usable DB package from auto_welcomelist_db_modules: " .
	$main->{conf}->{auto_welcomelist_db_modules}."\n";
  }

  my $umask = umask ~ (oct($main->{conf}->{auto_welcomelist_file_mode}));

  # if undef then don't worry -- empty hash!
  if (defined($main->{conf}->{auto_welcomelist_path})) {
    my $path = $main->sed_path($main->{conf}->{auto_welcomelist_path});
    my ($mod1, $mod2);

    if ($main->{locker}->safe_lock
            ($path, 30, $main->{conf}->{auto_welcomelist_file_mode}))
    {
      $self->{locked_file} = $path;
      $self->{is_locked}   = 1;
      ($mod1, $mod2) = ('R/W', O_RDWR | O_CREAT);
    }
    else {
      $self->{is_locked} = 0;
      ($mod1, $mod2) = ('R/O', O_RDONLY);
    }

    dbg("auto-welcomelist: tie-ing to DB file of type $dbm_module $mod1 in $path");

    ($self->{is_locked} && $dbm_module eq 'DB_File') and
            Mail::SpamAssassin::Util::avoid_db_file_locking_bug($path);

    if (! tie %{ $self->{accum} }, $dbm_module, $path, $mod2,
            oct($main->{conf}->{auto_welcomelist_file_mode}) & 0666)
    {
      my $err = $!;   # might get overwritten later
      if ($self->{is_locked}) {
        $self->{main}->{locker}->safe_unlock($self->{locked_file});
        $self->{is_locked} = 0;
      }
      die "auto-welcomelist: cannot open auto_welcomelist_path $path: $err\n";
    }
  }
  umask $umask;

  bless ($self, $class);
  return $self;
}

###########################################################################

sub finish {
  my $self = shift;
  dbg("auto-welcomelist: DB addr list: untie-ing and unlocking");
  untie %{$self->{accum}};
  if ($self->{is_locked}) {
    dbg("auto-welcomelist: DB addr list: file locked, breaking lock");
    $self->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
  }
  # TODO: untrap signals to unlock the db file here
}

###########################################################################

sub get_addr_entry {
  my ($self, $addr, $signedby) = @_;

  my $entry = {
	addr			=> $addr,
  };

  $entry->{msgcount} = $self->{accum}->{$addr} || 0;
  $entry->{totscore} = $self->{accum}->{$addr.'|totscore'} || 0;

  dbg("auto-welcomelist: db-based $addr scores ".$entry->{msgcount}.'/'.$entry->{totscore});
  return $entry;
}

###########################################################################

sub add_score {
    my($self, $entry, $score) = @_;

    $entry->{msgcount} ||= 0;
    $entry->{addr}  ||= '';

    $entry->{msgcount}++;
    $entry->{totscore} += $score;

    dbg("auto-welcomelist: add_score: new count: ".$entry->{msgcount}.", new totscore: ".$entry->{totscore});

    $self->{accum}->{$entry->{addr}} = $entry->{msgcount};
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

    while (my ($key, $value) = each %{$self->{accum}}) {
      # regex will catch both key and key|totscore entries and delete them
      if ($key =~ /^\Q${mailaddr}\E\|/) {
        delete $self->{accum}->{$key};
      }
    }
  }
}

###########################################################################

1;
