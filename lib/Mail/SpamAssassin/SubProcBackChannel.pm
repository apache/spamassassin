# back-channel for communication between a master and multiple slave processes.
#
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

package Mail::SpamAssassin::SubProcBackChannel;

use strict;
use warnings;
# use bytes;
use re 'taint';

use IO::Socket;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Constants qw(:sa);

our @ISA = qw();

=head1 NAME

Mail::SpamAssassin::SubProcBackChannel - back-channel for communication between a master and multiple slave processes

=head1 METHODS

=cut


###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  $self->{kids} = { };
  $self->{fileno_to_fh} = { };

  $self;
}

###########################################################################

sub set_selector {
  my ($self, $sel) = @_;
  $self->{selector} = $sel;
}

sub setup_backchannel_parent_pre_fork {
  my ($self) = @_;

  my $io = IO::Socket->new();
  ($self->{latest_kid_fh}, $self->{parent}) =
            $io->socketpair(AF_UNIX,SOCK_STREAM,PF_UNSPEC)
            or die "backchannel: socketpair failed: $!";

  # set those to use non-blocking I/O
  $self->{parent}->blocking(0)
            or die "backchannel: set non-blocking failed: $!";
  $self->{latest_kid_fh}->blocking(0)
            or die "backchannel: set non-blocking failed: $!";
}

sub setup_backchannel_parent_post_fork {
  my ($self, $pid) = @_;

  my $fh = $self->{latest_kid_fh};

  close $self->{parent}    # because it's us!
    or die "backchannel: error closing parent side of the pipe: $!";

  # disable caching for parent<->child relations
  my ($old) = select($fh);
  $| = 1;   # turn off buffering
  select($old);

  $self->{kids}->{$pid} = $fh;
  $self->add_to_selector($fh);
}

sub add_to_selector {
  my ($self, $fh) = @_;
  if (!defined $fh) {
    warn "undef fh in add_to_selector"; return;
  }
  my $fno = fileno($fh);
  $self->{fileno_to_fh}->{$fno} = $fh;
  vec (${$self->{selector}}, $fno, 1) = 1;
}

sub remove_from_selector {
  my ($self, $fh) = @_;
  if (!defined $fh) {
    warn "undef fh in remove_from_selector"; return;
  }
  my $fno = fileno($fh);
  delete $self->{fileno_to_fh}->{$fno};
  vec (${$self->{selector}}, $fno, 1) = 0;
}

sub select_vec_to_fh_list {
  my ($self, $vec) = @_;
  my $i = -1;

  # grotesque hackery alert! ;)   turn the vec() map of fds into a list of
  # filehandles.  note that filenos that don't have a filehandle in the
  # {fileno_to_fh} hash will be ignored; this is by design, so that other fhs
  # can be selected on using the same vec, and the caller can just check for
  # those in their own code, before they fall back to using this method.

  return grep {
        defined
      } map {
        $i++;
        ($_ ? $self->{fileno_to_fh}->{$i} : undef);
      } split (//, unpack ("b*", $vec));
}

sub get_socket_for_child {
  my ($self, $pid) = @_;
  return $self->{kids}->{$pid};
}

sub delete_socket_for_child {
  my ($self, $pid) = @_;
  delete $self->{kids}->{$pid};
}

###########################################################################

sub setup_backchannel_child_post_fork {
  my ($self) = @_;

  close $self->{latest_kid_fh}  # because it's us!
    or die "backchannel: error closing child side of the pipe: $!";

  my $old = select($self->{parent});
  $| = 1;   # print to parent by default, turn off buffering
  select($old);
}

sub get_parent_socket {
  my ($self) = @_;
  return $self->{parent};
}

############################################################################

1;

__END__

=head1 SEE ALSO

Mail::SpamAssassin(3)
Mail::SpamAssassin::ArchiveIterator(3)
Mail::SpamAssassin::SpamdPreforkScaling(3)
spamassassin(1)
spamd(1)
mass-check(1)
