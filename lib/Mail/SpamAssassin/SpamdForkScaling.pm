# spamd prefork scaling, using an Apache-based algorithm
#
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

package Mail::SpamAssassin::SpamdForkScaling;

*dbg=\&Mail::SpamAssassin::dbg;

use strict;
use warnings;
use bytes;

use Mail::SpamAssassin::Util;

use vars qw {
  @PFSTATE_VARS %EXPORT_TAGS @EXPORT_OK
};

use base qw( Exporter );

@PFSTATE_VARS = qw(
  PFSTATE_ERROR PFSTATE_STARTING PFSTATE_IDLE PFSTATE_BUSY PFSTATE_KILLED
  PFORDER_ACCEPT
);

%EXPORT_TAGS = (
  'pfstates' => [ @PFSTATE_VARS ]
);
@EXPORT_OK = ( @PFSTATE_VARS );

use constant PFSTATE_ERROR       => -1;
use constant PFSTATE_STARTING    => 0;
use constant PFSTATE_IDLE        => 1;
use constant PFSTATE_BUSY        => 2;
use constant PFSTATE_KILLED      => 3;

use constant PFORDER_ACCEPT      => 10;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  $self->{kids} = { };
  $self->{overloaded} = 0;
  $self->{min_children} ||= 1;

  $self;
}

###########################################################################
# Parent methods

sub add_child {
  my ($self, $pid) = @_;
  $self->set_child_state ($pid, PFSTATE_STARTING);
}

sub child_exited {
  my ($self, $pid) = @_;
  delete $self->{kids}->{$pid};
}

sub set_child_state {
  my ($self, $pid, $state) = @_;
  $self->{kids}->{$pid} = $state;
  dbg ("prefork: child $pid: entering state $state");
  $self->compute_lowest_child_pid();
}

sub compute_lowest_child_pid {
  my ($self) = @_;

  my @pids = grep { $self->{kids}->{$_} == PFSTATE_IDLE }
        keys %{$self->{kids}};

  my $l = shift @pids;
  foreach my $p (@pids) {
    if ($l > $p) { $l = $p };
  }
  $self->{lowest_idle_pid} = $l;
}

###########################################################################

sub set_server_fh {
  my ($self, $fh) = @_;
  $self->{server_fh} = $fh;
  $self->{server_fileno} = $fh->fileno();
}

sub main_server_poll {
  my ($self, $tout) = @_;

  my $rin = ${$self->{backchannel}->{selector}};
  if ($self->{overloaded}) {
    # don't select on the server fh -- we already KNOW that's ready,
    # since we're overloaded
    vec($rin, $self->{server_fileno}, 1) = 0;
  }

  my ($rout, $eout, $nfound, $timeleft);

  # use alarm to back up select()'s built-in alarm, to debug theo's bug
  eval {
    Mail::SpamAssassin::Util::trap_sigalrm_fully(sub {
                          die "tcp timeout";
                        });
    alarm ($tout*2) if ($tout);
    ($nfound, $timeleft) = select($rout=$rin, undef, $eout=$rin, $tout);
  };
  alarm 0;

  if ($@) {
    warn "prefork: select timeout failed! recovering\n";
    sleep 1;        # avoid overload
    return;
  }

  if (!defined $nfound) {
    warn "prefork: select returned undef! recovering\n";
    sleep 1;        # avoid overload
    return;
  }

  # errors on the handle?
  # return them immediately, they may be from a SIGHUP restart signal
  if (vec ($eout, $self->{server_fileno}, 1)) {
    warn "prefork: select returned error on server filehandle: $!\n";
    return;
  }

  # any action?
  return unless ($nfound);

  # were the kids ready, or did we get signal?
  if (vec ($rout, $self->{server_fileno}, 1)) {
    # dbg("prefork: server fh ready");
    # the server socket: new connection from a client
    if (!$self->order_idle_child_to_accept()) {
      # dbg("prefork: no idle kids, noting overloaded");
      # there are no idle kids!  we're overloaded, mark that
      $self->{overloaded}++;
    }
    return;
  }

  foreach my $fh ($self->{backchannel}->select_vec_to_fh_list($rout))
  {
    # otherwise it's a status report from a child.
    # just read one line.  if there's more lines, we'll get them
    # when we re-enter the can_read() select call above...
    if ($self->read_one_line_from_child_socket($fh) == PFSTATE_IDLE)
    {
      dbg("prefork: child reports idle");
      if ($self->{overloaded}) {
        # if we were overloaded, then now that this kid is idle,
        # we can use it to handle the waiting connection.  zero
        # the overloaded flag, anyway; if there's >1 waiting
        # conn, they'll show up next time we do the select.

        dbg("prefork: overloaded, immediately telling kid to accept");
        if (!$self->order_idle_child_to_accept()) {
          # this should not happen
          warn "prefork: oops! still overloaded?";
        }
        dbg("prefork: no longer overloaded");
        $self->{overloaded} = 0;
      }
    }
  }

  # now that we've ordered some kids to accept any new connections,
  # increase/decrease the pool as necessary
  $self->adapt_num_children();
}

sub read_one_line_from_child_socket {
  my ($self, $sock) = @_;

  my $line = $sock->getline();
  if (!defined $line) {
    dbg ("prefork: child closed connection");

    # stop it being select'd
    vec(${$self->{backchannel}->{selector}}, $sock->fileno, 1) = 0;
    $sock->close();
    return PFSTATE_ERROR;
  }

  chomp $line;
  if ($line =~ /^I(\d+)/) {
    $self->set_child_state ($1, PFSTATE_IDLE);
    return PFSTATE_IDLE;
  }
  elsif ($line =~ /^B(\d+)/) {
    $self->set_child_state ($1, PFSTATE_BUSY);
    return PFSTATE_BUSY;
  }
  else {
    die "unknown message from child: '$line'";
    return PFSTATE_ERROR;
  }
}

###########################################################################

# we use the following protocol between the master and child processes to
# control when they accept/who accepts: server tells a child to accept with a
# "A\n", child responds with "B$pid\n" when it's busy, and "I$pid\n" once it's
# idle again.  Very simple, line-based protocol.

sub order_idle_child_to_accept {
  my ($self) = @_;

  my $kid = $self->{lowest_idle_pid};
  if (defined $kid) {
    my $sock = $self->{backchannel}->get_socket_for_child($kid);
    $sock->syswrite ("A\n");
    dbg ("prefork: ordered $kid to accept");

    # now wait for it to say it's done that
    return $self->wait_for_child_to_accept($sock);

  }
  else {
    dbg ("prefork: no spare children to accept, waiting for one to complete");
    return undef;
  }
}

sub wait_for_child_to_accept {
  my ($self, $sock) = @_;

  while (1) {
    my $state = $self->read_one_line_from_child_socket($sock);
    if ($state == PFSTATE_BUSY) {
      return 1;     # 1 == success
    }
    if ($state == PFSTATE_ERROR) {
      return undef;
    }
    else {
      die "prefork: ordered child to accept, but child reported state '$state'";
    }
  }
}

sub child_now_ready_to_accept {
  my ($self, $kid) = @_;
  if ($self->{waiting_for_idle_child}) {
    my $sock = $self->{backchannel}->get_socket_for_child($kid);
    $sock->syswrite ("A\n");
    $self->{waiting_for_idle_child} = 0;
  }
}

###########################################################################
# Child methods

sub set_my_pid {
  my ($self, $pid) = @_;
  $self->{pid} = $pid;  # save calling $$ all the time
}

sub update_child_status_idle {
  my ($self) = @_;
  $self->report_backchannel_socket("I".$self->{pid}."\n");
}

sub update_child_status_busy {
  my ($self) = @_;
  $self->report_backchannel_socket("B".$self->{pid}."\n");
}

sub report_backchannel_socket {
  my ($self, $str) = @_;
  my $sock = $self->{backchannel}->get_parent_socket();
  syswrite ($sock, $str)
        or write "syswrite() to parent failed: $!";
}

sub wait_for_orders {
  my ($self) = @_;

  my $sock = $self->{backchannel}->get_parent_socket();
  while (1) {
    my $line = $sock->getline();
    if (!defined($line)) {
      die "empty order from parent";
    }
    chomp $line;
    if (index ($line, "A") == 0) {  # string starts with "A" = accept
      return PFORDER_ACCEPT;
    }
    else {
      die "unknown order from parent: '$line'";
    }
  }
}

###########################################################################
# Master server code again

# this is pretty much the algorithm from perform_idle_server_maintainance() in
# Apache's "prefork" MPM.  However: we don't do exponential server spawning,
# since our servers are a lot more heavyweight than theirs is.

sub adapt_num_children {
  my ($self) = @_;

  my $kids = $self->{kids};
  my $statestr = '';
  my $num_idle = 0;
  my @pids = sort { $a <=> $b } keys %{$kids};
  my $num_servers = scalar @pids;

  foreach my $pid (@pids) {
    my $k = $kids->{$pid};
    if ($k == PFSTATE_IDLE) {
      $statestr .= 'I';
      $num_idle++;
    }
    elsif ($k == PFSTATE_BUSY) {
      $statestr .= 'B';
    }
    elsif ($k == PFSTATE_KILLED) {
      $statestr .= 'K';
    }
    elsif ($k == PFSTATE_ERROR) {
      $statestr .= 'E';
    }
    elsif ($k == PFSTATE_STARTING) {
      $statestr .= 'S';
    }
    else {
      $statestr .= '?';
    }
  }
  warn ("prefork: child states: ".$statestr."\n");

  # just kill off/add one at a time, to avoid swamping stuff and
  # reacting too quickly; Apache emulation
  if ($num_idle < $self->{min_idle}) {
    if ($num_servers < $self->{max_children}) {
      $self->need_to_add_server($num_idle);
    } else {
      warn "prefork: server reached --max-clients setting, consider raising it\n";
    }
  }
  elsif ($num_idle > $self->{max_idle} && $num_servers > $self->{min_children}) {
    $self->need_to_del_server($num_idle);
  }
}

sub need_to_add_server {
  my ($self, $num_idle) = @_;
  my $cur = ${$self->{cur_children_ref}};
  $cur++;
  dbg ("prefork: adjust: increasing, not enough idle children ($num_idle < $self->{min_idle})");
  main::spawn();
  # servers will be started once main_server_poll() returns
}

sub need_to_del_server {
  my ($self, $num_idle) = @_;
  my $cur = ${$self->{cur_children_ref}};
  $cur--;
  my $pid;
  foreach my $k (keys %{$self->{kids}}) {
    my $v = $self->{kids}->{$k};
    if ($v == PFSTATE_IDLE)
    {
      # kill the highest; Apache emulation, exploits linux scheduler
      # behaviour (and is predictable)
      if (!defined $pid || $k > $pid) {
        $pid = $k;
      }
    }
  }

  if (!defined $pid) {
    # this should be impossible. assert it
    die "oops! no idle kids in need_to_del_server?";
  }

  # warning: race condition if these two lines are the other way around.
  # see bug 3983, comment 37 for details
  $self->set_child_state ($pid, PFSTATE_KILLED);
  kill 'INT' => $pid;

  dbg ("prefork: adjust: decreasing, too many idle children ($num_idle > $self->{max_idle}), killed $pid");
}

1;

__END__
