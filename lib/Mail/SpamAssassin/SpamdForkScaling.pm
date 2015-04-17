# spamd prefork scaling, using an Apache-based algorithm
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

package Mail::SpamAssassin::SpamdForkScaling;

use strict;
use warnings;
use bytes;
use re 'taint';
use Errno qw();

use Mail::SpamAssassin::Util qw(am_running_on_windows);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;

use vars qw {
  @PFSTATE_VARS %EXPORT_TAGS @EXPORT_OK
};

use base qw( Exporter );

@PFSTATE_VARS = qw(
  PFSTATE_ERROR PFSTATE_STARTING PFSTATE_IDLE PFSTATE_BUSY PFSTATE_KILLED
  PFORDER_ACCEPT PFSTATE_GOT_SIGCHLD
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
use constant PFSTATE_GOT_SIGCHLD => 4;

use constant PFORDER_ACCEPT      => 10;

###########################################################################

# change to 1 to enable the below test instrumentation points
use constant SUPPORT_TEST_INSTRUMENTATION => 0;

# test instrumentation point: simulate random child failures in 1 in
# every N lookups
our $TEST_MODE_CAUSE_RANDOM_KID_FAILURES = 0;

# test instrumentation point: simulate child->parent and parent->child
# write failures (needing retries) once in every N syswrite()s
our $TEST_MODE_CAUSE_RANDOM_WRITE_RETRIES = 0;

# test instrumentation point: simulate ping failures (for unspecified
# reasons) once in every N pings
our $TEST_MODE_CAUSE_RANDOM_PING_FAILURES = 0;

###########################################################################

# we use the following protocol between the master and child processes to
# control when they accept/who accepts: server tells a child to accept with a
# PF_ACCEPT_ORDER, child responds with "B$pid\n" when it's busy, and "I$pid\n"
# once it's idle again.  In addition, the parent sends PF_PING_ORDER
# periodically to ping the child processes.  Very simple protocol.  Note that
# the $pid values are packed into 4 bytes so that the buffers are always of a
# known length; if you need to transfer longer data, assign a new protocol verb
# (the first char) and use the length of the following data buffer as the
# packed value.
use constant PF_ACCEPT_ORDER     => "A....\n";
use constant PF_PING_ORDER       => "P....\n";

# timeout for a sysread() on the command channel.  if we go this long
# without a message from the spamd parent or child, it's an error.
use constant TOUT_READ_MAX       => 300;

# interval between "ping" messages from the spamd parent to all children,
# used as a sanity check to ensure TOUT_READ_MAX isn't hit when things
# are functional.
use constant TOUT_PING_INTERVAL  => 150;

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
  $self->{server_last_ping} = time;

  $self;
}

###########################################################################
# Parent methods

sub add_child {
  my ($self, $pid) = @_;
  $self->set_child_state ($pid, PFSTATE_STARTING);
}

# this is called by the SIGCHLD handler in spamd.  The idea is that
# main_ping_kids etc. can mark a child as probably dead ("K" state), but until
# SIGCHLD is received, the process is still around (in some form), so it
# shouldn't be removed from the list until it's confirmed dead.
#
sub child_exited {
  my ($self, $pid) = @_;

  dbg("prefork: child $pid: just exited");

  # defer removal from the list until after return from the signal
  # handler; it seems that we may be corrupting the list structure
  # by deleting the {kids} hash entry from a sig handler. (bug 5422)
  $self->set_child_state ($pid, PFSTATE_GOT_SIGCHLD);

  # note this for the select()-caller's benefit
  $self->{child_just_exited} = 1;
}
 
sub post_sigchld_cleanup {
  my ($self) = @_;
  my @pids = grep { $self->{kids}->{$_} == PFSTATE_GOT_SIGCHLD }
        keys %{$self->{kids}};
  return unless @pids;

  foreach my $pid (@pids) {
    delete $self->{kids}->{$pid};       # remove from list

    # remove the child from the backchannel list, too
    $self->{backchannel}->delete_socket_for_child($pid);
  }

  # ensure we recompute, so that we don't try to tell that child to
  # accept a request, only to find that it's died in the meantime.
  $self->compute_lowest_child_pid();
}

# this is called by SIGTERM and SIGHUP handlers, to ensure that new
# kids aren't added while the main code is killing the old ones
# and planning to exit.
#
sub set_exiting_flag {
  my ($self) = @_;
  $self->{am_exiting} = 1;
}

sub child_error_kill {
  my ($self, $pid, $sock) = @_;

  warn "prefork: killing failed child $pid fd=".
    ((defined $sock && defined $sock->fileno) ? $sock->fileno : "undefined");

  # close the socket and remove the child from our list
  $self->set_child_state ($pid, PFSTATE_KILLED);

  #Bug 6304 research
  #info("6304: prefork: child_error_kill called - %s", $pid);
  kill 'INT' => $pid
    or warn "prefork: kill of failed child $pid failed: $!\n";

  $self->{backchannel}->delete_socket_for_child($pid);

  if (defined $sock && defined $sock->fileno()) {
    $self->{backchannel}->remove_from_selector($sock);
  }

  if ($sock) {
    $sock->close or info("prefork: error closing socket: $!");
  }

  delete $self->{kids}->{$pid};       # remove from list

  # ensure we recompute, so that we don't try to tell that child to
  # accept a request, only to find that it's died in the meantime.
  $self->compute_lowest_child_pid();

  warn "prefork: killed child $pid\n";
}

sub set_child_state {
  my ($self, $pid, $state) = @_;

  # I keep misreading this -- so: this says, if the child is starting, or is
  # dying, or it has an entry in the {kids} hash, then allow the state to be
  # set.  otherwise the update can be ignored.
  if ($state == PFSTATE_STARTING || $state == PFSTATE_KILLED ||
        $state == PFSTATE_GOT_SIGCHLD || exists $self->{kids}->{$pid})
  {
    $self->{kids}->{$pid} = $state;
    dbg("prefork: child $pid: entering state $state");
    $self->compute_lowest_child_pid();

  } else {
    dbg("prefork: child $pid: ignored new state $state, already exited?");
  }
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

  dbg("prefork: new lowest idle kid: ".
            ($self->{lowest_idle_pid} ? $self->{lowest_idle_pid} : 'none'));
}

###########################################################################

sub set_server_fh {
  my ($self, @fhs) = @_;

  $self->{server_fh} = [];
  $self->{server_fileno} = [];

  foreach my $fh (@fhs) {
    next unless defined $fh;
    push @{$self->{server_fh}}, $fh;
    push @{$self->{server_fileno}}, $fh->fileno();
  }
}

sub main_server_poll {
  my ($self, $tout) = @_;

  my $rin = ${$self->{backchannel}->{selector}};
  if ($self->{overloaded}) {
    # don't select on the server fh -- we already KNOW that's ready,
    # since we're overloaded
    $self->vec_all(\$rin, $self->{server_fileno}, 0);
  }

  # clean up any fresh zombies before we select()
  $self->post_sigchld_cleanup();

  my ($rout, $eout, $nfound, $timeleft, $selerr);

  # use alarm to back up select()'s built-in alarm, to debug Theo's bug.
  # not that I can remember what Theo's bug was, but hey ;)    A good
  # 60 seconds extra on the alarm() should make that quite rare...

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => ($tout*2) + 60 });

  $timer->run(sub {

    # right before select() syscall, but after alarm(), eval scope, etc.
    $self->{child_just_exited} = 0;     
    ($nfound, $timeleft) = select($rout=$rin, undef, $eout=$rin, $tout);
    $selerr = $!  if !defined $nfound || $nfound < 0;

  });

  # in case any kids exited during select()
  $self->post_sigchld_cleanup();

  # bug 4696: under load, the process can go for such a long time without
  # being context-switched in, that when it does return the alarm() fires
  # before the select() timeout does.   Treat this as a select() timeout
  if ($timer->timed_out) {
    dbg("prefork: select timed out (via alarm)");
    $nfound = 0;
    $timeleft = 0;
  }

  # errors; handle undef *or* -1 returned.  do this before "errors on
  # the handle" below, since an error condition is signalled both via
  # a -1 return and a $eout bit.
  if (!defined $nfound || $nfound < 0)
  {
    if (exists &Errno::EINTR && $selerr == &Errno::EINTR)
    {
      # this happens if the process is signalled during the select(),
      # for example if someone sends SIGHUP to reload the configuration.
      # just return inmmediately
      dbg("prefork: select returned err $selerr, probably signalled");
      return;
    }

    # if a child exits during that select() call, it generates a spurious
    # error, like this:
    #
    # Jan 29 12:53:17 dogma spamd[18518]: prefork: child states: BI
    # Jan 29 12:53:17 dogma spamd[18518]: spamd: handled cleanup of child pid 13101 due to SIGCHLD
    # Jan 29 12:53:17 dogma spamd[18518]: prefork: select returned -1! recovering:
    #
    # avoid by setting a boolean in the child_exited() callback and checking
    # it here.  log $! just in case, though.
    if ($self->{child_just_exited} && $nfound == -1) {
      dbg("prefork: select returned -1 due to child exiting, ignored ($selerr)");
      return;
    }

    warn "prefork: select returned ".
            (defined $nfound ? $nfound : "undef").
            "! recovering: $selerr\n";

    sleep 1;        # avoid overload
    return;
  }

  # errors on the handle?
  # return them immediately, they may be from a SIGHUP restart signal
  if ($self->vec_all(\$eout, $self->{server_fileno})) {
    warn "prefork: select returned error on server filehandle: $selerr $!\n";
    return;
  }

  # any action?
  if (!$nfound) {
    # none.  periodically ping the children though just to ensure
    # they're still alive and can hear us
    
    my $now = time;
    if ($now - $self->{server_last_ping} > TOUT_PING_INTERVAL) {
      $self->main_ping_kids($now);
    }
    return;
  }

  # were the kids ready, or did we get signal?
  if ($self->vec_all(\$rout, $self->{server_fileno})) {
    # dbg("prefork: server fh ready");
    # the server socket: new connection from a client
    if (!$self->order_idle_child_to_accept()) {
      # dbg("prefork: no idle kids, noting overloaded");
      # there are no idle kids!  we're overloaded, mark that
      $self->{overloaded} = 1;
    }
    return;
  }

  # otherwise it's a status report from a child.
  foreach my $fh ($self->{backchannel}->select_vec_to_fh_list($rout))
  {
    # just read one line.  if there's more lines, we'll get them
    # when we re-enter the can_read() select call above...
    if ($self->read_one_message_from_child_socket($fh) == PFSTATE_IDLE)
    {
      dbg("prefork: child reports idle");
      if ($self->{overloaded}) {
        # if we were overloaded, then now that this kid is idle,
        # we can use it to handle the waiting connection.  zero
        # the overloaded flag, anyway; if there's >1 waiting
        # conn, they'll show up next time we do the select.

        dbg("prefork: overloaded, immediately telling kid to accept");
        if (!$self->order_idle_child_to_accept()) {
          # this can happen if something is buggy in the child, and
          # it has to be killed, resulting in no idle kids left
          warn "prefork: lost idle kids, so still overloaded";
          $self->{overloaded} = 1;
        }
        else {
          dbg("prefork: no longer overloaded");
          $self->{overloaded} = 0;
        }
      }
    }
  }

  # now that we've ordered some kids to accept any new connections,
  # increase/decrease the pool as necessary
  $self->adapt_num_children();
}

sub main_ping_kids {
  my ($self, $now) = @_;

  $self->{server_last_ping} = $now;

  keys %{$self->{backchannel}->{kids}};     # reset each() iterator
  my ($sock, $kid);
  while (($kid, $sock) = each %{$self->{backchannel}->{kids}}) {
    # if the file handle is still defined ping the child
    # bug 4852: if not, we've run into a race condition with the child's
    # SIGCHLD handler... try killing again just in case something else happened

    if (SUPPORT_TEST_INSTRUMENTATION && $TEST_MODE_CAUSE_RANDOM_PING_FAILURES &&
              rand $TEST_MODE_CAUSE_RANDOM_PING_FAILURES < 1)
    {
      warn "prefork: TEST_MODE_CAUSE_RANDOM_PING_FAILURES simulating ping failure";
    }
    elsif (defined $sock && defined $sock->fileno) {
      $self->syswrite_with_retry($sock, PF_PING_ORDER, $kid, 3) and next;
      warn "prefork: write of ping failed to $kid fd=".$sock->fileno.": ".$!;
    }
    else {
      warn "prefork: cannot ping $kid, file handle not defined, child likely ".
	   "to still be processing SIGCHLD handler after killing itself\n";
    }

    # note: this is safe according to the note in perldoc -f each; 'it is
    # always safe to delete the item most recently returned by each()'
    $self->child_error_kill($kid, $sock);
  }
}

sub read_one_message_from_child_socket {
  my ($self, $sock) = @_;

  # "I  b1 b2 b3 b4 \n " or "B  b1 b2 b3 b4 \n "
  my $line;
  my $nbytes = $self->sysread_with_timeout($sock, \$line, 6, TOUT_READ_MAX);

  if (!defined $nbytes || $nbytes == 0) {
    dbg("prefork: child closed connection");

    # stop it being select'd
    my $fno = $sock->fileno;
    if (defined $fno) {
      $self->{backchannel}->remove_from_selector($sock);
      $sock->close or info("prefork: error closing socket: $!");
    }

    return PFSTATE_ERROR;
  }
  if ($nbytes < 6) {
    warn("prefork: child gave short message: len=$nbytes bytes=".
	 join(" ", unpack "C*", $line));
  }

  chomp $line;
  if ($line =~ s/^I//) {
    my $pid = unpack("l1", $line);      # signed, as 'N' causes win32 bugs (bug 6356)
    $self->set_child_state ($pid, PFSTATE_IDLE);
    return PFSTATE_IDLE;
  }
  elsif ($line =~ s/^B//) {
    my $pid = unpack("l1", $line);
    $self->set_child_state ($pid, PFSTATE_BUSY);
    return PFSTATE_BUSY;
  }
  else {
    die "prefork: unknown message from child: '$line'";
    return PFSTATE_ERROR;
  }
}

###########################################################################

sub order_idle_child_to_accept {
  my ($self) = @_;

  my $kid = $self->{lowest_idle_pid};
  if (defined $kid)
  {
    my $sock = $self->{backchannel}->get_socket_for_child($kid);

    if (SUPPORT_TEST_INSTRUMENTATION && $TEST_MODE_CAUSE_RANDOM_KID_FAILURES) {
      if (rand $TEST_MODE_CAUSE_RANDOM_KID_FAILURES < 1) {
        $sock = undef; warn "prefork: TEST_MODE_CAUSE_RANDOM_KID_FAILURES simulating no socket for kid $kid";
      }
    }

    if (!$sock)
    {
      # this should not happen, but if it does, trap it here
      # before we attempt to call a method on an undef object
      warn "prefork: oops! no socket for child $kid, killing";
      $self->child_error_kill($kid, $sock);

      # retry with another child
      return $self->order_idle_child_to_accept();
    }

    if (!$self->syswrite_with_retry($sock, PF_ACCEPT_ORDER, $kid))
    {
      # failure to write to the child; bad news.  call it dead
      warn "prefork: killing rogue child $kid, failed to write on fd ".$sock->fileno.": $!\n";
      $self->child_error_kill($kid, $sock);

      # retry with another child
      return $self->order_idle_child_to_accept();
    }

    dbg("prefork: ordered $kid to accept");

    # now wait for it to say it's done that
    my $ret = $self->wait_for_child_to_accept($kid, $sock);
    if ($ret) {
      return $ret;
    } else {
      # retry with another child
      return $self->order_idle_child_to_accept();
    }

  }
  else {
    dbg("prefork: no spare children to accept, waiting for one to complete");
    return;
  }
}

sub wait_for_child_to_accept {
  my ($self, $kid, $sock) = @_;

  while (1) {
    my $state = $self->read_one_message_from_child_socket($sock);

    if ($state == PFSTATE_BUSY) {
      return 1;     # 1 == success
    }
    if ($state == PFSTATE_ERROR) {
      return;
    }
    else {
      warn "prefork: ordered child $kid to accept, but they reported state '$state', killing rogue";
      $self->child_error_kill($kid, $sock);
      $self->adapt_num_children();
      sleep 1;

      return;
    }
  }
}

sub child_now_ready_to_accept {
  my ($self, $kid) = @_;
  if ($self->{waiting_for_idle_child}) {
    my $sock = $self->{backchannel}->get_socket_for_child($kid);
    $self->syswrite_with_retry($sock, PF_ACCEPT_ORDER, $kid)
        or die "prefork: $kid claimed it was ready, but write failed on fd ".
                            $sock->fileno.": ".$!;
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
  # "I  b1 b2 b3 b4 \n "
  $self->report_backchannel_socket("I".pack("l",$self->{pid})."\n");
}

sub update_child_status_busy {
  my ($self) = @_;
  # "B  b1 b2 b3 b4 \n "
  $self->report_backchannel_socket("B".pack("l",$self->{pid})."\n");
}

sub report_backchannel_socket {
  my ($self, $str) = @_;
  my $sock = $self->{backchannel}->get_parent_socket();
  $self->syswrite_with_retry($sock, $str, 'parent')
        or die "syswrite() to parent failed: $!";
}

sub wait_for_orders {
  my ($self) = @_;

  my $sock = $self->{backchannel}->get_parent_socket();
  while (1) {
    # "A  .  .  .  .  \n "
    my $line;
    my $nbytes = $self->sysread_with_timeout($sock, \$line, 6, TOUT_READ_MAX);
    if (!defined $nbytes || $nbytes == 0) {
      if ($sock->eof()) {
        dbg("prefork: parent closed, exiting");
        exit;
      }
      die "prefork: empty order from parent";
    }
    if ($nbytes < 6) {
      warn("prefork: parent gave short message: len=$nbytes bytes=".
	   join(" ", unpack "C*", $line));
    }

    chomp $line;
    if (index ($line, "P") == 0) {  # string starts with "P" = ping
      dbg("prefork: periodic ping from spamd parent");
      if (am_running_on_windows()) {
        sleep 2;  # need this on win32 so that a child can get a signal
      }
      next;
    }
    if (index ($line, "A") == 0) {  # string starts with "A" = accept
      return PFORDER_ACCEPT;
    }
    else {
      die "prefork: unknown order from parent: '$line'";
    }
  }
}

###########################################################################

sub sysread_with_timeout {
  my ($self, $sock, $lineref, $toread, $timeout) = @_;

  $$lineref = '';   # clear the output buffer
  my $readsofar = 0;
  my $deadline; # we only set this if the first read fails
  my $buf;

retry_read:
  my $nbytes = $sock->sysread($buf, $toread);

  if (!defined $nbytes) {
    unless ((exists &Errno::EAGAIN && $! == &Errno::EAGAIN)
        || (exists &Errno::EWOULDBLOCK && $! == &Errno::EWOULDBLOCK))
    {
      # an error that wasn't non-blocking I/O-related.  that's serious
      return;
    }

    # ok, we didn't get it first time.  we'll have to start using
    # select() and timeouts (which is slower).  Don't warn just yet,
    # as it's quite acceptable in our design to have to "block" on
    # sysread()s here.

    my $now = time();
    my $tout = $timeout;
    if (!defined $deadline) {
      # set this.  it'll be close enough ;)
      $deadline = $now + $timeout;
    }
    elsif ($now > $deadline) {
      # timed out!  report failure
      dbg("prefork: sysread(%d) failed after %.1f secs",
          $sock->fileno, $timeout);
      return;
    }
    else {
      $tout = $deadline - $now;     # the remaining timeout
      $tout = 1 if ($tout <= 0);    # ensure it's > 0
    }

    dbg("prefork: sysread(%d) not ready, wait max %.1f secs",
        $sock->fileno, $tout);
    my $rin = '';
    vec($rin, $sock->fileno, 1) = 1;
    my $nfound = select($rin, undef, undef, $tout);
    defined $nfound && $nfound >= 0
      or info("prefork: sysread_with_timeout select error: %s", $!);
    goto retry_read;

  }
  elsif ($nbytes == 0) {        # EOF
    return $readsofar;          # may be a partial read, or 0 for EOF

  }
  elsif ($nbytes == $toread) {  # a complete read, nice.
    $readsofar += $nbytes;
    $$lineref .= $buf;
    return $readsofar;

  }
  else {
    # we want to know about this.  this is not supposed to happen!
    warn "prefork: partial read of $nbytes, toread=".$toread.
            "sofar=".$readsofar." fd=".$sock->fileno.", recovering";
    $readsofar += $nbytes;
    $$lineref .= $buf;
    $toread -= $nbytes;
    goto retry_read;
  }

  die "assert: should not get here";
}

sub syswrite_with_retry {
  my ($self, $sock, $buf, $targetname, $numretries) = @_;
  $numretries ||= 10;       # default 10 retries

  my $written = 0;
  my $try = 0;

retry_write:

  $try++;
  if ($try > 1) {
    warn "prefork: syswrite(".$sock->fileno.") to $targetname failed on try $try";
    if ($try > $numretries) {
      warn "prefork: giving up";
      return;
    }
    else {
      # give it 1 second to recover
      my $rout = '';
      vec($rout, $sock->fileno, 1) = 1;
      my $nfound = select(undef, $rout, undef, 1);
      defined $nfound && $nfound >= 0
        or info("prefork: syswrite_with_retry select error: %s", $!);
    }
  }

  my $nbytes;
  if (SUPPORT_TEST_INSTRUMENTATION && $TEST_MODE_CAUSE_RANDOM_WRITE_RETRIES &&
            rand $TEST_MODE_CAUSE_RANDOM_WRITE_RETRIES < 1)
  {
    warn "prefork: TEST_MODE_CAUSE_RANDOM_WRITE_RETRIES simulating write failure";
    $nbytes = undef; $! = &Errno::EAGAIN;
  }
  else {
    $nbytes = $sock->syswrite($buf);
  }

  if (!defined $nbytes) {
    unless ((exists &Errno::EAGAIN && $! == &Errno::EAGAIN)
        || (exists &Errno::EWOULDBLOCK && $! == &Errno::EWOULDBLOCK))
    {
      # an error that wasn't non-blocking I/O-related.  that's serious
      return;
    }

    warn "prefork: retrying syswrite(): $!";
    goto retry_write;
  }
  else {
    $written += $nbytes;
    $buf = substr($buf, $nbytes);

    if ($buf eq '') {
      return $written;      # it's complete, we can return
    }
    else {
      warn "prefork: partial write of $nbytes to ".
            $targetname.", towrite=".length($buf).
            " sofar=".$written." fd=".$sock->fileno.", recovering";
      goto retry_write;
    }
  }

  die "assert: should not get here";
}

###########################################################################
# Master server code again

# this is pretty much the algorithm from perform_idle_server_maintainance() in
# Apache's "prefork" MPM.  However: we don't do exponential server spawning,
# since our servers are a lot more heavyweight than theirs is.

sub adapt_num_children {
  my ($self) = @_;

  # don't start up new kids while main is working at killing the old ones
  return if $self->{am_exiting};

  my $kids = $self->{kids};
  my $statestr = '';
  my $num_idle = 0;
  my @pids = sort { $a <=> $b } keys %{$kids};
  my $num_servers = scalar @pids;

  foreach my $pid (@pids) {
    my $k = $kids->{$pid};

    # note: race condition here.  if a child exits between the keys() call
    # above, and this point, then $k will be undef here due to its deletion
    # from the hash in the SIGCHLD handler.  This is harmless, but ugly, since
    # it produces a 'Use of uninitialized value in numeric eq (==)' warning at
    # the "== PFSTATE_IDLE" line below.
    next unless defined $k;

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
    elsif ($k == PFSTATE_GOT_SIGCHLD) {
      $statestr .= 'Z';
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
  info("prefork: child states: ".$statestr."\n");

  # just kill off/add one at a time, to avoid swamping stuff and
  # reacting too quickly; Apache emulation
  if ($num_idle < $self->{min_idle}) {
    if ($num_servers < $self->{max_children}) {
      $self->need_to_add_server($num_idle);
    } else {
      info("prefork: server reached --max-children setting, consider raising it\n");
    }
  }
  elsif ($num_idle > $self->{max_idle} && $num_servers > $self->{min_children}) {
    $self->need_to_del_server($num_idle);
  }
}

sub need_to_add_server {
  my ($self, $num_idle) = @_;
  my ($pid);
  my $cur = ${$self->{cur_children_ref}};
  $cur++;
  dbg("prefork: adjust: increasing, not enough idle children ($num_idle < $self->{min_idle})");
  $pid = main::spawn();
  # servers will be started once main_server_poll() returns

  #Added for bug 6304 to work on notifying administrators of poor parameters for spamd
  info("prefork: adjust: %s idle children less than %s minimum idle children.  Increasing spamd children: %s started.",$num_idle, $self->{min_idle}, $pid);
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
    die "prefork: oops! no idle kids in need_to_del_server?";
  }

  # warning: race condition if these two lines are the other way around.
  # see bug 3983, comment 37 for details
  $self->set_child_state ($pid, PFSTATE_KILLED);
  if (!am_running_on_windows()) {
    kill 'INT' => $pid;
  } else {
    my $sock = $self->{backchannel}->get_socket_for_child($pid);
    # On win32 child cannot get a signal while reading socket
    $sock->syswrite("P....\n");
    kill 'INT' => $pid or warn "prefork: kill of child $pid failed: $!\n";
	
    $self->{backchannel}->delete_socket_for_child($pid);
    if (defined $sock && defined $sock->fileno()) {
      $self->{backchannel}->remove_from_selector($sock);
    }
    $sock->close  if $sock;
  }

  dbg("prefork: adjust: decreasing, too many idle children ($num_idle > $self->{max_idle}), killed $pid");
  #Added for bug 6304 to work on notifying administrators of poor parameters for spamd
  info("prefork: adjust: %s idle children more than %s maximum idle children. Decreasing spamd children: %s killed.",$num_idle, $self->{max_idle}, $pid);
}

sub vec_all {
  my ($self, $bitsref, $fhs, $value) = @_;
  my $ret = 0;
  foreach my $fh (@{$fhs}) {
    next unless defined $fh;
    if (defined $value) {
      vec($$bitsref, $fh, 1) = $value;
    } else {
      $ret |= vec($$bitsref, $fh, 1);
    }
  }
  return $ret;
}

1;

__END__
