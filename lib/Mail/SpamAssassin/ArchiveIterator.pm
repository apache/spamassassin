#!/usr/bin/perl -w
#
# iterate over mail archives, calling a function on each message.

package Mail::SpamAssassin::ArchiveIterator;

use strict;
use bytes;

use IO::Select;
use IO::Socket;
use Mail::SpamAssassin::Util;

use constant BIG_BYTES => 256*1024;	# 256k is a big email
use constant BIG_LINES => BIG_BYTES/65;	# 65 bytes/line is a good approximation

my $no;
my $tz;

BEGIN {
  $no = 1;
  $tz = local_tz();
}

use vars qw {
  $MESSAGES
};

my @ISA = qw($MESSAGES);

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  $self->{s} = { };		# spam, of course
  $self->{h} = { };		# ham, as if you couldn't guess

  $self;
}

###########################################################################

sub set_functions {
  my ($self, $wanted, $result) = @_;
  $self->{wanted_sub} = $wanted;
  $self->{result_sub} = $result;
}

###########################################################################

sub run {
  my ($self, @targets) = @_;

  if (!defined $self->{wanted_sub}) {
    die "set_functions never called";
  }

  if ($self->{opt_j} == 1) {
    my $message;
    my $class;
    my $result;
    my $messages;

    # message-array
    ($MESSAGES,$messages) = $self->message_array(\@targets);

    while ($message = (shift @{$messages})) {
      my ($class, undef, $date) = index_unpack($message);
      $result = $self->run_message($message);
      &{$self->{result_sub}}($class, $result, $date) if $result;
    }
  }
  elsif ($self->{opt_j} > 1) {
    my $select = IO::Select->new();

    my $total_count = 0;
    my $needs_restart = 0;
    my @child = ();
    my @pid = ();
    my $messages;

    $self->start_children($self->{opt_j}, \@child, \@pid, $select);

    # message-array
    ($MESSAGES,$messages) = $self->message_array(\@targets);
    #warn ">> total: $MESSAGES\n";

    # feed childen
    while ($select->count()) {
      foreach my $socket ($select->can_read()) {
	my $result = '';
	my $line;
	while ($line = readline $socket) {
	  if ($line =~ /^RESULT (.+)$/) {
	    my($class,$type,$date) = index_unpack($1);
	    #warn ">> RESULT: $class, $type, $date\n";

	    if (defined $self->{opt_restart} && ($total_count % $self->{opt_restart}) == 0) {
	      $needs_restart = 1;
	    }

	    # if messages remain, and we don't need to restart, send a message
	    if (($MESSAGES>$total_count) && !$needs_restart) {
	      print { $socket } (shift @{$messages}) . "\n";
	      $total_count++;
	      #warn ">> recv: $MESSAGES $total_count\n";
	    }
	    else {
	      # stop listening on this child since we're done with it.
	      #warn ">> removeresult: $needs_restart $MESSAGES $total_count\n";
	      $select->remove($socket);
	    }

	    # Deal with the result we got.
	    if ($result) {
	      chop $result;	# need to chop the \n before RESULT
	      &{$self->{result_sub}}($class, $result, $date);
	    }

	    last; # this will get out of the read for this client
	  }
	  elsif ($line eq "START\n") {
	    if ($MESSAGES>$total_count) {
	      # we still have messages, send one to child
	      print { $socket } (shift @{$messages}) . "\n";
	      $total_count++;
	      #warn ">> new: $MESSAGES $total_count\n";
	    }
	    else {
	      # no more messages, so stop listening on this child
	      #warn ">> removestart: $needs_restart $MESSAGES $total_count\n";
	      $select->remove($socket);
	    }

	    last; # this will get out of the read for this client
	  }
	  else {
	    # result line, remember it.
	    $result .= $line;
	  }
	}

        # some error happened during the read!
        if ( !defined $line || !$line ) {
          $needs_restart = 1;
          warn "Got an undef from readline?!?  Restarting all children, probably lost some results. :(\n";
          $select->remove($socket);
        }
      }

      #warn ">> out of loop, $MESSAGES $total_count $needs_restart ".$select->count()."\n";

      # If there are still messages to process, and we need to restart
      # the children, and all of the children are idle, let's go ahead.
      if ($needs_restart && $select->count() == 0 && ($MESSAGES>$total_count)) {
	$needs_restart = 0;

	#warn "debug: Needs restart, $MESSAGES total, $total_count done.\n";
	$self->reap_children($self->{opt_j}, \@child, \@pid);
	@child=();
	@pid=();
	$self->start_children($self->{opt_j}, \@child, \@pid, $select);
      }
    }
    # reap children
    $self->reap_children($self->{opt_j}, \@child, \@pid);
  }
}

############################################################################

sub message_array {
  my($self, $targets) = @_;

  foreach my $target (@${targets}) {
    my ($class, $format, $rawloc) = split(/:/, $target, 3);

    my @locations = $self->fix_globs($rawloc);

    foreach my $location (@locations) {
      $class = substr($class, 0, 1);
      if ($format eq "dir") {
	$self->scan_directory($class, $location);
      }
      elsif ($format eq "file") {
	$self->scan_file($class, $location);
      }
      elsif ($format eq "mbox") {
	$self->scan_mailbox($class, $location);
      }
    }
  }

  my @messages;
  if ($self->{opt_n}) {
    my %both = (%{ $self->{s} }, %{$self->{h}});
    undef $self->{s};
    undef $self->{h};
    @messages = sort({ $both{$a} <=> $both{$b} } keys %both);
    splice(@messages, $self->{opt_head}) if $self->{opt_head};
    splice(@messages, 0, -$self->{opt_tail}) if $self->{opt_tail};
  }
  else {
    my @s = sort({ $self->{s}->{$a} <=> $self->{s}->{$b} } keys %{$self->{s}});
    undef $self->{s};
    my @h = sort({ $self->{h}->{$a} <=> $self->{h}->{$b} } keys %{$self->{h}});
    undef $self->{h};
    splice(@s, $self->{opt_head}) if $self->{opt_head};
    splice(@s, 0, -$self->{opt_tail}) if $self->{opt_tail};
    splice(@h, $self->{opt_head}) if $self->{opt_head};
    splice(@h, 0, -$self->{opt_tail}) if $self->{opt_tail};
    while (@s && @h) {
      push @messages, (shift @s);
      push @messages, (shift @h);
    }
    push @messages, (splice @s), (splice @h);
  }
  return (scalar(@messages),\@messages);
}

sub start_children {
  my($self, $count, $child, $pid, $socket) = @_;

  my $io = IO::Socket->new();
  my $parent;

  # create children
  for (my $i = 0; $i < $count; $i++) {
    ($child->[$i],$parent) = $io->socketpair(AF_UNIX,SOCK_STREAM,PF_UNSPEC)
	or die "socketpair failed: $!";
    if ($pid->[$i] = fork) {
      close $parent;

      # disable caching for parent<->child relations
      my($old) = select($child->[$i]);
      $|++;
      select($old);

      $socket->add($child->[$i]);
      #warn "debug: starting new child $i (pid ",$pid->[$i],")\n";
      next;
    }
    elsif (defined $pid->[$i]) {
      my $result;
      my $line;
      close $child->[$i];
      select($parent);
      $| = 1;	# print to parent by default, turn off buffering
      print "START\n";
      while ($line = readline $parent) {
	chomp $line;
	if ($line eq "exit") {
	  print "END\n";
	  close $parent;
	  exit;
	}
	$result = $self->run_message($line);
	print "$result\nRESULT $line\n";
      }
      exit;
    }
    else {
      die "cannot fork: $!";
    }
  }
}

sub reap_children {
  my($self, $count, $socket, $pid) = @_;

  # If the child died, sending it the exit will generate a SIGPIPE
  # but we don't really care since the readline will go undef which is fine,
  # then we do the waitpid which will finish it off.  So we end up in the
  # right state, in theory.
  local $SIG{'PIPE'} = 'IGNORE';

  for (my $i = 0; $i < $count; $i++) {
    #warn "debug: killing child $i (pid ",$pid->[$i],")\n";
    print { $socket->[$i] } "exit\n"; # tell the child to die.
    my $line = readline $socket->[$i]; # read its END statement.
    close $socket->[$i];
    waitpid($pid->[$i], 0); # wait for the signal ...
  }
}

sub mail_open {
  my ($file) = @_;

  my $expr;
  if ($file =~ /\.gz$/) {
    $expr = "gunzip -cd $file |";
  }
  elsif ($file =~ /\.bz2$/) {
    $expr = "bzip2 -cd $file |";
  }
  else {
    $expr = "$file";
  }
  if (!open (INPUT, $expr)) {
    warn "unable to open $file: $@";
    return 0;
  }
  return 1;
}

sub first_date {
  my (@strings) = @_;

  foreach my $string (@strings) {
    my $time = Mail::SpamAssassin::Util::parse_rfc822_date($string);
    return $time if defined($time) && $time;
  }
  return undef;
}

sub receive_date {
  my ($self, $header) = @_;

  $header ||= '';
  $header =~ s/\n[ \t]+/ /gs;	# fix continuation lines

  my @rcvd = ($header =~ /^Received:(.*)/img);
  my @local;
  my $time;

  if (@rcvd) {
    if ($rcvd[0] =~ /qmail \d+ invoked by uid \d+/ ||
	$rcvd[0] =~ /\bfrom (?:localhost\s|(?:\S+ ){1,2}\S*\b127\.0\.0\.1\b)/)
    {
      push @local, (shift @rcvd);
    }
    if (@rcvd && ($rcvd[0] =~ m/\bby localhost with \w+ \(fetchmail-[\d.]+/)) {
      push @local, (shift @rcvd);
    }
    elsif (@local) {
      unshift @rcvd, (shift @local);
    }
  }

  if (@rcvd) {
    $time = first_date(shift @rcvd);
    return $time if defined($time);
  }
  if (@local) {
    $time = first_date(@local);
    return $time if defined($time);
  }
  if ($header =~ /^(?:From|X-From-Line:)\s+(.+)$/im) {
    my $string = $1;
    $string .= " $tz" unless $string =~ /(?:[-+]\d{4}|\b[A-Z]{2,4}\b)/;
    $time = first_date($string);
    return $time if defined($time);
  }
  if (@rcvd) {
    $time = first_date(@rcvd);
    return $time if defined($time);
  }
  if ($header =~ /^Resent-Date:\s*(.+)$/im) {
    $time = first_date($1);
    return $time if defined($time);
  }
  if ($header =~ /^Date:\s*(.+)$/im) {
    $time = first_date($1);
    return $time if defined($time);
  }

  return time;
}

############################################################################

sub index_pack {
  return join("\000", @_);
}

sub index_unpack {
  return split(/\000/, $_[0]);
}

sub scan_directory {
  my ($self, $class, $folder) = @_;

  my @files;

  opendir(DIR, $folder) || die "Can't open '$folder' dir: $!";
  if (-f "$folder/cyrus.header") {
    # cyrus metadata: http://unix.lsa.umich.edu/docs/imap/imap-lsa-srv_3.html
    @files = grep { /^\S+$/ && !/^cyrus\.(?:index|header|cache|seen)/ }
			readdir(DIR);
  }
  else {
    # ignore ,234 (deleted or refiled messages) and MH metadata dotfiles
    @files = grep { /^[^,.]\S*$/ } readdir(DIR);
  }
  closedir(DIR);

  @files = grep { -f } map { "$folder/$_" } @files;

  foreach my $mail (@files) {
    if ($self->{opt_n}) {
      $self->{$class}->{index_pack($class, "f", $no, $mail)} = $no;
      $no++;
      next;
    }
    my $header;
    mail_open($mail) or next;
    while (<INPUT>) {
      last if /^$/;
      $header .= $_;
    }
    close(INPUT);
    my $date = $self->receive_date($header);
    $self->{$class}->{index_pack($class, "f", $date, $mail)} = $date;
  }
}

sub scan_file {
  my ($self, $class, $mail) = @_;

  if ($self->{opt_n}) {
    $self->{$class}->{index_pack($class, "f", $no, $mail)} = $no;
    $no++;
    return;
  }
  my $header;
  mail_open($mail) or return;
  while (<INPUT>) {
    last if /^$/;
    $header .= $_;
  }
  close(INPUT);
  my $date = $self->receive_date($header);
  $self->{$class}->{index_pack($class, "f", $date, $mail)} = $date;
}

sub scan_mailbox {
  my ($self, $class, $folder) = @_;

  if ($folder =~ /\.(?:gz|bz2)$/) {
    die "compressed mbox folders are not supported at this time\n";
  }
  mail_open($folder) or return;

  my $start = 0;		# start of a message
  my $where = 0;		# current byte offset
  my $first = '';		# first line of message
  my $header = '';		# header text
  my $in_header = 0;		# are in we a header?
  while (!eof INPUT) {
    my $offset = $start;	# byte offset of this message
    my $header = $first;	# remember first line
    while (<INPUT>) {
      if ($in_header) {
	if (/^$/) {
	  $in_header = 0;
	}
	else {
	  $header .= $_;
	}
      }
      if (substr($_,0,5) eq "From ") {
	$in_header = 1;
	$first = $_;
	$start = $where;
	$where = tell INPUT;
	last;
      }
      $where = tell INPUT;
    }
    if ($header) {
      my $t = ($self->{opt_n} ? $no++ : $self->receive_date($header));
      $self->{$class}->{index_pack($class, "m", $t, "$folder.$offset")} = $t;
    }
  }
  close INPUT;
}

############################################################################

sub run_message {
  my ($self, $msg) = @_;

  my (undef, $format, $date, $mail) = index_unpack($msg);

  if ($format eq "f") {
    return $self->run_file($mail, $date);
  }
  elsif ($format eq "m") {
    return $self->run_mailbox($mail, $date);
  }
}

sub run_file {
  my ($self, $where, $date) = @_;

  mail_open($where) or return;
  # skip too-big mails
  if (! $self->{opt_all} && -s INPUT > BIG_BYTES) {
    close INPUT;
    return;
  }
  my @msg = (<INPUT>);
  close INPUT;

  &{$self->{wanted_sub}}($where, $date, \@msg);
}

sub run_mailbox {
  my ($self, $where, $date) = @_;

  my ($file, $offset) = ($where =~ m/(.*)\.(\d+)$/);
  my @msg;
  mail_open($file) or return;
  seek(INPUT,$offset,0);
  my $past = 0;
  while (<INPUT>) {
    if ($past) {
      last if substr($_,0,5) eq "From ";
    }
    else {
      $past = 1;
    }
    # skip too-big mails
    if (! $self->{opt_all} && @msg > BIG_LINES) {
      close INPUT;
      return;
    }
    push (@msg, $_);
  }
  close INPUT;
  &{$self->{wanted_sub}}("$file.$offset", $date, \@msg);
}

############################################################################

sub fix_globs {
  my ($self, $path) = @_;

  # replace leading tilde with home dir: ~/abc => /home/jm/abc
  $path =~ s/^~/$ENV{'HOME'}/;

  # protect/escape spaces: ./Mail/My Letters => ./Mail/My\ Letters
  $path =~ s/([^\\])(\s)/$1\\$2/g;

  # apply csh-style globs: ./corpus/*.mbox => er, you know what it does ;)
  my @paths = glob $path;
  return @paths;
}

############################################################################

1;
