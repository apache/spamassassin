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

=head1 NAME

Mail::SpamAssassin::Util::Progress - Progress bar support for SpamAssassin

=head1 SYNOPSIS

  my $progress = Mail::SpamAssassin::Util::Progress->new({total => 100});

  $msgcount = 0;
  foreach my $message (@messages) {
    # do something here
    $msgcount++;
    $progress->update($msgcount);
  }

  $progress->final();

=head1 DESCRIPTION

This module implements a progress bar for use in SpamAssassin scripts and
modules.  It allows you to create the progress bar, update it and print
out the final results of a particular run.

=cut

package Mail::SpamAssassin::Util::Progress;

use strict;
use warnings;
use bytes;
use re 'taint';

use Time::HiRes qw(time);

use constant HAS_TERM_READKEY => eval { require Term::ReadKey };

=head2 new

public class (Mail::SpamAssassin::Util::Progress) new (\% $args)

Description:
Creates a new Mail::SpamAssassin::Util::Progress object, valid values for
the $args hashref are:

=over 4

=item total (required)

The total number of messages expected to be processed.  This item is
required.

=item fh [optional]

An optional filehandle may be passed in, otherwise STDERR will be used by
default.

=item term [optional]

The module will attempt to determine if a valid terminal exists on the
STDIN filehandle.  This item allows you to override that value.

=back

=cut

sub new {
  my ($class, $args) = @_;
  $class = ref($class) || $class;

  if (!exists($args->{total}) || $args->{total} < 1) {
    warn "progress: must provide a total value > 1";
    return;
  }

  my $self = {
	      'total' => $args->{total},
	      'fh' => $args->{fh} || \*STDERR,
              'itemtype' => $args->{itemtype} || 'msgs'
	     };

  bless ($self, $class);

  $self->{term} = $args->{term} || (-t STDIN);

  $self->init_bar(); # this will give us the initial progress bar
  
  return $self;
}

=head2 init_bar

public instance () init_bar()

Description:
This method creates the initial progress bar and is called automatically from new.  In addition
you can call init_bar on an existing object to reset the bar to it's original state.

=cut

sub init_bar {
  my ($self) = @_;

  my $fh = $self->{fh};

  $self->{prev_num_done} = 0; # 0 for now, maybe allow this to be passed in
  $self->{num_done} = 0; # 0 for now, maybe allow this to be passed in

  $self->{avg_msgs_per_sec} = undef;

  $self->{start_time} = time();
  $self->{prev_time} = $self->{start_time};

  return unless ($self->{term});

  my $term_size;

  # If they have set the COLUMNS environment variable, respect it and move on
  if ($ENV{COLUMNS}) {
    $term_size = $ENV{COLUMNS};
  }

  # The ideal case would be if they happen to have Term::ReadKey installed
  if (!defined($term_size) && HAS_TERM_READKEY) {
    my $term_readkey_term_size;
    eval {
      $term_readkey_term_size =
        (Term::ReadKey::GetTerminalSize($self->{fh}))[0];
      1;
    } or do {  # an error will just keep the default
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      # dbg("progress: Term::ReadKey::GetTerminalSize failed: $eval_stat");
      # GetTerminalSize might have returned an empty array, so check the
      # value and set if it exists, if not we keep the default
      $term_size = $term_readkey_term_size if ($term_readkey_term_size);
    }
  }

  # only viable on Unix based OS, so exclude windows, etc here
  if ($^O !~ /^(mswin|dos|os2)/i) {
    if (!defined $term_size) {
      my $data = `stty -a`;
      if (defined $data && $data =~ /columns (\d+)/) {
        $term_size = $1;
      }
    }

    if (!defined $term_size) {
      my $data = `tput cols`;
      if (defined $data && $data =~ /^(\d+)/) {
        $term_size = $1;
      }
    }
  }

  # fall back on the default
  if (!defined($term_size)) {
    $term_size = 80;
  }


  # Adjust the bar size based on what all is going to print around it,
  # do not forget the trailing space. Here is what we have to deal with
  #1234567890123456789012345678901234567
  # XXX% [] XXX.XX msgs/sec XXmXXs LEFT
  # XXX% [] XXX.XX msgs/sec XXmXXs DONE
  $self->{bar_size} = $term_size - 37;

  my @chars = (' ') x $self->{bar_size};

  print $fh sprintf("\r%3d%% [%s] %6.2f %s/sec %sm%ss LEFT",
		    0, join('', @chars), 0, $self->{itemtype}, '--', '--');

  return;
}

=head2 update

public instance () update ([Integer $num_done])

Description:
This method is what gets called to update the progress bar.  You may optionally pass in
an integer value that indicates how many messages have been processed.  If you do not pass
anything in then the num_done value will be incremented by one.

=cut

sub update {
  my ($self, $num_done) = @_;

  my $fh = $self->{fh};
  my $time_now = time();

  # If nothing is passed in to update assume we are adding one to the prev_num_done value
  unless(defined($num_done)) {
    $num_done = $self->{prev_num_done} + 1;
  }

  my $msgs_since = $num_done - $self->{prev_num_done};
  my $time_since = $time_now - $self->{prev_time};

 # we have to have processed at least one message and moved a little time
  if ($msgs_since > 0 && $time_since > .5) {

    if ($self->{term}) {
      my $percentage = $num_done != 0 ? int(($num_done / $self->{total}) * 100) : 0;

      my @chars = (' ') x $self->{bar_size};
      my $used_bar = $num_done * ($self->{bar_size} / $self->{total});
      for (0..$used_bar-1) {
	$chars[$_] = '=';
      }
      my $rate = $msgs_since/$time_since;
      my $overall_rate = $num_done/($time_now-$self->{start_time});
      
      # semi-complicated calculation here so that we get the avg msg per sec over time
      $self->{avg_msgs_per_sec} = defined($self->{avg_msgs_per_sec}) ? 
	0.5 * $self->{avg_msgs_per_sec} + 0.5 * ($msgs_since / $time_since) : $msgs_since / $time_since;
      
      # using the overall_rate here seems to provide much smoother eta numbers
      my $eta = ($self->{total} - $num_done)/$overall_rate;
      
      # we make the assumption that we will never run > 1 hour, maybe this is bad
      my $min = int($eta/60) % 60;
      my $sec = int($eta % 60);
      
      print $fh sprintf("\r%3d%% [%s] %6.2f %s/sec %02dm%02ds LEFT",
			$percentage, join('', @chars), $self->{avg_msgs_per_sec},
                        $self->{itemtype}, $min, $sec);
    }
    else { # we have no term, so fake it
      print $fh '.' x $msgs_since;
    }

    $self->{prev_time} = $time_now;
    $self->{prev_num_done} = $num_done;
  }
  $self->{num_done} = $num_done;
  return;
}

=head2 final

public instance () final ([Integer $num_done])

Description:
This method should be called once all processing has finished.
It will print out the final msgs per sec calculation and the total time taken.
You can optionally pass in a num_done value, otherwise it will use the value
calculated from the last call to update.

=cut

sub final {
  my ($self, $num_done) = @_;

  # passing in $num_done is optional, and will most likely rarely be used,
  # we should generally favor the data that has been passed in to update()
  unless (defined($num_done)) {
    $num_done = $self->{num_done};
  }

  my $fh = $self->{fh};

  my $time_taken = time() - $self->{start_time};
  $time_taken ||= 1; # can't have 0 time, so just make it 1 second

  # in theory this should be 100% and the bar would be completely full, however
  # there is a chance that we had an early exit so we aren't at 100%
  my $percentage = $num_done != 0 ? int(($num_done / $self->{total}) * 100) : 0;

  my $msgs_per_sec = $num_done / $time_taken;

  my $min = int($time_taken/60) % 60;
  my $sec = $time_taken % 60;

  if ($self->{term}) {
    my @chars = (' ') x $self->{bar_size};
    my $used_bar = $num_done * ($self->{bar_size} / $self->{total});
    for (0..$used_bar-1) {
      $chars[$_] = '=';
    }

    print $fh sprintf("\r%3d%% [%s] %6.2f %s/sec %02dm%02ds DONE\n",
		      $percentage, join('', @chars), $msgs_per_sec,
                      $self->{itemtype}, $min, $sec);
  }
  else {
    print $fh sprintf("\n%3d%% Completed %6.2f %s/sec in %02dm%02ds\n",
		      $percentage, $msgs_per_sec,
                      $self->{itemtype}, $min, $sec);
  }

  return;
}

1;
