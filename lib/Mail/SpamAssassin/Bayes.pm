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

Mail::SpamAssassin::Bayes - support for learning classifiers

=head1 DESCRIPTION

This is the general class used to train a learning classifier with new samples
of spam and ham mail, and classify based on prior training. 

Prior to version 3.3.0, the default Bayes implementation was here; if you're
looking for information on that, it has moved to
C<Mail::SpamAssassin::Plugin::Bayes>.

=cut

package Mail::SpamAssassin::Bayes;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

our @ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my ($main) = @_;
  my $self = {
    'main'              => $main,
    'conf'		=> $main->{conf},
    'use_ignores'       => 1,
  };
  bless ($self, $class);

  $self->{main}->call_plugins("learner_new");
  $self;
}

###########################################################################

sub finish {
  my $self = shift;
  # we don't need to do the plugin; Mail::SpamAssassin::finish() does
  # that for us
  %{$self} = ();
}

###########################################################################

# force the Bayes dbs to be closed, if they haven't already been; called
# at the end of scan operation, or when switching between user IDs,
# or when C<Mail::SpamAssassin::finish_learner()> is called.
#
sub force_close {
  my $self = shift;
  my $quiet = shift;
  $self->{main}->call_plugins("learner_close", { quiet => $quiet });
}

###########################################################################

sub ignore_message {
  my ($self,$PMS) = @_;

  return 0 unless $self->{use_ignores};

  my $ig_from = $self->{main}->call_plugins ("check_wb_list",
        { permsgstatus => $PMS, type => 'from', list => 'bayes_ignore_from' });
  my $ig_to = $self->{main}->call_plugins ("check_wb_list", 
        { permsgstatus => $PMS, type => 'to', list => 'bayes_ignore_to' });

  my $ignore = $ig_from || $ig_to;
  dbg("bayes: not using bayes, bayes_ignore_from or _to rule") if $ignore;
  return $ignore;
}

###########################################################################

sub learn {
  my ($self, $isspam, $msg, $id) = @_;
  return unless $self->{conf}->{use_learner};
  return unless defined $msg;

  if( $self->{use_ignores} )  # Remove test when PerMsgStatus available.
  {
    # DMK, koppel@ece.lsu.edu:  Hoping that the ultimate fix to bug 2263 will
    # make it unnecessary to construct a PerMsgStatus here.
    my $PMS = Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);
    my $ignore = $self->ignore_message($PMS);
    $PMS->finish();
    return 0 if $ignore;
  }

  return $self->{main}->call_plugins("learn_message", { isspam => $isspam, msg => $msg, id => $id });
}

###########################################################################

sub forget {
  my ($self, $msg, $id) = @_;
  return unless $self->{conf}->{use_learner};
  return unless defined $msg;
  return $self->{main}->call_plugins("forget_message", { msg => $msg, id => $id });
}

###########################################################################

sub sync {
  my ($self, $sync, $expire, $opts) = @_;
  return 0 unless $self->{conf}->{use_learner};

  if ($sync) {
    $self->{main}->call_plugins("learner_sync", $opts );
  }
  if ($expire) {
    $self->{main}->call_plugins("learner_expire_old_training", $opts );
  }

  return 0;
}

###########################################################################

sub is_scan_available {
  my $self = shift;
  return 0 unless $self->{conf}->{use_learner};
  return $self->{main}->call_plugins("learner_is_scan_available");
}

###########################################################################

sub dump_bayes_db {
  my($self, $magic, $toks, $regex) = @_;
  return 0 unless $self->{conf}->{use_learner};
  return $self->{main}->call_plugins("learner_dump_database", { 
            magic => $magic, toks => $toks, regex => $regex });
}

1;
