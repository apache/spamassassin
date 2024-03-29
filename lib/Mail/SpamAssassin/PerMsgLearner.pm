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

Mail::SpamAssassin::PerMsgLearner - per-message status (spam or not-spam)

=head1 SYNOPSIS

  my $spamtest = Mail::SpamAssassin->new({
    'rules_filename'      => '/etc/spamassassin.rules',
    'userprefs_filename'  => $ENV{HOME}.'/.spamassassin/user_prefs'
  });
  my $mail = $spamtest->parse();

  my $status = $spamtest->learn($mail,$id,$isspam,$forget);
  my $didlearn = $status->did_learn();
  $status->finish();


=head1 DESCRIPTION

The Mail::SpamAssassin C<learn()> method returns an object of this
class.  This object encapsulates all the per-message state for
the learning process.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::PerMsgLearner;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Bayes;
use Mail::SpamAssassin::Logger;

our @ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg) = @_;

  my $self = {
    'main'              => $main,
    'msg'               => $msg,
    'learned'		=> 0,
    'master_deadline'   => $msg->{master_deadline},  # dflt inherited from msg
  };

  $self->{conf} = $self->{main}->{conf};

  $self->{bayes_scanner} = $self->{main}->{bayes_scanner};

  bless ($self, $class);
  $self;
}

###########################################################################

# $status->learn_spam($id)
# 
# Learn the message as spam.
# 
# C<$id> is an optional message-identification string, used internally
# to tag the message.  If it is C<undef>, one will be generated.
# It should be unique to that message.
# 
# This is a semi-private API; callers should use
# C<$spamtest-E<gt>learn($mail,$id,$isspam,$forget)> instead.

sub learn_spam {
  my ($self, $id) = @_;

  # bug 4096
  # if ($self->{main}->{learn_with_welcomelist}) {
  # $self->{main}->add_all_addresses_to_blocklist ($self->{msg});
  # }

  # use the real message-id here instead of mass-check's idea of an "id",
  # as we may deliver the msg into another mbox format but later need
  # to forget it's training.
  $self->{learned} = $self->{bayes_scanner}->learn (1, $self->{msg}, $id);
}

###########################################################################

# $status->learn_ham($id)
# 
# Learn the message as ham.
# 
# C<$id> is an optional message-identification string, used internally
# to tag the message.  If it is C<undef>, one will be generated.
# It should be unique to that message.
# 
# This is a semi-private API; callers should use
# C<$spamtest-E<gt>learn($mail,$id,$isspam,$forget)> instead.

sub learn_ham {
  my ($self, $id) = @_;

  # bug 4096
  # if ($self->{main}->{learn_with_welcomelist}) {
  # $self->{main}->add_all_addresses_to_welcomelist ($self->{msg});
  # }

  $self->{learned} = $self->{bayes_scanner}->learn (0, $self->{msg}, $id);
}

###########################################################################

# $status->forget($id)
# 
# Forget about a previously-learned message.
# 
# C<$id> is an optional message-identification string, used internally
# to tag the message.  If it is C<undef>, one will be generated.
# It should be unique to that message.
# 
# This is a semi-private API; callers should use
# C<$spamtest-E<gt>learn($mail,$id,$isspam,$forget)> instead.

sub forget {
  my ($self, $id) = @_;

  # bug 4096
  # if ($self->{main}->{learn_with_welcomelist}) {
  # $self->{main}->remove_all_addresses_from_welcomelist ($self->{msg});
  # }

  $self->{learned} = $self->{bayes_scanner}->forget ($self->{msg}, $id);
}

###########################################################################

=item $didlearn = $status-E<gt>did_learn()

Returns C<1> if the message was learned from or forgotten successfully.

=cut

sub did_learn {
  my ($self) = @_;
  return ($self->{learned});
}

###########################################################################

=item $status-E<gt>finish()

Finish with the object.

=cut

sub finish {
  my $self = shift;
  %{$self} = ();
}

###########################################################################

1;
__END__

=back

=head1 SEE ALSO

Mail::SpamAssassin(3)
spamassassin(1)

