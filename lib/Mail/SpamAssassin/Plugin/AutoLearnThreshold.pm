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

Mail::SpamAssassin::Plugin::AutoLearnThreshold - threshold-based discriminator for Bayes auto-learning

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::AutoLearnThreshold

=head1 DESCRIPTION

This plugin implements the threshold-based auto-learning discriminator
for SpamAssassin's Bayes subsystem.  Auto-learning is a mechanism
whereby high-scoring mails (or low-scoring mails, for non-spam) are fed
into its learning systems without user intervention, during scanning.

Note that certain tests are ignored when determining whether a message
should be trained upon:

=over 4

=item * rules with tflags set to 'learn' (the Bayesian rules)

=item * rules with tflags set to 'userconf' (user configuration)

=item * rules with tflags set to 'noautolearn'

=back

Also note that auto-learning occurs using scores from either scoreset 0
or 1, depending on what scoreset is used during message check.  It is
likely that the message check and auto-learn scores will be different.

=cut

package Mail::SpamAssassin::Plugin::AutoLearnThreshold;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER OPTIONS

The following configuration settings are used to control auto-learning:

=over 4

=item bayes_auto_learn_threshold_nonspam n.nn   (default: 0.1)

The score threshold below which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a non-spam message.

=cut

  push (@cmds, {
    setting => 'bayes_auto_learn_threshold_nonspam',
    default => 0.1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item bayes_auto_learn_threshold_spam n.nn      (default: 12.0)

The score threshold above which a mail has to score, to be fed into
SpamAssassin's learning systems automatically as a spam message.

Note: SpamAssassin requires at least 3 points from the header, and 3
points from the body to auto-learn as spam.  Therefore, the minimum
working value for this option is 6.

=cut

  push (@cmds, {
    setting => 'bayes_auto_learn_threshold_spam',
    default => 12.0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub autolearn_discriminator {
  my ($self, $params) = @_;

  my $scan = $params->{permsgstatus};
  my $conf = $scan->{conf};

  # Figure out min/max for autolearning.
  # Default to specified auto_learn_threshold settings
  my $min = $conf->{bayes_auto_learn_threshold_nonspam};
  my $max = $conf->{bayes_auto_learn_threshold_spam};

  # Find out what score we should consider this message to have ...
  my $score = $scan->get_autolearn_points();
  my $body_only_points = $scan->get_body_only_points();
  my $head_only_points = $scan->get_head_only_points();
  my $learned_points = $scan->get_learned_points();

  dbg("learn: auto-learn? ham=$min, spam=$max, ".
                "body-points=".$body_only_points.", ".
                "head-points=".$head_only_points.", ".
                "learned-points=".$learned_points);

  my $isspam;
  if ($score < $min) {
    $isspam = 0;
  } elsif ($score >= $max) {
    $isspam = 1;
  } else {
    dbg("learn: auto-learn? no: inside auto-learn thresholds, not considered ham or spam");
    return;
  }

  my $learner_said_ham_points = -1.0;
  my $learner_said_spam_points = 1.0;

  if ($isspam) {
    my $required_body_points = 3;
    my $required_head_points = 3;

    if ($body_only_points < $required_body_points) {
      dbg("learn: auto-learn? no: scored as spam but too few body points (".
          $body_only_points." < ".$required_body_points.")");
      return;
    }
    if ($head_only_points < $required_head_points) {
      dbg("learn: auto-learn? no: scored as spam but too few head points (".
          $head_only_points." < ".$required_head_points.")");
      return;
    }
    if ($learned_points < $learner_said_ham_points) {
      dbg("learn: auto-learn? no: scored as spam but learner indicated ham (".
          $learned_points." < ".$learner_said_ham_points.")");
      return;
    }

    if (!$scan->is_spam()) {
      dbg("learn: auto-learn? no: scored as ham but autolearn wanted spam");
      return;
    }

  } else {
    if ($learned_points > $learner_said_spam_points) {
      dbg("learn: auto-learn? no: scored as ham but learner indicated spam (".
          $learned_points." > ".$learner_said_spam_points.")");
      return;
    }

    if ($scan->is_spam()) {
      dbg("learn: auto-learn? no: scored as spam but autolearn wanted ham");
      return;
    }
  }

  dbg("learn: auto-learn? yes, ".($isspam?"spam ($score > $max)":"ham ($score < $min)"));
  return $isspam;
}

1;

=back

=cut
