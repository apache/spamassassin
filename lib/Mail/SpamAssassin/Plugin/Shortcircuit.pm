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

Mail::SpamAssassin::Plugin::Shortcircuit - short-circuit evaluation for certain rules

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Shortcircuit

  report Content analysis details:   (_SCORE_ points, _REQD_ required, s/c _SCTYPE_)

  add_header all Status "_YESNO_, score=_SCORE_ required=_REQD_ tests=_TESTS_ shortcircuit=_SCTYPE_ autolearn=_AUTOLEARN_ version=_VERSION_"

=head1 DESCRIPTION

This plugin implements simple, test-based shortcircuiting.  Shortcircuiting a
test will force all other pending rules to be skipped, if that test is hit.
In addition, a symbolic rule, C<SHORTCIRCUIT>, will fire.

Recommended usage is to use C<priority> to set rules with strong S/O values (ie.
1.0) to be run first, and make instant spam or ham classification based on
that.

=cut

package Mail::SpamAssassin::Plugin::Shortcircuit;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_shortcircuit"); # type does not matter
  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub check_shortcircuit { return 0; }        # never used

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 CONFIGURATION SETTINGS

The following configuration settings are used to control shortcircuiting:

=over 4

=item shortcircuit SYMBOLIC_TEST_NAME {ham|spam|on|off}

Shortcircuiting a test will force all other pending rules to be skipped, if
that test is hit.

Recommended usage is to use C<priority> to set rules with strong S/O values (ie.
1.0) to be run first, and make instant spam or ham classification based on
that.

To override a test that uses shortcircuiting, you can set the classification
type to C<off>.

Note that DNS and other network lookups are launched when SA reaches
priority -100.  If you want to shortcircuit scanning before any network
queries are sent, you need to set lower than -100 priority to any such rule,
like -200 as in the examples below.

Shortcircuited test will be automatically set to priority -200, but only if
the original priority is unchanged at default 0.

=over 4

=item on

Shortcircuits the rest of the tests, but does not make a strict classification
of spam or ham.  Rather, it uses the default score for the rule being
shortcircuited.  This would allow you, for example, to define a rule such as

  body TEST /test/
  describe TEST test rule that scores barely over spam threshold
  score TEST 5.5
  priority TEST -200
  shortcircuit TEST on

The result of a message hitting the above rule would be a final score of 5.5,
as opposed to 100 (default) if it were classified as spam.

=item off

Disables shortcircuiting on said rule.

=item spam

Shortcircuit the rule using a set of defaults; override the default score of
this rule with the score from C<shortcircuit_spam_score>, set the
C<noautolearn> tflag, and set priority to C<-200>.  In other words,
equivalent to:

  shortcircuit TEST on
  priority TEST -200
  score TEST 100
  tflags TEST noautolearn

=item ham

Shortcircuit the rule using a set of defaults; override the default score of
this rule with the score from C<shortcircuit_ham_score>, set the C<noautolearn>
and C<nice> tflags, and set priority to C<-200>.   In other words, equivalent
to:

  shortcircuit TEST on
  priority TEST -200
  score TEST -100
  tflags TEST noautolearn nice

=back

=cut

  push (@cmds, {
    setting => 'shortcircuit',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      local($1,$2);
      unless ($value =~ /^(\w+)\s+(\w+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my ($rule, $type) = ($1, $2);

      if ($type eq "ham" || $type eq "spam") {
        dbg("shortcircuit: adding $rule using abbreviation $type");

        # set the defaults:
        $self->{shortcircuit}->{$rule} = $type;
        # don't override existing priority unless it's default 0
        $self->{priority}->{$rule} ||= -200;

        my $tf = $self->{tflags}->{$rule};
        $self->{tflags}->{$rule} = ($tf ? $tf." " : "") .
                ($type eq 'ham' ? "nice " : "") .
                "noautolearn";
      }
      elsif ($type eq "on") {
        $self->{shortcircuit}->{$rule} = "on";
      }
      elsif ($type eq "off") {
        delete $self->{shortcircuit}->{$rule};
      }
      else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

=item shortcircuit_spam_score n.nn (default: 100)

When shortcircuit is used on a rule, and the shortcircuit classification type
is set to C<spam>, this value should be applied in place of the default score
for that rule.

=cut

  push (@cmds, {
    setting => 'shortcircuit_spam_score',
    default => 100,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item shortcircuit_ham_score n.nn (default: -100)

When shortcircuit is used on a rule, and the shortcircuit classification type
is set to C<ham>, this value should be applied in place of the default score
for that rule.

=cut

  push (@cmds, {
    setting => 'shortcircuit_ham_score',
    default => -100,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item shortcircuit_min_ham_score n.nn (default: undef)

When shortcircuit_min_ham_score is set, SpamAssassin will stop processing when total score
will be lower then this value.

=cut

  push (@cmds, {
    setting => 'shortcircuit_min_ham_score',
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item shortcircuit_max_spam_score n.nn (default: undef)

When shortcircuit_max_spam_score is set, SpamAssassin will stop processing when total score
will be higher then this value.

=cut

  push (@cmds, {
    setting => 'shortcircuit_max_spam_score',
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

  $conf->{parser}->register_commands(\@cmds);
}

=back

=head1 TAGS

The following tags are added to the set available for use in reports, headers
etc.:

  _SC_              shortcircuit status (classification and rule name)
  _SCRULE_          rulename that caused the shortcircuit 
  _SCTYPE_          shortcircuit classification ("spam", "ham", "default", "none")

=cut

sub hit_rule {
  my ($self, $params) = @_;

  my $scan = $params->{permsgstatus};
  my $rule = $params->{rulename};

  my $conf = $scan->{conf};
  my $score = $params->{score};

  return if $scan->{shortcircuited};

  # don't s/c if we're linting
  return if ($self->{main}->{lint_rules});

  # don't s/c if we're in compile_now()
  return if ($self->{am_compiling});

  if((defined $conf->{shortcircuit_min_ham_score} and ($scan->{score} < $conf->{shortcircuit_min_ham_score})) or
    (defined $conf->{shortcircuit_max_spam_score} and ($scan->{score} > $conf->{shortcircuit_max_spam_score}))) {
    $scan->{shortcircuited} = 1;

    # bug 5256: if we short-circuit, don't do auto-learning
    $scan->{disable_auto_learning} = 1;
    $scan->{shortcircuit_type} = ($scan->{score} < 0 ? 'ham' : 'spam');
    if($scan->{shortcircuit_type} eq 'ham') {
      dbg("shortcircuit: s/c due to shortcircuit_min_ham_score $conf->{shortcircuit_min_ham_score}, total score is $scan->{score}");
      $scan->got_hit('SHORTCIRCUIT', '', score => -0.001);
    } elsif($scan->{shortcircuit_type} eq 'spam') {
      dbg("shortcircuit: s/c due to shortcircuit_max_spam_score $conf->{shortcircuit_max_spam_score}, total score is $scan->{score}");
      $scan->got_hit('SHORTCIRCUIT', '', score => 0.001);
    }
  }

  my $sctype = $scan->{conf}->{shortcircuit}->{$rule};
  return unless $sctype;

  $scan->{shortcircuit_rule} = $rule;
  my $scscore;
  if ($sctype eq 'on') {  # guess by rule score
    dbg("shortcircuit: s/c due to $rule, using score of $score");
    $scan->{shortcircuit_type} = ($score < 0 ? 'ham' : 'spam');
    $scscore = ($score < 0) ? -0.0001 : 0.0001;
  }
  else {
    $scan->{shortcircuit_type} = $sctype;
    if ($sctype eq 'ham') {
      $score = $conf->{shortcircuit_ham_score};
    } else {
      $score = $conf->{shortcircuit_spam_score};
    }
    dbg("shortcircuit: s/c $sctype due to $rule, using score of $score");
    $scscore = $score;
  }

  $scan->{shortcircuited} = 1;

  # bug 5256: if we short-circuit, don't do auto-learning
  $scan->{disable_auto_learning} = 1;
  $scan->got_hit('SHORTCIRCUIT', '', score => $scscore);
}

sub parsed_metadata {
  my ($self, $params) = @_;
  my $scan = $params->{permsgstatus};

  $scan->set_tag ('SC', sub {
      my $rule = $scan->{shortcircuit_rule};
      my $type = $scan->{shortcircuit_type};
      return "$rule ($type)" if ($rule);
      return "no";
    });

  $scan->set_tag ('SCRULE', sub {
      my $rule = $scan->{shortcircuit_rule};
      return ($rule || "none");
    });

  $scan->set_tag ('SCTYPE', sub {
      my $type = $scan->{shortcircuit_type};
      return ($type || "no");
    });

  $scan->set_spamd_result_item (sub {
          "shortcircuit=".$scan->get_tag("SCTYPE");
        }); 
}

sub have_shortcircuited {
  my ($self, $params) = @_;
  return (exists $params->{permsgstatus}->{shortcircuit_type}) ? 1 : 0;
}

sub compile_now_start {
  my ($self, $params) = @_;
  $self->{am_compiling} = 1;
}

sub compile_now_finish {
  my ($self, $params) = @_;
  delete $self->{am_compiling};
}

1;

=head1 SEE ALSO

C<https://issues.apache.org/SpamAssassin/show_bug.cgi?id=3109>

=cut
