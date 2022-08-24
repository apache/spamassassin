=head1 NAME

Mail::SpamAssassin::Plugin::Reuse - For reusing old rule hits during a mass-check

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::Reuse

  ifplugin      Mail::SpamAssassin::Plugin::Reuse

  reuse NETWORK_RULE [ NETWORK_RULE_OLD_NAME ]

  run_reuse_tests_only 0/1

  endif

=head1 DESCRIPTION

The purpose of this plugin is to work in conjunction with B<mass-check
--reuse> to map rules hit in input messages to rule hits in the
mass-check output.

run_reuse_tests_only 1 is special option for spamassassin/spamd use.
Only reuse flagged tests will be run. It will also _enable_ network/DNS
lookups. This is mainly intended for fast mass processing of corpus
messages, so they can be properly reused later. For example:
  spamd --pre="loadmodule Mail::SpamAssassin::Plugin::Reuse" \
    --pre="run_reuse_tests_only 1" ...
Such dedicated spamd could be scripted to add X-Spam-Status header to
messages efficiently.

=cut

package Mail::SpamAssassin::Plugin::Reuse;

# use bytes;
use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:sa);

our @ISA = qw(Mail::SpamAssassin::Plugin);

my $RULENAME_RE = RULENAME_RE;

# constructor
sub new {
  my $invocant = shift;
  my $samain = shift;

  # some boilerplate...
  my $class = ref($invocant) || $invocant;
  my $self = $class->SUPER::new($samain);
  bless ($self, $class);

  $self->set_config($samain->{conf});
  # make sure we run last (or close) of the finish_parsing_end since
  # we need all other rules to be defined
  $self->register_method_priority("finish_parsing_start", 100);
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  # reuse CURRENT_NAME ADDITIONAL_NAMES_IN_INPUT ...
  # e.g.
  # reuse NET_TEST_V1 NET_TEST_V0

  push (@cmds, {
    setting => 'reuse',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($conf, $key, $value, $line) = @_;

      if ($value !~ /^\s*(${RULENAME_RE})(?:\s+(${RULENAME_RE}(?:\s+${RULENAME_RE})*))?\s*$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      my $new_name = $1;
      my @old_names = ($new_name);
      if (defined $2) {
        push @old_names, split (/\s+/, $2);
      }

      dbg("reuse: read rule, old: %s new: %s", join(' ', @old_names), $new_name);
  
      foreach my $old (@old_names) {
        push @{$conf->{reuse_tests}->{$new_name}}, $old;
      }
    }
  });

  push(@cmds, {
    setting => 'run_reuse_tests_only',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_start {
  my ($self, $opts) = @_;

  my $conf = $opts->{conf};
  my $tflags = $conf->{tflags};

  while (my($rulename,$tfl) = each %{$tflags}) {
    if ($tfl =~ /\bnet\b/ && !exists $conf->{reuse_tests}->{$rulename}) {
      dbg("reuse: forcing reuse of net rule $rulename");
      push @{$conf->{reuse_tests}->{$rulename}}, $rulename;
    }
  }

  return 0 if (!exists $conf->{reuse_tests});

  if ($conf->{run_reuse_tests_only}) {
    # simply delete all rules not reuse
    foreach (keys %{$conf->{tests}}) {
      if (!defined $conf->{reuse_tests}->{$_}) {
        delete $conf->{tests}->{$_};
      }
    }
    return 0;
  }

  foreach my $rule_name (keys %{$conf->{reuse_tests}}) {

    # If the rule does not exist, add a new EMPTY test, set default score
    if (!exists $conf->{tests}->{$rule_name}) {
      dbg("reuse: $rule_name does not exist, adding empty test");
      $conf->{parser}->add_test($rule_name, undef, $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
    }
    if (!exists $conf->{scores}->{$rule_name}) {
      my $set_score = ($rule_name =~/^T_/) ? 0.01 : 1.0;
      $set_score = -$set_score if ( ($tflags->{$rule_name}||'') =~ /\bnice\b/ );
      foreach my $ss (0..3) {
        $conf->{scoreset}->[$ss]->{$rule_name} = $set_score;
      }
    }

    # Figure out when to add any hits -- grab priority and "stage"
    my $priority = $conf->{priority}->{$rule_name} || 0;
    my $stage = $self->_get_stage_from_rule($conf, $rule_name);
    $conf->{reuse_tests_order}->{$rule_name} = [ $priority, $stage ];

  }
}

sub check_start {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};
  my $scoreset = $conf->{scoreset};

  return 0 if $conf->{run_reuse_tests_only};

  # Can we reuse?
  my $msg = $pms->get_message();

  unless (exists $msg->{metadata}->{reuse_tests_hit}) {
    dbg("reuse: no old test hits passed in");
    return 0;
  }
  my $old_hash = $msg->{metadata}->{reuse_tests_hit};

  # now go through the rules and priorities and figure out which ones
  # need to be disabled
  foreach my $rule (keys %{$conf->{reuse_tests}}) {

    my ($priority, $stage) = @{$conf->{reuse_tests_order}->{$rule}};

    # score set could change after check_start but before we add hits,
    # so we need to disable the rule in all sets
    my @dis;
    foreach my $ss (0..3) {
      if (exists $scoreset->[$ss]->{$rule}) {
        $pms->{reuse_old_scores}->{$rule}->[$ss] =
          $scoreset->[$ss]->{$rule};
        $scoreset->[$ss]->{$rule} = 0;
        push @dis, $ss;
      }
    }
    dbg("reuse: disabling rule $rule in score sets %s",
      join(',', @dis)) if @dis;

    # now, check for hits
    foreach my $old_test (@{$conf->{reuse_tests}->{$rule}}) {
      if ($old_hash->{$old_test}) {
        push @{$pms->{reuse_hits_to_add}->{"$priority $stage"}}, $rule;
        dbg("reuse: rule $rule hit, will add at priority $priority, stage " .
           "$stage");
        last;
      } else {
        # Make sure rule is marked ready for meta rules
        $pms->rule_ready($rule);
      }
    }
  }
}

sub check_end {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};
  my $scoreset = $conf->{scoreset};

  return 0 if $conf->{run_reuse_tests_only};

  foreach my $disabled_rule (keys %{$pms->{reuse_old_scores}}) {
    foreach my $ss (0..3) {
      next unless exists $scoreset->[$ss]->{$disabled_rule};
      $scoreset->[$ss]->{$disabled_rule} =
        $pms->{reuse_old_scores}->{$disabled_rule}->[$ss];
    }
  }

  delete $pms->{reuse_old_scores};
}

sub start_rules {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};

  return 0 if $pms->{conf}->{run_reuse_tests_only};

  return $self->_add_hits($pms, $opts->{priority}, $opts->{ruletype});
}

sub _add_hits {
  my ($self, $pms, $priority, $stage) = @_;

  return unless exists $pms->{reuse_hits_to_add}->{"$priority $stage"};
  return if exists $pms->{reuse_hits_done}->{"$priority $stage"};
  foreach my $rule (@{$pms->{reuse_hits_to_add}->{"$priority $stage"}}) {
    # Add hit even if rule was originally disabled
    my $ss = $pms->{conf}->get_score_set();
    $pms->{conf}->{scores}->{$rule} =
      $pms->{reuse_old_scores}->{$rule}->[$ss] || 0.001;

    dbg("reuse: registering hit for $rule: score: " .
       $pms->{conf}->{scores}->{$rule});
    $pms->got_hit($rule);

    $pms->{conf}->{scores}->{$rule} = 0;
  }
  $pms->{reuse_hits_done}->{"$priority $stage"} = 1;
}

my %type_to_stage = (
  $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS    => "head",
  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS    => "eval",
  $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS    => "body",
  $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS    => "eval",
  $Mail::SpamAssassin::Conf::TYPE_FULL_TESTS    => "full",
  $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS    => "eval",
  $Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS => "rawbody",
  $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS => "eval",
  $Mail::SpamAssassin::Conf::TYPE_URI_TESTS     => "uri",
  $Mail::SpamAssassin::Conf::TYPE_URI_EVALS     => "eval",
  $Mail::SpamAssassin::Conf::TYPE_META_TESTS    => "meta",
  $Mail::SpamAssassin::Conf::TYPE_RBL_EVALS     => "eval",
);

sub _get_stage_from_rule {
  my  ($self, $conf, $rule) = @_;

  my $type = $conf->{test_types}->{$rule};
  if ($type && $type == $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS) {
    # this is a "fake" rule... see if the rule "text"/"definition" is
    # the name of the "parent" rule"
    my $parent = $conf->{tests}->{$rule};
    if ($parent) {
      $type = $conf->{test_types}->{$parent};
    }
  }
  if ($type && exists $type_to_stage{$type}) {
    return $type_to_stage{$type};
  }
  else {
    # Run before the meta rules run so that they can use these hits as
    # inputs.
    return "meta";
  }
}

1;
