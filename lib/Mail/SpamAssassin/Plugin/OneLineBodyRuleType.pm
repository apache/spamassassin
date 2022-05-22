=head1 NAME

Mail::SpamAssassin::Plugin::OneLineBodyRuleType - spamassassin body test plugin

=cut

package Mail::SpamAssassin::Plugin::OneLineBodyRuleType;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Constants qw(:sa);

use strict;
use warnings;
use re 'taint';

our @ISA = qw();

# constructor
sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {};
  bless ($self, $class);
  return $self;
}

###########################################################################

sub check_rules_at_priority {
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};
  my $checkobj = $params->{checkobj};
  my $priority = $params->{priority};
  Mail::SpamAssassin::Plugin::Check::do_one_line_body_tests($checkobj,
            $pms, $priority);
}

sub check_start {
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};
  my $conf = $pms->{conf};

  # this method runs before the body ruleset is compiled, but after
  # finish_tests().  perfect spot to remove rules from the body
  # set and add to another set...

  my $test_set = $conf->{body_tests};
  foreach my $pri (keys %{$test_set})
  {
    foreach my $rulename (keys %{$test_set->{$pri}})
    {
      if ($conf->{generate_body_one_line_sub}->{$rulename}) {
        # add the rule to the one-liner set
        $conf->{one_line_body_tests}->{$pri} ||= { };
        $conf->{one_line_body_tests}->{$pri}->{$rulename} =
                    $test_set->{$pri}->{$rulename};
      }

      if ($conf->{skip_body_rules}->{$rulename}) {
        # remove from the body set
        delete $test_set->{$pri}->{$rulename};
      }
    }
  }
}

sub check_cleanup {
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};
  my $scoresptr = $pms->{conf}->{scores};

  # Force all body rules ready for meta rules.  Need to do it here in
  # cleanup, because the body is scanned per line instead of per rule
  if ($pms->{conf}->{skip_body_rules}) {
    foreach (keys %{$pms->{conf}->{skip_body_rules}}) {
      $pms->rule_ready($_, 1)  if $scoresptr->{$_};
    }
  }
}

###########################################################################

1;

# inject this method into the Check plugin's namespace
# TODO: we need a better way to define new ruletypes via plugin
package Mail::SpamAssassin::Plugin::Check;

sub do_one_line_body_tests {
  my ($self, $pms, $priority) = @_;

  # TODO: should have a consttype for plugin-defined "alien" rule types,
  # probably something like TYPE_ALIEN_TESTS.  it's only used as a key
  # for {user_rules_of_type}, so that should be fine

  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS,
    type => 'one_line_body',
    testhash => $pms->{conf}->{one_line_body_tests},
    args => [ ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    my $sub = '
      my ($self, $line) = @_;
      my $qrptr = $self->{main}->{conf}->{test_qrs};
    ';

    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      $sub .= '
        my $hitsptr = $self->{tests_already_hit};
      ';
      # support multiple matches
      my ($max) = $conf->{tflags}->{$rulename} =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      if ($max) {
        $sub .= '
          if ($hitsptr->{q{'.$rulename.'}}) {
            return 0 if $hitsptr->{q{'.$rulename.'}} >= '.$max.';
          }
        ';
      }
      # avoid [perl #86784] bug (fixed in 5.13.x), access the arg through ref
      $sub .= '
      my $lref = \$line;
      pos $$lref = 0;
      '.$self->hash_line_for_rule($pms, $rulename).'
      while ($$lref =~ /$qrptr->{q{'.$rulename.'}}/gop) {
        $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "one_line_body");
        '. $self->hit_rule_plugin_code($pms, $rulename, "one_line_body", "") . '
        '. ($max? 'last if $hitsptr->{q{'.$rulename.'}} >= '.$max.';' : '') . '
      }
      ';

    } else {
      $sub .= '
      '.$self->hash_line_for_rule($pms, $rulename).'
      if ($line =~ /$qrptr->{q{'.$rulename.'}}/op) {
        $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "one_line_body");
        '. $self->hit_rule_plugin_code($pms, $rulename, "one_line_body", "return 1") . '
      }
      ';

    }

    # Make sure rule is marked ready for meta rules
    $sub .= '
      $self->rule_ready(q{'.$rulename.'}, 1);
    ';

    return if ($opts{doing_user_rules} &&
                  !$self->is_user_rule_sub($rulename.'_one_line_body_test'));

    $self->add_temporary_method ($rulename.'_one_line_body_test', $sub);
  },
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->add_evalstr($pms, '
 
      my $bodytext = $self->get_decoded_stripped_body_text_array();
      $self->{main}->call_plugins("run_body_fast_scan", {
              permsgstatus => $self, ruletype => "body",
              priority => '.$opts{priority}.', lines => $bodytext
            });

    ');
  });
}

###########################################################################

1;
