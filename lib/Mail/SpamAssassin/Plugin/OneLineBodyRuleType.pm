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

use vars qw(@ISA); @ISA = qw();

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
    $pat = untaint_var($pat);
    my $sub;

    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # avoid [perl #86784] bug (fixed in 5.13.x), access the arg through ref
      $sub = '
      my $lref = \$_[1];
      pos $$lref = 0;
      '.$self->hash_line_for_rule($pms, $rulename).'
      while ($$lref =~ '.$pat.'g) {
        my $self = $_[0];
        $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "one_line_body");
        '. $self->hit_rule_plugin_code($pms, $rulename, "one_line_body",
                                      "return 1") . '
      }
      ';

    } else {
      $sub = '
      '.$self->hash_line_for_rule($pms, $rulename).'
      if ($_[1] =~ '.$pat.') {
        my $self = $_[0];
        $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "one_line_body");
        '. $self->hit_rule_plugin_code($pms, $rulename, "one_line_body", "return 1") . '
      }
      ';

    }

    return if ($opts{doing_user_rules} &&
                  !$self->is_user_rule_sub($rulename.'_one_line_body_test'));

    $self->add_temporary_method ($rulename.'_one_line_body_test', '{'.$sub.'}');
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
