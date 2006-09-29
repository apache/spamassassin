# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::Rule2XSBody;

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

  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};
  $self->setup_test_set ($conf, $conf->{body_tests}, 'body');
}

sub setup_test_set {
  my ($self, $conf, $test_set, $ruletype) = @_;
  foreach my $pri (keys %{$test_set}) {
    my $nicepri = $pri; $nicepri =~ s/-/neg/g;
    $self->setup_test_set_pri($conf, $test_set->{$pri}, $ruletype.'_'.$nicepri);
  }
}

sub setup_test_set_pri {
  my ($self, $conf, $rules, $ruletype) = @_;

  my $modname = "Mail::SpamAssassin::CompiledRegexps::".$ruletype;
  my $hasrules;

  if (!eval qq{ use $modname; \$hasrules = \$${modname}::HAS_RULES; 1; }) {
    # the module isn't available, so no rules will be either
    return 0;
  }

  $conf->{skip_body_rules} = { };

  my $found = 0;
  foreach my $name (keys %{$rules}) {
    my $rule = $rules->{$name};
    next unless ($hasrules->{$name} && $hasrules->{$name} eq $rule);

    # ignore rules marked for ReplaceTags work!
    # TODO: we should be able to order the 'finish_parsing_end'
    # plugin calls to do this.
    next if ($conf->{rules_to_replace}->{$name});

    # we have the rule, and its regexp matches.  zero out the body
    # rule, so that the module can do the work instead

    # TODO: need a cleaner way to do this.  I expect when rule types
    # are implementable in plugins, I can do it that way
    $conf->{skip_body_rules}->{$name} = 1;
    $found++;
  }

  if ($found) {
    # report how many of the zoomed rules could be used; when this
    # figure gets low, it's a good indication that the rule2xs
    # module needs to be regenerated and rebuilt.

    my $totalhasrules = scalar keys %{$hasrules};
    my $pc_zoomed   = ($found / ($totalhasrules || .001)) * 100;

    dbg("zoom: $found compiled rules are available for type $ruletype; ".
        "$pc_zoomed\% were usable");

    $conf->{zoom_ruletypes_available} ||= { };
    $conf->{zoom_ruletypes_available}->{$ruletype} = 1;
    return 1;
  }

  return 0;
}

###########################################################################

sub run_body_hack {
  my ($self, $params) = @_;

  return unless ($params->{ruletype} eq 'body');

  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};
  return unless $conf->{zoom_ruletypes_available}->{$ruletype};

  dbg("zoom: run_body_hack for $ruletype start");

  my $do_dbg = (would_log('dbg', 'zoom') > 1);

  my $scoresptr = $conf->{scores};
  my $modname = "Mail::SpamAssassin::CompiledRegexps::".$ruletype;

  {
    no strict "refs";
    foreach my $line (@{$params->{lines}})
    {
      # unfortunately, calling lc() here seems to be the fastest
      # way to support this and still work with UTF-8 ok
      my $results = &{$modname.'::scan'}(lc $line);

      my %alreadydone = ();
      foreach my $rulename (@{$results})
      {
        # only try each rule once per line
        next if exists $alreadydone{$rulename};
        $alreadydone{$rulename} = undef;

        # ignore 0-scored rules, of course
        next unless $scoresptr->{$rulename};

        # TODO: it would be very useful to provide an optional
        # means of instrumenting the ruleset, so that we can
        # find out when the base matched but the full RE didn't.

	# if ($do_dbg) {
	# dbg("zoom: base found for $rulename: $line");
	# }

        # run the real regexp -- on this line alone
        &{'Mail::SpamAssassin::PerMsgStatus::'.$rulename.'_one_line_body_test'}
                    ($scanner, $line);
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_hack for $ruletype done");
}

###########################################################################

1;
