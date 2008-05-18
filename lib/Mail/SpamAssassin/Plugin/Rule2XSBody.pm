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

=head1 NAME

Mail::SpamAssassin::Plugin::Rule2XSBody - speed up SpamAssassin by compiling regexps

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Rule2XSBody

=head1 DESCRIPTION

This plugin will use native-code object files representing the ruleset,
in order to provide significant speedups in rule evaluation.

Note that C<sa-compile> must be run in advance, in order to compile the
ruleset using C<re2c> and the C compiler.  See the C<sa-compile>
documentation for more details.

=cut

package Mail::SpamAssassin::Plugin::Rule2XSBody;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Plugin::OneLineBodyRuleType;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);
  $self->{one_line_body} = Mail::SpamAssassin::Plugin::OneLineBodyRuleType->new();
  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};

  my $instdir = $conf->{main}->sed_path
                ('__local_state_dir__/compiled/__perl_major_ver__/__version__');
  unshift @INC, $instdir, "$instdir/auto";
  dbg "zoom: loading compiled ruleset from $instdir";

  $self->setup_test_set ($conf, $conf->{body_tests}, 'body');
}

sub compile_now_start {
  my ($self) = @_;
  # call info here (and no earlier) so that the message appears in the syslog
  # but not on stderr when we start spamd
  if (exists $self->{compiled_rules_log_msg_text}) {
    info("zoom: $self->{compiled_rules_log_msg_text}") unless (would_log('dbg', 'zoom'));
    delete $self->{compiled_rules_log_msg_text};
  }
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
  my $modpath = "Mail/SpamAssassin/CompiledRegexps/".$ruletype.".pm";
  my $hasrules;

  if (!eval qq{ use $modname; \$hasrules = \$${modname}::HAS_RULES; 1; }) {
    # the module isn't available, so no rules will be either
    dbg "zoom: no compiled ruleset found for $modname";
    return 0;
  }

  # track down the "real" file we're using
  my $file;
  foreach my $dir (@INC) {
    my $try = $dir."/".$modpath;
    if (-f $try && -r $try) { $file = $try; last; }
  }
  dbg "zoom: using compiled ruleset in $file for $modname";

  $conf->{skip_body_rules}   ||= { };
  $conf->{need_one_line_sub} ||= { };

  my %longname;
  foreach my $nameandflags (keys %{$hasrules}) {
    my $name = $nameandflags; $name =~ s/,\[.*?\]$//;
    $longname{$name} = $nameandflags;
  }

  my $found = 0;
  foreach my $name (keys %{$rules}) {
    my $rule = $rules->{$name};
    my $comprule = $hasrules->{$longname{$name} || ''};
    $rule =~ s/\#/\[hash\]/gs;

    if (!$comprule) { 
      # this is pretty common, based on rule complexity; don't warn
      # dbg "zoom: skipping rule $name, not in compiled ruleset";
      next;
    }
    if ($comprule ne $rule) {
      dbg "zoom: skipping rule $name, code differs in compiled ruleset";
      next;
    }

    # ignore rules marked for ReplaceTags work!
    # TODO: we should be able to order the 'finish_parsing_end'
    # plugin calls to do this.
    if ($conf->{rules_to_replace}->{$name}) {
      dbg "zoom: skipping rule $name, ReplaceTags";
      next;
    }

    # we have the rule, and its regexp matches.  zero out the body
    # rule, so that the module can do the work instead

    # TODO: need a cleaner way to do this.  I expect when rule types
    # are implementable in plugins, I can do it that way
    $conf->{skip_body_rules}->{$name} = 1;

    # ensure that the one-liner version of the function call is
    # created, though
    $conf->{generate_body_one_line_sub}->{$name} = 1;
    $found++;
  }

  if ($found) {
    # report how many of the zoomed rules could be used; when this
    # figure gets low, it's a good indication that the rule2xs
    # module needs to be regenerated and rebuilt.

    my $totalhasrules = scalar keys %{$hasrules};
    my $pc_zoomed   = ($found / ($totalhasrules || .001)) * 100;
    $pc_zoomed   = int($pc_zoomed * 1000) / 1000;

    $self->{compiled_rules_log_msg_text} = "able to use $found/".
        "$totalhasrules '$ruletype' compiled rules ($pc_zoomed\%)";
    dbg("zoom: $self->{compiled_rules_log_msg_text}");

    # TODO: issue a warning for low counts?
    # TODO: inhibit rule2xs scanning entirely for low counts?

    $conf->{zoom_ruletypes_available} ||= { };
    $conf->{zoom_ruletypes_available}->{$ruletype} = 1;
    return 1;
  }
  else {
    dbg("zoom: no usable compiled rules for type $ruletype");
  }

  return 0;
}

###########################################################################

# delegate these to the OneLineBodyRuleType object
sub check_start {
  my ($self, $params) = @_;
  $self->{one_line_body}->check_start($params);
}

sub check_rules_at_priority {
  my ($self, $params) = @_;
  $self->{one_line_body}->check_rules_at_priority($params);
}

###########################################################################

sub run_body_fast_scan {
  my ($self, $params) = @_;

  return unless ($params->{ruletype} eq 'body');

  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};
  return unless $conf->{zoom_ruletypes_available}->{$ruletype};

  dbg("zoom: run_body_fast_scan for $ruletype start");

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

      my %alreadydone;
      foreach my $ruleandflags (@{$results})
      {
        # only try each rule once per line
        next if exists $alreadydone{$ruleandflags};
        $alreadydone{$ruleandflags} = undef;

        my $rulename = $ruleandflags;
        my $flags = ($rulename =~ s/,\[(.*?)\]$//)?$1:'';

        # ignore 0-scored rules, of course
        next unless $scoresptr->{$rulename};

        # non-lossy rules; the re2c version matches exactly what
        # the perl regexp matches, so we don't need to perform
        # a validation match to follow up; it's a hit!
        if ($flags =~ /\bl=0/) {
          $scanner->got_hit($rulename, "BODY: ", ruletype => "one_line_body");
          # TODO: hit_rule_plugin_code? it's just debugging really
          next;
        }

	# dbg("zoom: base found for $rulename: $line");
	# }

	my $fn = 'Mail::SpamAssassin::Plugin::Check::'.
				$rulename.'_one_line_body_test';

        # run the real regexp -- on this line alone.
	# don't try this unless the fn exists; this can happen if the
	# installed compiled-rules file contains details of rules
	# that are not in our current ruleset (e.g. gets out of
	# sync, or was compiled with extra rulesets installed)
	if (defined &{$fn}) {
	  if (!&{$fn} ($scanner, $line) && $do_dbg) {
	    $self->{rule2xs_misses}->{$rulename}++;
	  }
	}
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_fast_scan for $ruletype done");
}

sub finish {
  my ($self) = @_;

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  return unless $do_dbg;

  my $miss = $self->{rule2xs_misses};
  foreach my $r (sort { $miss->{$a} <=> $miss->{$b} } keys %{$miss}) {
    dbg("zoom: %s misses for rule2xs rule %s", $miss->{$r},$r);
  }
}

###########################################################################

1;
