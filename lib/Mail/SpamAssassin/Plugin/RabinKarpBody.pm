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

package Mail::SpamAssassin::Plugin::RabinKarpBody;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use RabinKarpAccel;
use Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor;
use Mail::SpamAssassin::Plugin::OneLineBodyRuleType;

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
  $self->{one_line_body} = Mail::SpamAssassin::Plugin::OneLineBodyRuleType->new();
  return $self;
}

###########################################################################

sub finish_parsing_end {
  my ($self, $params) = @_;
  my $conf = $params->{conf};

  my $main = $self->{main};
  $main->{base_extract} = 1;
  $main->{bases_must_be_casei} = 1;
  $main->{bases_can_use_alternations} = 0; # /(foo|bar|baz)/
  $main->{bases_can_use_quantifiers} = 0; # /foo.*bar/ or /foo*bar/ or /foooo?bar/
  $main->{bases_can_use_char_classes} = 0; # /fo[opqr]bar/
  $main->{bases_split_out_alternations} = 1; # /(foo|bar|baz)/ => ["foo", "bar", "baz"]

  my $basextor = Mail::SpamAssassin::Plugin::BodyRuleBaseExtractor->new
			($self->{main});
  $basextor->extract_bases($conf);

  $conf->{skip_body_rules}   ||= { };
  $conf->{need_one_line_sub} ||= { };

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

  $conf->{$ruletype}->{rkhashes} = { };
  foreach my $base (keys %{$conf->{base_string}->{$ruletype}}) {
    next unless (length $base > 4);
    my @rules = split(' ', $conf->{base_string}->{$ruletype}->{$base});
    RabinKarpAccel::add_bitvec($conf->{$ruletype}->{rkhashes}, lc $base, [ @rules ]);
    foreach my $rule (@rules) {
      # ignore rules marked for ReplaceTags work!
      # TODO: we should be able to order the 'finish_parsing_end'
      # plugin calls to do this.
      next if ($conf->{rules_to_replace}->{$rule});

      # TODO: need a cleaner way to do this.  I expect when rule types
      # are implementable in plugins, I can do it that way
      $conf->{skip_body_rules}->{$rule} = 1;

      # ensure that the one-liner version of the function call is
      # created, though
      $conf->{generate_body_one_line_sub}->{$rule} = 1;
    }
  }
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

  my $pri = $params->{priority};
  my $nicepri = $params->{priority}; $nicepri =~ s/-/neg/g;
  my $ruletype = ($params->{ruletype}.'_'.$nicepri);
  my $scanner = $params->{permsgstatus};
  my $conf = $scanner->{conf};

  my $rkhashes = $conf->{$ruletype}->{rkhashes};
  if (!$rkhashes || (scalar keys %{$conf->{$ruletype}->{rkhashes}} <= 0))
  {
    dbg("zoom: run_body_fast_scan for $ruletype skipped, no rules");
    return;
  }

  my $do_dbg = (would_log('dbg', 'zoom') > 1);
  my $scoresptr = $conf->{scores};

  dbg("zoom: run_body_fast_scan for $ruletype start");

  {
    no strict "refs";
    foreach my $line (@{$params->{lines}})
    {
      my $results = RabinKarpAccel::scan_string($rkhashes, lc $line);
      next unless $results;

      my %alreadydone;
      foreach my $rulename (@{$results})
      {
        # only try each rule once per line
	next if exists $alreadydone{$rulename};
	$alreadydone{$rulename} = undef;

        # ignore 0-scored rules, of course
	next unless $scoresptr->{$rulename};

        # dbg("zoom: base found for $rulename: $line");

        my $fn = 'Mail::SpamAssassin::Plugin::Check::'.
                                $rulename.'_one_line_body_test';

        # run the real regexp -- on this line alone.
        # don't try this unless the fn exists; this can happen if the
        # installed compiled-rules file contains details of rules
        # that are not in our current ruleset (e.g. gets out of
        # sync, or was compiled with extra rulesets installed)
        # if (defined &{$fn}) {
          if (!&{$fn} ($scanner, $line) && $do_dbg) {
            $self->{rule2xs_misses}->{$rulename}++;
          }
        # }
      }
    }
    use strict "refs";
  }

  dbg("zoom: run_body_fast_scan for $ruletype done");
}

###########################################################################

1;
